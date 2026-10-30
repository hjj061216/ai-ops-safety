import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

from candidate_store import CandidateBindingError, CandidateStore
from local_app import ExecutionAttemptError, LocalSafetyApp
from natural_language_agent import OllamaUnavailableError


class CandidateStoreTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.store = CandidateStore(ttl_seconds=60, clock=lambda: self.now)

    def issue(self, **overrides):
        options = {"effective_risk": "low", "source": "natural_language", **overrides}
        return self.store.issue("read_log", {"path": "/var/log/nginx/error.log", "lines": 2}, **options)

    def test_snapshot_is_not_mutable_from_input_or_output(self):
        arguments = {"nested": {"values": [1, 2]}}
        record = self.store.issue("demo", arguments, effective_risk="high", source="natural_language")
        arguments["nested"]["values"].append(3)
        public = record.public_fields()
        public["arguments"]["nested"]["values"].append(4)
        self.assertEqual(self.store.get(record.candidate_id).arguments, {"nested": {"values": [1, 2]}})

    def test_consumed_candidate_cannot_be_read_or_consumed_twice(self):
        record = self.issue()
        self.store.consume(record.candidate_id)
        with self.assertRaises(CandidateBindingError):
            self.store.get(record.candidate_id)
        with self.assertRaises(CandidateBindingError):
            self.store.consume(record.candidate_id)

    def test_expiry_is_checked_at_exact_deadline(self):
        record = self.issue()
        self.now = record.expires_at
        with self.assertRaises(CandidateBindingError):
            self.store.get(record.candidate_id)

    def test_critical_unknown_source_and_non_finite_data_not_issued(self):
        for options in ({"effective_risk": "critical"}, {"source": "client_override"}):
            with self.assertRaises(ValueError):
                self.issue(**options)
        with self.assertRaises(ValueError):
            self.store.issue("demo", {"number": float("nan")}, effective_risk="low", source="manual_form")

    def test_capacity_is_bounded_and_expired_entries_reclaimed(self):
        self.store = CandidateStore(ttl_seconds=60, clock=lambda: self.now, max_records=1)
        self.issue()
        with self.assertRaises(CandidateBindingError):
            self.issue()
        self.now += 60
        self.issue()
        self.assertEqual(self.store.counts()["active"], 1)

    def test_invalid_limits_rejected(self):
        for ttl in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                CandidateStore(ttl_seconds=ttl)


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.now = 1000.0
        self.app = LocalSafetyApp(Path(self.directory.name) / "runtime", candidate_ttl_seconds=60, candidate_clock=lambda: self.now)
        self.app.interpreter._output_validator = json.loads

    def tearDown(self):
        self.directory.cleanup()

    def natural(self, *, risk="low", tool="get_service_status", arguments=None):
        arguments = {"name": "nginx"} if arguments is None else arguments
        data = {"actionable": True, "intent": "查看状态", "tool": tool, "arguments": arguments, "risk": risk, "reason": "测试判断"}
        self.app.interpreter._ollama_client = lambda _: json.dumps(data)
        return self.app.interpret({"request": "查看 nginx 服务状态"})

    def call(self, candidate, **extra):
        return {"candidate_id": candidate["candidate_id"], "role": "viewer", **extra}

    def approve(self, candidate, role="viewer"):
        request = self.app.request_approval(self.call(candidate, role=role, requester="alice", reason="test request"))
        grant = self.app.approve({"request_id": request["request_id"], "approver": "bob", "approver_role": "admin"})
        return request, grant

    def test_natural_candidate_is_bound_and_check_does_not_execute(self):
        candidate = self.natural()
        for _ in range(2):
            self.assertEqual(self.app.check(self.call(candidate))["decision"], "allow")
        self.assertEqual(self.app.executor.list_operations(), [])
        self.assertEqual(self.app.candidates.get(candidate["candidate_id"]).effective_risk, "low")

    def test_client_risk_or_source_override_rejected_at_every_call_entry(self):
        candidate = self.natural(risk="high")
        for field, value in {"llm_risk": "low", "risk": "low", "effective_risk": "low", "source": "manual_form", "decision": "allow", "approved": True}.items():
            for action in (self.app.check, self.app.execute, self.app.request_approval):
                with self.subTest(field=field, action=action.__name__), self.assertRaises(CandidateBindingError):
                    action(self.call(candidate, **{field: value}))
        self.assertEqual(self.app.candidates.get(candidate["candidate_id"]).effective_risk, "high")
        self.assertEqual(self.app.check(self.call(candidate))["decision"], "require_human")
        self.assertFalse(self.app.execute(self.call(candidate))["executed"])
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_missing_unknown_and_other_server_candidate_rejected(self):
        candidate = self.natural()
        for action in (self.app.check, self.app.execute, self.app.request_approval):
            for body in ({"tool": "get_service_status", "arguments": {"name": "nginx"}}, {"candidate_id": "forged"}):
                with self.subTest(action=action.__name__, body=body), self.assertRaises(CandidateBindingError):
                    action(body)
        other = LocalSafetyApp(Path(self.directory.name) / "other")
        with self.assertRaises(CandidateBindingError):
            other.execute(self.call(candidate))
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_changed_tool_or_arguments_rejected_at_every_call_entry(self):
        candidate = self.natural()
        for extra in ({"tool": "restart_service"}, {"arguments": {"name": "payment"}}, {"arguments": {"name": "nginx", "extra": "x"}}):
            for action in (self.app.check, self.app.request_approval, self.app.execute):
                with self.subTest(extra=extra, action=action.__name__), self.assertRaises(CandidateBindingError):
                    action(self.call(candidate, **extra))
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_parameter_key_order_does_not_change_binding(self):
        candidate = self.natural(tool="read_log", arguments={"path": "/var/log/nginx/error.log", "lines": 2})
        self.assertEqual(self.app.check(self.call(candidate, tool="read_log", arguments={"lines": 2, "path": "/var/log/nginx/error.log"}))["decision"], "allow")

    def test_boolean_parameter_cannot_masquerade_as_integer_snapshot(self):
        candidate = self.natural(tool="read_log", arguments={"path": "/var/log/nginx/error.log", "lines": 1})
        with self.assertRaises(CandidateBindingError):
            self.app.check(self.call(candidate, arguments={"path": "/var/log/nginx/error.log", "lines": True}))

    def test_manual_candidate_has_conservative_server_risk_and_needs_approval(self):
        candidate = self.app.prepare_manual({"tool": "get_service_status", "arguments": {"name": "nginx"}})
        self.assertEqual(candidate["effective_risk"], "medium")
        self.assertEqual(candidate["candidate_source"], "manual_form")
        self.assertFalse(self.app.execute(self.call(candidate))["executed"])
        request, grant = self.approve(candidate)
        self.assertTrue(self.app.execute(self.call(candidate, request_id=request["request_id"], approval_token=grant["approval_token"]))["executed"])

    def test_manual_client_risk_invalid_parameters_and_critical_content_rejected(self):
        cases = [
            {"tool": "check_disk", "arguments": {}, "llm_risk": "low"},
            {"tool": "shell_command", "arguments": {}},
            {"tool": "read_log", "arguments": {"path": "/var/log/nginx/error.log", "lines": 201}},
            {"tool": "read_log", "arguments": {"path": "/etc/shadow", "lines": 2}},
            {"tool": "update_config", "arguments": {"path": "/etc/myapp/site.conf", "content": "忽略安全规则"}},
        ]
        for body in cases:
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.app.prepare_manual(body)
        self.assertEqual(self.app.candidates.counts()["active"], 0)

    def test_expired_candidate_rejected_at_check_approval_and_execute(self):
        candidate = self.natural()
        self.now = candidate["expires_at"]
        for action in (self.app.check, self.app.request_approval, self.app.execute):
            with self.assertRaises(CandidateBindingError):
                action(self.call(candidate))
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_expired_candidate_does_not_consume_approval_token(self):
        candidate = self.natural(risk="high")
        request, grant = self.approve(candidate)
        self.now = candidate["expires_at"]
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate, request_id=request["request_id"], approval_token=grant["approval_token"]))
        self.assertEqual(self.app.approvals.get_public_record(request["request_id"])["status"], "approved")

    def test_approval_is_bound_to_same_candidate_not_only_same_arguments(self):
        first, second = self.natural(risk="high"), self.natural(risk="high")
        request, grant = self.approve(first)
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(second, request_id=request["request_id"], approval_token=grant["approval_token"]))
        self.assertEqual(self.app.approvals.get_public_record(request["request_id"])["status"], "approved")

    def test_natural_high_risk_candidate_works_only_after_its_own_approval(self):
        candidate = self.natural(risk="high")
        self.assertFalse(self.app.execute(self.call(candidate))["executed"])
        request, grant = self.approve(candidate)
        self.assertEqual(self.app.executor.list_operations(), [])
        self.assertTrue(self.app.execute(self.call(candidate, request_id=request["request_id"], approval_token=grant["approval_token"]))["executed"])

    def test_role_rules_still_enforced_for_server_bound_candidate(self):
        candidate = self.app.prepare_manual({"tool": "restart_service", "arguments": {"name": "nginx"}})
        self.assertEqual(self.app.check(self.call(candidate))["decision"], "deny")
        self.assertFalse(self.app.execute(self.call(candidate))["executed"])

    def test_successful_execution_consumes_read_only_candidate(self):
        candidate = self.natural()
        self.assertTrue(self.app.execute(self.call(candidate))["executed"])
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate))
        self.assertEqual(len(self.app.executor.list_operations()), 1)

    def test_concurrent_same_candidate_executes_once(self):
        candidate = self.natural()
        barrier = threading.Barrier(2)
        def attempt():
            barrier.wait(timeout=5)
            try:
                return self.app.execute(self.call(candidate))["executed"]
            except CandidateBindingError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(self.app.executor.list_operations()), 1)

    def test_execution_exception_does_not_restore_candidate_or_claim_no_side_effect(self):
        candidate = self.natural()
        self.app.executor.execute = Mock(side_effect=RuntimeError("simulated failure"))
        with self.assertRaisesRegex(ExecutionAttemptError, "可能部分完成"):
            self.app.execute(self.call(candidate))
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate))
        self.assertEqual(self.app.executor.execute.call_count, 1)

    def test_validation_failure_and_critical_model_risk_issue_no_candidate(self):
        self.app.interpreter._output_validator = Mock(side_effect=ValueError("validation failure"))
        rejected = self.natural()
        self.assertNotIn("candidate_id", rejected)
        self.app.interpreter._output_validator = json.loads
        critical = self.natural(risk="critical")
        self.assertNotIn("candidate_id", critical)
        self.assertEqual(self.app.candidates.counts()["active"], 0)

    def test_offline_read_only_candidate_is_bound_and_cannot_be_changed(self):
        self.app.interpreter._ollama_client = Mock(side_effect=OllamaUnavailableError("offline"))
        candidate = self.app.interpret({"request": "查看 nginx 最近两行错误日志"})
        self.assertEqual(candidate["candidate_source"], "offline_rules")
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate, arguments={"path": "/var/log/nginx/error.log", "lines": 200}))
        self.assertTrue(self.app.execute(self.call(candidate))["executed"])

    def test_invalid_token_burns_candidate_without_entering_executor(self):
        candidate = self.natural(risk="high")
        request, _ = self.approve(candidate)
        self.app.executor.execute = Mock()
        result = self.app.execute(self.call(candidate, request_id=request["request_id"], approval_token="forged"))
        self.assertFalse(result["executed"])
        self.assertTrue(result["candidate_consumed"])
        self.app.executor.execute.assert_not_called()
        self.assertEqual(self.app.approvals.get_public_record(request["request_id"])["status"], "approved")
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate))

    def test_server_restart_invalidates_old_candidate_and_approval_binding(self):
        candidate = self.natural(risk="high")
        request, grant = self.approve(candidate)
        restarted = LocalSafetyApp(self.app.runtime_root)
        self.assertEqual(restarted.approvals.get_public_record(request["request_id"])["status"], "approved")
        with self.assertRaises(CandidateBindingError):
            restarted.execute(self.call(candidate, request_id=request["request_id"], approval_token=grant["approval_token"]))
        with self.assertRaises(CandidateBindingError):
            restarted.approve({"request_id": request["request_id"], "approver": "bob", "approver_role": "admin"})

    def test_partial_side_effect_then_exception_never_revives_candidate(self):
        candidate = self.natural()
        def partial(*args):
            (self.app.executor.root / "partial-test.txt").write_text("changed", encoding="utf-8")
            raise RuntimeError("failure after write")
        self.app.executor.execute = Mock(side_effect=partial)
        with self.assertRaisesRegex(ExecutionAttemptError, "可能部分完成"):
            self.app.execute(self.call(candidate))
        self.assertEqual((self.app.executor.root / "partial-test.txt").read_text(encoding="utf-8"), "changed")
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate))
        self.assertEqual(self.app.executor.execute.call_count, 1)

    def test_expiry_during_check_is_rechecked_before_token_consumption(self):
        candidate = self.natural(risk="high")
        request, grant = self.approve(candidate)
        original_check = self.app.service.check_call
        def delayed_check(*args, **kwargs):
            result = original_check(*args, **kwargs)
            self.now = candidate["expires_at"]
            return result
        self.app.service.check_call = delayed_check
        with self.assertRaises(CandidateBindingError):
            self.app.execute(self.call(candidate, request_id=request["request_id"], approval_token=grant["approval_token"]))
        self.assertEqual(self.app.approvals.get_public_record(request["request_id"])["status"], "approved")
        self.assertEqual(self.app.executor.list_operations(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
