"""Planning contracts, completion evidence and cancellation security regressions."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from local_app import LocalSafetyApp
from natural_language_agent import OllamaUnavailableError
from ops_catalog import CATALOG, KNOWN_SERVICE_LOGS, READ_ONLY_TOOLS
from task_scope import analyze_task, check_task_scope, check_task_preconditions, remaining_requirements, service_facts


def action(tool=None, arguments=None, status="propose"):
    return {"status":status, "message":"按证据处理下一步", "plan":["检查并分析"],
            "tool":tool, "arguments":arguments or {}, "risk":"low"}


class PlanningContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = LocalSafetyApp(Path(self.temp.name))
        self.planner = self.app.tasks.planner

    def tearDown(self):
        self.temp.cleanup()

    def stub_validator(self, *responses):
        self.planner._guardrails_validator.validate_input = Mock()
        self.planner._guardrails_validator.validate_task_with_context = Mock(side_effect=responses)
        self.planner._ollama_client = Mock(return_value="{}")

    def test_shared_catalog_contains_tools_resources_and_risk(self):
        self.assertEqual(self.planner.tools, CATALOG["tools"])
        self.assertEqual(self.app.service.gateway.tools, self.planner.tools)
        self.assertEqual(KNOWN_SERVICE_LOGS["nginx"], "/var/log/nginx/error.log")
        self.assertTrue(all(CATALOG["tools"][tool]["effect"] == "read" for tool in READ_ONLY_TOOLS))

    def test_missing_service_clarifies_before_model_and_keeps_input_guard(self):
        self.stub_validator()
        result = self.planner.suggest("帮我排查服务异常", [])
        self.assertEqual(result["status"], "clarify")
        self.assertIn("哪个服务", result["message"])
        self.planner._guardrails_validator.validate_input.assert_called_once()
        self.planner._ollama_client.assert_not_called()

    def test_known_service_scope_disallows_model_generated_missing_information(self):
        self.stub_validator(action("restart_service", {"name":"nginx"}))
        self.planner.suggest("重启nginx服务", [])
        self.assertNotIn("clarify", self.planner.response_format["properties"]["status"]["enum"])
        with self.assertRaisesRegex(ValueError, "信息.*齐全|无需.*追问"):
            check_task_scope(action(status="clarify"), "重启nginx服务")
        check_task_scope(action(status="clarify"), "重启服务")

    def test_user_service_supplement_binds_only_an_unnamed_restart(self):
        restart=action("restart_service", {"name":"nginx"})
        check_task_scope(restart, "重启服务\n用户补充：nginx")
        for request in ("重启payment服务\n用户补充：查看nginx状态",
                        "重启redis服务\n用户补充：查看nginx状态",
                        "重启服务\n用户补充：nginx和payment",
                        "不要重启服务\n用户补充：nginx",
                        "查看nginx状态"):
            with self.subTest(request=request), self.assertRaises(ValueError):
                check_task_scope(restart, request)

    def test_log_path_and_line_ambiguity_clarify(self):
        self.stub_validator()
        for request in ("查看payment错误日志", "查看nginx最近999行日志", "查看nginx最近三百行日志", "查看nginx最近2行和最近3行日志"):
            with self.subTest(request=request):
                self.assertEqual(self.planner.suggest(request, [])["status"], "clarify")
        self.planner._ollama_client.assert_not_called()

    def test_unsupported_operation_is_not_misreported_as_validator_failure(self):
        self.stub_validator()
        result = self.planner.suggest("查看服务器当前系统时间", [])
        self.assertEqual(result["status"], "unsupported")
        self.planner._ollama_client.assert_not_called()

    def test_negative_clause_does_not_prohibit_later_positive_query(self):
        request = "不要重启nginx，查看nginx最近2行日志"
        intent = analyze_task(request)
        self.assertIn("restart_service", intent.forbidden_tools)
        self.assertNotIn("read_log", intent.forbidden_tools)
        check_task_scope(action("read_log", {"path":KNOWN_SERVICE_LOGS["nginx"], "lines":2}), request)

    def test_negative_only_request_does_not_authorize_an_implicit_query(self):
        self.stub_validator()
        result=self.planner.suggest("不要重启nginx", [])
        self.assertEqual(result["status"], "clarify")
        self.planner._ollama_client.assert_not_called()
        intent=analyze_task("不要重启payment，查看nginx服务状态")
        self.assertEqual(intent.services, ["nginx"])
        with self.assertRaises(ValueError):
            check_task_scope(action("get_service_status", {"name":"payment"}), intent.goal)

    def test_task_candidates_cannot_outlive_task_after_task_record_cleanup(self):
        self.planner.suggest=Mock(return_value=action("check_disk"))
        result=self.app.task_start({"request":"查看磁盘"})
        self.assertLessEqual(result["expires_at"], result["task_expires_at"])

    def test_model_receives_scope_remaining_requirements_and_evidence(self):
        self.stub_validator(action("get_service_status", {"name":"nginx"}))
        self.planner.suggest("排查nginx异常，检查磁盘和日志，不要重启", [])
        payload=json.loads(self.planner._ollama_client.call_args.args[0])
        self.assertIn("restart_service", payload["task_scope"]["forbidden_tools"])
        self.assertEqual({item["tool"] for item in payload["remaining_requirements"]}, {"get_service_status", "read_log", "check_disk"})
        self.assertNotIn("complete", self.planner.response_format["properties"]["status"]["enum"])

    def test_generation_schema_couples_tool_and_arguments_and_nonempty_plan(self):
        self.stub_validator(action("get_service_status", {"name":"api"}))
        self.planner.suggest("查看nginx和api服务状态，再检查磁盘，不要重启", [{"tool":"get_service_status", "target":"nginx"}])
        branches=self.planner.response_format["anyOf"]
        proposal=next(item["properties"] for item in branches if item["properties"]["tool"].get("enum")==["get_service_status"])
        self.assertEqual(proposal["arguments"]["properties"]["name"]["enum"], ["api"])
        self.assertEqual(proposal["plan"]["minItems"], 1)
        terminal=branches[-1]["properties"]
        self.assertEqual(terminal["tool"], {"type":"null"})
        self.assertEqual(terminal["arguments"]["properties"], {})
        self.assertEqual(terminal["plan"]["maxItems"], 0)
        self.assertEqual(self.planner._task_resources["log_paths"], [])

    def test_invalid_output_has_only_one_correction_attempt(self):
        accepted=action("check_disk")
        self.stub_validator(ValueError("invalid"), accepted)
        self.assertEqual(self.planner.suggest("查看磁盘", []), accepted)
        self.assertEqual(self.planner._ollama_client.call_count, 2)
        self.assertIn("validation_feedback", json.loads(self.planner._ollama_client.call_args.args[0]))
        self.stub_validator(ValueError("invalid"), ValueError("invalid again"))
        with self.assertRaises(ValueError):
            self.planner.suggest("查看磁盘", [])
        self.assertEqual(self.planner._ollama_client.call_count, 2)
        self.assertEqual(self.app.candidates.counts()["active"], 0)

    def test_false_completion_is_blocked_by_coordinator(self):
        self.planner.suggest = Mock(return_value=action(status="complete"))
        result=self.app.task_start({"request":"查看nginx服务状态，再检查磁盘"})
        self.assertEqual(result["task_status"], "blocked")
        self.assertIn("必要步骤", result["message"])
        self.assertEqual(len(result["remaining_requirements"]), 2)
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_restart_requires_real_precheck_and_postchange_observation(self):
        request="先检查nginx状态，然后重启nginx"
        with self.assertRaises(ValueError):
            check_task_preconditions(action("restart_service", {"name":"nginx"}), request, [])
        history=[{"tool":"get_service_status", "target":"nginx", "facts":{"status":"running"}},
                 {"tool":"restart_service", "target":"nginx"}]
        remaining=remaining_requirements(analyze_task(request), history)
        self.assertEqual(remaining, [{"tool":"get_service_status", "target":"nginx", "reason":"变更后核验"}])
        history.append({"tool":"get_service_status", "target":"nginx"})
        self.assertEqual(remaining_requirements(analyze_task(request), history), [])

    def test_healthy_conditional_branch_skips_mutation_requirement(self):
        intent=analyze_task("先检查nginx状态，如果服务异常就重启nginx")
        history=[{"tool":"get_service_status", "target":"nginx", "facts":{"status":"running", "healthy":True}}]
        self.assertEqual(remaining_requirements(intent, history), [])
        history[-1]["facts"]={"status":"stopped", "healthy":False}
        self.assertIn({"tool":"restart_service", "target":"nginx"}, remaining_requirements(intent, history))

    def test_unknown_service_status_is_not_evidence_for_conditional_restart(self):
        facts=service_facts({"status":"unknown"})
        self.assertIsNone(facts["healthy"])
        with self.assertRaises(ValueError):
            check_task_preconditions(action("restart_service", {"name":"nginx"}), "如果nginx状态异常就重启nginx",
                [{"tool":"get_service_status", "target":"nginx", "facts":facts}])

    def test_config_data_cannot_authorize_a_separate_service_operation(self):
        request="修改 /etc/myapp/test.conf，完整内容：restart nginx"
        self.assertEqual(analyze_task(request).services, [])
        with self.assertRaises(ValueError):
            check_task_scope(action("restart_service", {"name":"nginx"}), request)

    def test_expiry_during_model_planning_does_not_issue_candidate(self):
        clock=[100.0]
        self.app.tasks.clock=lambda:clock[0]
        def delayed(*args):
            clock[0]=1100
            return action("check_disk")
        self.planner.suggest=delayed
        result=self.app.task_start({"request":"查看磁盘"})
        self.assertEqual(result["task_status"], "blocked")
        self.assertEqual(self.app.candidates.counts()["active"], 0)

    def test_stopping_revokes_pending_candidate_and_prevents_manual_execution(self):
        self.planner.suggest=Mock(return_value=action("check_disk"))
        task=self.app.task_start({"request":"查看磁盘"})
        self.app.task_stop({"task_id":task["task_id"]})
        with self.assertRaises(ValueError):
            self.app.execute({"candidate_id":task["candidate_id"], "role":"admin"})
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_expired_task_candidate_is_rejected_even_if_candidate_is_still_live(self):
        self.planner.suggest=Mock(return_value=action("check_disk"))
        task=self.app.task_start({"request":"查看磁盘"})
        self.app.tasks.tasks[task["task_id"]]["expires_at"]=0
        with self.assertRaises(ValueError):
            self.app.execute({"candidate_id":task["candidate_id"], "role":"admin"})

    def test_model_connection_failure_has_actionable_error_code(self):
        self.planner.suggest=Mock(side_effect=OllamaUnavailableError("connection refused"))
        task=self.app.task_start({"request":"查看磁盘"})
        self.assertEqual(task["error_code"], "model_unavailable")
        self.assertIn("Ollama", task["message"])
        self.assertEqual(task["diagnostic"], "connection refused")


if __name__ == "__main__":
    unittest.main()
