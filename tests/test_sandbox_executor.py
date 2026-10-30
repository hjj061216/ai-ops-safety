"""沙箱执行与回滚测试，不接触真实系统服务或配置。"""
import tempfile
import unittest
from pathlib import Path

from approval_manager import ApprovalManager
from sandbox_executor import SandboxExecutionError, SandboxExecutor
from secure_tool_service import SecureToolService


class SandboxExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.executor = SandboxExecutor(root / "sandbox")
        self.service = SecureToolService(
            approvals=ApprovalManager(root / "approvals.json")
        )
        log = root / "sandbox" / "var" / "log" / "nginx" / "error.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("line1\nline2\nline3\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def approved_decision(self, tool: str, arguments: dict) -> object:
        request = self.service.request_approval(
            tool, arguments, requester="alice", requester_role="admin",
            reason="sandbox test",
        )
        grant = self.service.approve_request(
            request["request_id"], approver="bob", approver_role="admin"
        )
        return self.service.authorize_with_token(
            tool, arguments, role="admin", llm_risk="low",
            request_id=request["request_id"],
            approval_token=grant["approval_token"],
        )

    def test_read_log_runs_only_inside_sandbox(self) -> None:
        arguments = {"path": "/var/log/nginx/error.log", "lines": 2}
        decision = self.service.check_call("read_log", arguments, role="viewer")
        result = self.executor.execute("read_log", arguments, decision)
        self.assertEqual(result["result"]["lines"], ["line2", "line3"])
        self.assertFalse(result["rollback_available"])

    def test_path_mapping_keeps_tool_specific_roots(self) -> None:
        roots = self.executor.gateway.tools["read_log"]["parameters"]["path"]["allowed_roots"]
        mapped = self.executor._map_virtual_path("/var/log/nginx/error.log", allowed_roots=roots)
        self.assertEqual(mapped, self.executor.root / "var" / "log" / "nginx" / "error.log")
        for path in (
            "/var/log/nginx/x\\..\\..\\..\\..\\etc\\myapp\\secret.conf",
            "/etc/myapp/secret.conf",
        ):
            with self.subTest(path=path):
                with self.assertRaises(SandboxExecutionError):
                    self.executor._map_virtual_path(path, allowed_roots=roots)

    def test_denied_decision_cannot_execute(self) -> None:
        arguments = {"name": "nginx;whoami"}
        decision = self.service.check_call("restart_service", arguments, role="admin")
        with self.assertRaises(SandboxExecutionError):
            self.executor.execute("restart_service", arguments, decision)

    def test_authorization_digest_cannot_be_reused_for_other_arguments(self) -> None:
        original = {"path": "/var/log/nginx/error.log", "lines": 1}
        decision = self.service.check_call("read_log", original, role="viewer")
        changed = {"path": "/var/log/nginx/error.log", "lines": 3}
        with self.assertRaises(SandboxExecutionError):
            self.executor.execute("read_log", changed, decision)

    def test_config_update_and_rollback_restores_old_content(self) -> None:
        virtual_path = "/etc/nginx/conf.d/site.conf"
        mapped = self.executor._map_virtual_path(virtual_path)
        mapped.parent.mkdir(parents=True, exist_ok=True)
        mapped.write_text("old", encoding="utf-8")
        arguments = {"path": virtual_path, "content": "new"}
        decision = self.approved_decision("update_config", arguments)
        executed = self.executor.execute("update_config", arguments, decision)
        self.assertEqual(mapped.read_text(encoding="utf-8"), "new")
        self.executor.rollback(executed["operation_id"])
        self.assertEqual(mapped.read_text(encoding="utf-8"), "old")

    def test_new_config_is_removed_on_rollback(self) -> None:
        virtual_path = "/etc/myapp/new.conf"
        mapped = self.executor._map_virtual_path(virtual_path)
        arguments = {"path": virtual_path, "content": "enabled=true"}
        decision = self.approved_decision("update_config", arguments)
        executed = self.executor.execute("update_config", arguments, decision)
        self.assertTrue(mapped.exists())
        self.executor.rollback(executed["operation_id"])
        self.assertFalse(mapped.exists())

    def test_service_restart_and_rollback_restore_state(self) -> None:
        arguments = {"name": "nginx"}
        decision = self.approved_decision("restart_service", arguments)
        executed = self.executor.execute("restart_service", arguments, decision)
        self.assertEqual(executed["result"]["restart_count"], 1)
        self.executor.rollback(executed["operation_id"])
        status_args = {"name": "nginx"}
        status_decision = self.service.check_call(
            "get_service_status", status_args, role="viewer"
        )
        status = self.executor.execute(
            "get_service_status", status_args, status_decision
        )
        self.assertEqual(status["result"]["restart_count"], 0)

    def test_operation_cannot_be_rolled_back_twice(self) -> None:
        arguments = {"name": "nginx"}
        decision = self.approved_decision("restart_service", arguments)
        executed = self.executor.execute("restart_service", arguments, decision)
        self.executor.rollback(executed["operation_id"])
        with self.assertRaises(SandboxExecutionError):
            self.executor.rollback(executed["operation_id"])

    def test_readonly_operation_has_no_rollback(self) -> None:
        decision = self.service.check_call("check_disk", {}, role="viewer")
        executed = self.executor.execute("check_disk", {}, decision)
        with self.assertRaises(SandboxExecutionError):
            self.executor.rollback(executed["operation_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

