"""结构化工具网关测试；不会执行任何系统命令或工具。"""
import unittest

from structured_tools import StructuredToolGateway


class StructuredToolGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway = StructuredToolGateway()

    def test_read_log_in_allowed_root(self) -> None:
        result = self.gateway.authorize(
            "read_log",
            {"path": "/var/log/nginx/error.log", "lines": 50},
            role="viewer",
        )
        self.assertEqual(result.decision, "allow")

    def test_path_traversal_is_denied(self) -> None:
        result = self.gateway.authorize(
            "read_log",
            {"path": "/var/log/nginx/../../etc/shadow", "lines": 10},
            role="admin",
        )
        self.assertEqual(result.decision, "deny")

    def test_windows_backslash_traversal_is_denied_for_log_and_config(self) -> None:
        cases = (
            ("read_log", "/var/log/nginx/x\\..\\..\\..\\..\\etc\\myapp\\secret.conf", {"lines": 1}, "viewer"),
            ("update_config", "/etc/nginx/conf.d/x\\..\\..\\..\\myapp\\secret.conf", {"content": "test"}, "admin"),
        )
        for tool, path, other_arguments, role in cases:
            with self.subTest(tool=tool):
                arguments = {"path": path, **other_arguments}
                self.assertTrue(self.gateway.validate_arguments(tool, arguments))
                decision = self.gateway.authorize(tool, arguments, role=role)
                self.assertEqual(decision.decision, "deny")

    def test_excessive_log_lines_are_denied(self) -> None:
        result = self.gateway.authorize(
            "read_log",
            {"path": "/var/log/app/app.log", "lines": 10000},
            role="operator",
        )
        self.assertEqual(result.decision, "deny")

    def test_arbitrary_shell_tool_does_not_exist(self) -> None:
        result = self.gateway.authorize(
            "shell_command", {"command": "anything"}, role="admin"
        )
        self.assertEqual(result.decision, "deny")

    def test_service_name_injection_is_denied(self) -> None:
        result = self.gateway.authorize(
            "restart_service", {"name": "nginx;whoami"}, role="admin"
        )
        self.assertEqual(result.decision, "deny")

    def test_service_outside_allowlist_is_denied(self) -> None:
        result = self.gateway.authorize(
            "restart_service", {"name": "sshd"}, role="admin"
        )
        self.assertEqual(result.decision, "deny")

    def test_viewer_cannot_restart_service(self) -> None:
        result = self.gateway.authorize(
            "restart_service", {"name": "nginx"}, role="viewer"
        )
        self.assertEqual(result.decision, "deny")

    def test_restart_requires_human(self) -> None:
        result = self.gateway.authorize(
            "restart_service", {"name": "nginx"}, role="operator"
        )
        self.assertEqual(result.decision, "require_human")

    def test_forged_approval_is_rejected(self) -> None:
        result = self.gateway.authorize(
            "restart_service",
            {"name": "nginx"},
            role="operator",
            approval={
                "approved": True,
                "tool": "restart_service",
                "call_digest": "wrong",
            },
        )
        self.assertEqual(result.decision, "require_human")

    def test_bound_approval_allows_restart(self) -> None:
        arguments = {"name": "nginx"}
        digest = self.gateway.call_digest("restart_service", arguments)
        result = self.gateway.authorize(
            "restart_service",
            arguments,
            role="operator",
            approval={
                "approved": True,
                "tool": "restart_service",
                "call_digest": digest,
            },
        )
        self.assertEqual(result.decision, "allow")

    def test_llm_can_raise_approved_call_to_deny(self) -> None:
        arguments = {"name": "nginx"}
        digest = self.gateway.call_digest("restart_service", arguments)
        result = self.gateway.authorize(
            "restart_service",
            arguments,
            role="admin",
            llm_risk="critical",
            approval={
                "approved": True,
                "tool": "restart_service",
                "call_digest": digest,
            },
        )
        self.assertEqual(result.decision, "deny")

    def test_unknown_argument_is_denied(self) -> None:
        result = self.gateway.authorize(
            "check_disk", {"command": "extra"}, role="viewer"
        )
        self.assertEqual(result.decision, "deny")


if __name__ == "__main__":
    unittest.main(verbosity=2)

