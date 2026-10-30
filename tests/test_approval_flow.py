"""一次性审批和结构化工具联动测试；不会执行真实工具。"""
import tempfile
import unittest
from pathlib import Path

from approval_manager import ApprovalError, ApprovalManager
from secure_tool_service import SecureToolService


class MutableClock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class ApprovalFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.clock = MutableClock()
        self.manager = ApprovalManager(
            Path(self.tempdir.name) / "approvals.json", clock=self.clock
        )
        self.service = SecureToolService(approvals=self.manager)
        self.arguments = {"name": "nginx"}

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def create_request(self, ttl_seconds: int = 900) -> dict:
        return self.service.request_approval(
            "restart_service",
            self.arguments,
            requester="alice",
            requester_role="operator",
            reason="部署后需要重启 nginx",
            ttl_seconds=ttl_seconds,
        )

    def test_pending_request_is_created(self) -> None:
        request = self.create_request()
        self.assertEqual(request["status"], "pending")
        self.assertNotIn("token_hash", request)

    def test_requester_cannot_approve_own_request(self) -> None:
        request = self.create_request()
        with self.assertRaises(ApprovalError):
            self.manager.approve(
                request["request_id"], approver="alice", approver_role="admin"
            )

    def test_non_approver_role_cannot_approve(self) -> None:
        request = self.create_request()
        with self.assertRaises(ApprovalError):
            self.manager.approve(
                request["request_id"], approver="bob", approver_role="viewer"
            )

    def test_valid_token_allows_call_once(self) -> None:
        request = self.create_request()
        grant = self.manager.approve(
            request["request_id"], approver="bob", approver_role="admin"
        )
        decision = self.service.authorize_with_token(
            "restart_service",
            self.arguments,
            role="operator",
            llm_risk="low",
            request_id=request["request_id"],
            approval_token=grant["approval_token"],
        )
        self.assertEqual(decision.decision, "allow")
        record = self.manager.get_public_record(request["request_id"])
        self.assertEqual(record["status"], "consumed")

    def test_consumed_token_cannot_be_replayed(self) -> None:
        request = self.create_request()
        grant = self.manager.approve(
            request["request_id"], approver="bob", approver_role="approver"
        )
        first = self.service.authorize_with_token(
            "restart_service", self.arguments, role="operator", llm_risk="low",
            request_id=request["request_id"], approval_token=grant["approval_token"],
        )
        second = self.service.authorize_with_token(
            "restart_service", self.arguments, role="operator", llm_risk="low",
            request_id=request["request_id"], approval_token=grant["approval_token"],
        )
        self.assertEqual(first.decision, "allow")
        self.assertEqual(second.decision, "deny")

    def test_token_is_bound_to_arguments(self) -> None:
        request = self.create_request()
        grant = self.manager.approve(
            request["request_id"], approver="bob", approver_role="admin"
        )
        decision = self.service.authorize_with_token(
            "restart_service",
            {"name": "api"},
            role="operator",
            llm_risk="low",
            request_id=request["request_id"],
            approval_token=grant["approval_token"],
        )
        self.assertEqual(decision.decision, "deny")
        self.assertEqual(
            self.manager.get_public_record(request["request_id"])["status"],
            "approved",
        )

    def test_forged_token_is_denied_without_consuming(self) -> None:
        request = self.create_request()
        self.manager.approve(
            request["request_id"], approver="bob", approver_role="admin"
        )
        decision = self.service.authorize_with_token(
            "restart_service", self.arguments, role="operator", llm_risk="low",
            request_id=request["request_id"], approval_token="forged",
        )
        self.assertEqual(decision.decision, "deny")
        self.assertEqual(
            self.manager.get_public_record(request["request_id"])["status"],
            "approved",
        )

    def test_expired_request_cannot_be_approved(self) -> None:
        request = self.create_request(ttl_seconds=30)
        self.clock.value += 31
        with self.assertRaises(ApprovalError):
            self.manager.approve(
                request["request_id"], approver="bob", approver_role="admin"
            )
        self.assertEqual(
            self.manager.get_public_record(request["request_id"])["status"],
            "expired",
        )

    def test_llm_critical_denies_without_consuming_token(self) -> None:
        request = self.create_request()
        grant = self.manager.approve(
            request["request_id"], approver="bob", approver_role="admin"
        )
        decision = self.service.authorize_with_token(
            "restart_service", self.arguments, role="operator", llm_risk="critical",
            request_id=request["request_id"], approval_token=grant["approval_token"],
        )
        self.assertEqual(decision.decision, "deny")
        self.assertEqual(
            self.manager.get_public_record(request["request_id"])["status"],
            "approved",
        )

    def test_denied_tool_cannot_create_approval(self) -> None:
        with self.assertRaises(ApprovalError):
            self.service.request_approval(
                "shell_command",
                {"command": "anything"},
                requester="alice",
                requester_role="admin",
                reason="test",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

