"""验证工具、审批和哈希链审计的端到端联动。"""
import tempfile
import unittest
from pathlib import Path

from approval_manager import ApprovalManager
from audit_log import HashChainAuditLog
from secure_tool_service import SecureToolService


class SecureServiceAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.audit = HashChainAuditLog(root / "audit.jsonl")
        self.service = SecureToolService(
            approvals=ApprovalManager(root / "approvals.json"),
            audit=self.audit,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_complete_approval_is_audited_without_token(self) -> None:
        arguments = {"name": "nginx"}
        request = self.service.request_approval(
            "restart_service",
            arguments,
            requester="alice",
            requester_role="operator",
            reason="deployment",
        )
        grant = self.service.approve_request(
            request["request_id"], approver="bob", approver_role="admin"
        )
        decision = self.service.authorize_with_token(
            "restart_service",
            arguments,
            role="operator",
            llm_risk="low",
            request_id=request["request_id"],
            approval_token=grant["approval_token"],
        )
        self.assertEqual(decision.decision, "allow")
        verified = self.audit.verify()
        self.assertTrue(verified["valid"])
        audit_text = self.audit.log_path.read_text(encoding="utf-8")
        self.assertIn("approval_requested", audit_text)
        self.assertIn("approval_granted", audit_text)
        self.assertIn("approval_consumed", audit_text)
        self.assertNotIn(grant["approval_token"], audit_text)

    def test_replay_denial_is_audited(self) -> None:
        arguments = {"name": "nginx"}
        request = self.service.request_approval(
            "restart_service", arguments, requester="alice",
            requester_role="operator", reason="deployment",
        )
        grant = self.service.approve_request(
            request["request_id"], approver="bob", approver_role="admin"
        )
        for _ in range(2):
            self.service.authorize_with_token(
                "restart_service", arguments, role="operator", llm_risk="low",
                request_id=request["request_id"],
                approval_token=grant["approval_token"],
            )
        audit_text = self.audit.log_path.read_text(encoding="utf-8")
        self.assertIn("approval_rejected", audit_text)
        self.assertTrue(self.audit.verify()["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

