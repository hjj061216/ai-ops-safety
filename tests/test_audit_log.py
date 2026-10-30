"""哈希链审计日志测试。"""
import json
import tempfile
import unittest
from pathlib import Path

from audit_log import AuditIntegrityError, HashChainAuditLog


class MutableClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        self.value += 1
        return self.value


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "audit.jsonl"
        self.audit = HashChainAuditLog(self.path, clock=MutableClock())

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def add_entries(self) -> None:
        self.audit.append("tool_decision", {"tool": "read_log", "decision": "allow"})
        self.audit.append("approval_created", {"tool": "restart_service"})
        self.audit.append("approval_consumed", {"tool": "restart_service"})

    def test_valid_chain_verifies(self) -> None:
        self.add_entries()
        result = self.audit.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["count"], 3)

    def test_payload_tampering_is_detected(self) -> None:
        self.add_entries()
        text = self.path.read_text(encoding="utf-8")
        self.path.write_text(text.replace('"allow"', '"deny"'), encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()

    def test_reordering_is_detected(self) -> None:
        self.add_entries()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()

    def test_middle_deletion_is_detected(self) -> None:
        self.add_entries()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join((lines[0], lines[2])) + "\n", encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()

    def test_tail_deletion_is_detected_by_checkpoint(self) -> None:
        self.add_entries()
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()

    def test_checkpoint_tampering_is_detected(self) -> None:
        self.add_entries()
        checkpoint = json.loads(self.audit.checkpoint_path.read_text(encoding="utf-8"))
        checkpoint["last_hash"] = "f" * 64
        self.audit.checkpoint_path.write_text(
            json.dumps(checkpoint), encoding="utf-8"
        )
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify()

    def test_append_refuses_existing_corruption(self) -> None:
        self.add_entries()
        self.path.write_text("corrupted\n", encoding="utf-8")
        with self.assertRaises(AuditIntegrityError):
            self.audit.append("new_event", {})


if __name__ == "__main__":
    unittest.main(verbosity=2)

