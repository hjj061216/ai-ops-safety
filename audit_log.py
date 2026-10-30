"""带 SHA-256 哈希链和尾部检查点的安全审计日志。"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
DEFAULT_LOG_PATH = ROOT / "data" / "security_audit.jsonl"
GENESIS_HASH = "0" * 64


class AuditIntegrityError(ValueError):
    """审计日志完整性校验失败。"""


class HashChainAuditLog:
    def __init__(
        self,
        log_path: Path | str = DEFAULT_LOG_PATH,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.log_path = Path(log_path)
        self.checkpoint_path = self.log_path.with_suffix(self.log_path.suffix + ".checkpoint")
        self.clock = clock
        self._lock = threading.RLock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.write_text("", encoding="utf-8")
            self._write_checkpoint(0, GENESIS_HASH)
        elif not self.checkpoint_path.exists():
            raise AuditIntegrityError("现有日志缺少尾部检查点")

    @staticmethod
    def _canonical(entry_without_hash: dict[str, Any]) -> bytes:
        return json.dumps(
            entry_without_hash,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _entry_hash(cls, entry_without_hash: dict[str, Any]) -> str:
        return hashlib.sha256(cls._canonical(entry_without_hash)).hexdigest()

    def _read_checkpoint(self) -> dict[str, Any]:
        try:
            checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(f"无法读取审计检查点：{exc}") from exc
        if set(checkpoint) != {"count", "last_hash"}:
            raise AuditIntegrityError("审计检查点格式无效")
        return checkpoint

    def _write_checkpoint(self, count: int, last_hash: str) -> None:
        payload = json.dumps(
            {"count": count, "last_hash": last_hash},
            ensure_ascii=False,
            indent=2,
        )
        fd, temporary = tempfile.mkstemp(
            prefix="audit-checkpoint-",
            suffix=".tmp",
            dir=str(self.checkpoint_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.checkpoint_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not event.strip():
            raise ValueError("审计事件名不能为空")
        with self._lock:
            self.verify()
            checkpoint = self._read_checkpoint()
            body = {
                "sequence": checkpoint["count"] + 1,
                "timestamp": self.clock(),
                "event": event,
                "payload": payload,
                "previous_hash": checkpoint["last_hash"],
            }
            entry = {**body, "hash": self._entry_hash(body)}
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
            with self.log_path.open("a", encoding="utf-8", newline="") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self._write_checkpoint(entry["sequence"], entry["hash"])
            return entry

    def verify(self) -> dict[str, Any]:
        with self._lock:
            checkpoint = self._read_checkpoint()
            previous_hash = GENESIS_HASH
            count = 0
            try:
                lines = self.log_path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise AuditIntegrityError(f"无法读取审计日志：{exc}") from exc

            for count, line in enumerate(lines, 1):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError(f"第 {count} 行不是有效 JSON") from exc
                if entry.get("sequence") != count:
                    raise AuditIntegrityError(f"第 {count} 行序号异常")
                if entry.get("previous_hash") != previous_hash:
                    raise AuditIntegrityError(f"第 {count} 行前序哈希不匹配")
                supplied_hash = entry.get("hash")
                body = {key: value for key, value in entry.items() if key != "hash"}
                calculated_hash = self._entry_hash(body)
                if supplied_hash != calculated_hash:
                    raise AuditIntegrityError(f"第 {count} 行内容哈希不匹配")
                previous_hash = supplied_hash

            if checkpoint["count"] != len(lines):
                raise AuditIntegrityError("日志条目数量与检查点不匹配，可能发生尾部删除")
            if checkpoint["last_hash"] != previous_hash:
                raise AuditIntegrityError("日志尾部哈希与检查点不匹配")
            return {
                "valid": True,
                "count": len(lines),
                "last_hash": previous_hash,
            }

