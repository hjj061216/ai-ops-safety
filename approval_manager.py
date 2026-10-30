"""持久化的一次性人工审批管理器，不执行任何运维操作。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
DEFAULT_STORE = ROOT / "data" / "approvals.json"
APPROVER_ROLES = {"approver", "admin"}


class ApprovalError(ValueError):
    """审批流程拒绝操作时抛出。"""


class ApprovalManager:
    def __init__(
        self,
        store_path: Path | str = DEFAULT_STORE,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store_path = Path(store_path)
        self.clock = clock
        self._lock = threading.RLock()
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.store_path.exists():
            self._write({"version": 1, "requests": {}})

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _read(self) -> dict[str, Any]:
        try:
            document = json.loads(self.store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovalError(f"审批存储不可用：{exc}") from exc
        if document.get("version") != 1 or not isinstance(document.get("requests"), dict):
            raise ApprovalError("审批存储格式无效")
        return document

    def _write(self, document: dict[str, Any]) -> None:
        payload = json.dumps(document, ensure_ascii=False, indent=2)
        fd, temporary = tempfile.mkstemp(
            prefix="approvals-", suffix=".tmp", dir=str(self.store_path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.store_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def create_request(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        call_digest: str,
        requester: str,
        requester_role: str,
        reason: str,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        if not 30 <= ttl_seconds <= 3600:
            raise ApprovalError("审批有效期必须在 30 到 3600 秒之间")
        if not requester.strip() or not reason.strip():
            raise ApprovalError("申请人和申请原因不能为空")
        now = self.clock()
        request_id = uuid.uuid4().hex
        record = {
            "request_id": request_id,
            "status": "pending",
            "tool": tool,
            "arguments": arguments,
            "call_digest": call_digest,
            "requester": requester,
            "requester_role": requester_role,
            "reason": reason,
            "created_at": now,
            "expires_at": now + ttl_seconds,
            "approver": None,
            "approved_at": None,
            "consumed_at": None,
            "token_hash": None,
        }
        with self._lock:
            document = self._read()
            document["requests"][request_id] = record
            self._write(document)
        return {key: value for key, value in record.items() if key != "token_hash"}

    def approve(
        self, request_id: str, *, approver: str, approver_role: str
    ) -> dict[str, Any]:
        if approver_role not in APPROVER_ROLES:
            raise ApprovalError("当前角色无审批权限")
        with self._lock:
            document = self._read()
            record = document["requests"].get(request_id)
            if record is None:
                raise ApprovalError("审批申请不存在")
            now = self.clock()
            if record["status"] != "pending":
                raise ApprovalError("审批申请不是待审批状态")
            if now >= record["expires_at"]:
                record["status"] = "expired"
                self._write(document)
                raise ApprovalError("审批申请已过期")
            if approver == record["requester"]:
                raise ApprovalError("申请人与审批人必须不同")

            token = secrets.token_urlsafe(32)
            record.update(
                {
                    "status": "approved",
                    "approver": approver,
                    "approved_at": now,
                    "token_hash": self._token_hash(token),
                }
            )
            self._write(document)
            return {
                "request_id": request_id,
                "approval_token": token,
                "tool": record["tool"],
                "call_digest": record["call_digest"],
                "expires_at": record["expires_at"],
            }

    def consume(
        self,
        request_id: str,
        token: str,
        *,
        tool: str,
        call_digest: str,
    ) -> dict[str, Any]:
        with self._lock:
            document = self._read()
            record = document["requests"].get(request_id)
            if record is None:
                raise ApprovalError("审批申请不存在")
            now = self.clock()
            if record["status"] != "approved":
                raise ApprovalError("审批令牌不可用或已经使用")
            if now >= record["expires_at"]:
                record["status"] = "expired"
                self._write(document)
                raise ApprovalError("审批令牌已过期")
            if record["tool"] != tool or record["call_digest"] != call_digest:
                raise ApprovalError("审批与本次工具调用不匹配")
            supplied_hash = self._token_hash(token)
            if not hmac.compare_digest(record["token_hash"], supplied_hash):
                raise ApprovalError("审批令牌无效")

            record["status"] = "consumed"
            record["consumed_at"] = now
            self._write(document)
            return {
                "approved": True,
                "tool": tool,
                "call_digest": call_digest,
                "request_id": request_id,
                "approver": record["approver"],
            }

    def get_public_record(self, request_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._read()["requests"].get(request_id)
            if record is None:
                raise ApprovalError("审批申请不存在")
            return {key: value for key, value in record.items() if key != "token_hash"}

    def list_public_records(self) -> list[dict[str, Any]]:
        with self._lock:
            records = self._read()["requests"].values()
            return [
                {key: value for key, value in record.items() if key != "token_hash"}
                for record in sorted(
                    records, key=lambda item: item["created_at"], reverse=True
                )
            ]

