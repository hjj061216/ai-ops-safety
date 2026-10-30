"""本机原型的服务端候选快照。ID是临时凭证，不是用户身份认证。"""
from __future__ import annotations

import json
import math
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from structured_tools import StructuredToolGateway


class CandidateBindingError(ValueError):
    """候选缺失、过期、重放或客户端改写时拒绝请求。"""


@dataclass(frozen=True)
class BoundCandidate:
    candidate_id: str
    tool: str
    arguments_json: str
    call_digest: str
    effective_risk: str
    source: str
    expires_at: float
    owner_id: str | None = None

    @property
    def arguments(self) -> dict[str, Any]:
        # 每次返回新的对象，调用方不能修改存储中的快照。
        return json.loads(self.arguments_json)

    def public_fields(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "tool": self.tool,
            "arguments": self.arguments,
            "effective_risk": self.effective_risk,
            "candidate_source": self.source,
            "expires_at": self.expires_at,
        }


class CandidateStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = 900,
        clock: Callable[[], float] = time.time,
        max_records: int = 256,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("候选有效期必须是有限正数")
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records <= 0:
            raise ValueError("候选容量必须是正整数")
        self.ttl_seconds = float(ttl_seconds)
        self.clock = clock
        self.max_records = max_records
        self._records: dict[str, BoundCandidate] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def issue(self, tool: str, arguments: dict[str, Any], *, effective_risk: str, source: str, owner_id: str | None = None, deadline: float | None = None) -> BoundCandidate:
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            raise CandidateBindingError("候选工具和参数类型无效")
        if effective_risk not in {"low", "medium", "high"}:
            raise CandidateBindingError("拒绝或未知风险不能签发候选")
        if source not in {"natural_language", "offline_rules", "manual_form"}:
            raise CandidateBindingError("候选来源无效")
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or deadline <= self.clock()):
            raise CandidateBindingError("候选所属任务已经过期")
        arguments_json = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        snapshot = json.loads(arguments_json)
        with self._lock:
            now = self.clock()
            for candidate_id, record in list(self._records.items()):
                if record.expires_at <= now or candidate_id in self._consumed:
                    del self._records[candidate_id]
                    self._consumed.discard(candidate_id)
            if len(self._records) >= self.max_records:
                raise CandidateBindingError("候选容量已满，请等待旧候选过期")
            candidate_id = secrets.token_urlsafe(32)
            record = BoundCandidate(
                candidate_id, tool, arguments_json,
                StructuredToolGateway.call_digest(tool, snapshot),
                effective_risk, source, min(now + self.ttl_seconds, deadline) if deadline is not None else now + self.ttl_seconds, owner_id,
            )
            self._records[candidate_id] = record
            return record

    def _active(self, candidate_id: str) -> BoundCandidate:
        if not isinstance(candidate_id, str) or not candidate_id:
            raise CandidateBindingError("缺少服务端候选ID，请重新分析或生成手动候选")
        record = self._records.get(candidate_id)
        if record is None:
            raise CandidateBindingError("候选不存在或服务器已重启，请重新生成")
        if candidate_id in self._consumed:
            raise CandidateBindingError("候选已经用于执行，不能重复提交")
        if self.clock() >= record.expires_at:
            raise CandidateBindingError("候选已过期，请重新生成并重新审批")
        return record

    def get(self, candidate_id: str) -> BoundCandidate:
        with self._lock:
            return self._active(candidate_id)

    def consume(self, candidate_id: str) -> BoundCandidate:
        with self._lock:
            record = self._active(candidate_id)
            self._consumed.add(candidate_id)
            return record

    def counts(self) -> dict[str, int]:
        with self._lock:
            now = self.clock()
            return {
                "active": sum(record.expires_at > now and candidate_id not in self._consumed for candidate_id, record in self._records.items()),
                "consumed": len(self._consumed),
            }
