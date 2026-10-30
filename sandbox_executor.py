"""结构化工具的本地沙箱执行器，绝不调用 Shell 或真实系统服务。"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from audit_log import HashChainAuditLog
from structured_tools import StructuredToolGateway, ToolDecision
from ops_catalog import SERVICE_NAMES


class SandboxExecutionError(ValueError):
    """沙箱拒绝执行或回滚时抛出。"""


class SandboxExecutor:
    SUPPORTED_TOOLS = {
        "check_disk",
        "get_service_status",
        "read_log",
        "restart_service",
        "update_config",
    }

    def __init__(
        self,
        sandbox_root: Path | str,
        *,
        audit: HashChainAuditLog | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.root = Path(sandbox_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self.clock = clock
        self.gateway = StructuredToolGateway()
        self.operations_path = self.root / ".operations.json"
        self.services_path = self.root / ".services.json"
        if not self.operations_path.exists():
            self._atomic_json_write(self.operations_path, {"operations": {}})
        if not self.services_path.exists():
            self._atomic_json_write(
                self.services_path,
                {name:{"status":"running", "restart_count":0} for name in SERVICE_NAMES},
            )

    @staticmethod
    def _atomic_json_write(path: Path, document: dict[str, Any]) -> None:
        fd, temporary = tempfile.mkstemp(
            prefix=path.name + "-", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _audit(self, event: str, payload: dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(event, payload)

    def _map_virtual_path(self, virtual_path: str, *, allowed_roots: list[str] | None = None) -> Path:
        if not isinstance(virtual_path, str) or "\\" in virtual_path or ":" in virtual_path or any(ord(char) < 32 or ord(char) == 127 for char in virtual_path):
            raise SandboxExecutionError("虚拟路径包含非 POSIX 分隔符或控制字符")
        pure = PurePosixPath(virtual_path)
        if not pure.is_absolute() or ".." in pure.parts:
            raise SandboxExecutionError("虚拟路径必须是无穿越的绝对 POSIX 路径")
        relative_parts = [part for part in pure.parts if part not in {"/", ""}]
        mapped = self.root.joinpath(*relative_parts).resolve()
        try:
            mapped.relative_to(self.root)
        except ValueError as exc:
            raise SandboxExecutionError("路径逃逸出沙箱") from exc
        if allowed_roots is not None:
            allowed_paths = [
                self.root.joinpath(*PurePosixPath(root).parts[1:])
                for root in allowed_roots
            ]
            if not any(mapped == root or root in mapped.parents for root in allowed_paths):
                raise SandboxExecutionError("路径逃逸出工具允许目录")
        return mapped

    def _verify_authorization(
        self,
        tool: str,
        arguments: dict[str, Any],
        decision: ToolDecision,
    ) -> None:
        if decision.decision != "allow":
            raise SandboxExecutionError("只有 allow 决策可以进入沙箱执行")
        if decision.tool != tool:
            raise SandboxExecutionError("授权工具与执行工具不一致")
        expected_digest = self.gateway.call_digest(tool, arguments)
        if decision.call_digest != expected_digest:
            raise SandboxExecutionError("授权摘要与工具参数不一致")
        if tool not in self.SUPPORTED_TOOLS:
            raise SandboxExecutionError("执行器不支持该工具")
        errors = self.gateway.validate_arguments(tool, arguments)
        if errors:
            raise SandboxExecutionError("执行前参数校验失败：" + "；".join(errors))

    def _record_operation(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        call_digest: str,
        result: dict[str, Any],
        rollback: dict[str, Any] | None,
    ) -> str:
        document = json.loads(self.operations_path.read_text(encoding="utf-8"))
        operation_id = uuid.uuid4().hex
        document["operations"][operation_id] = {
            "operation_id": operation_id,
            "tool": tool,
            "arguments": arguments,
            "call_digest": call_digest,
            "status": "executed",
            "executed_at": self.clock(),
            "rolled_back_at": None,
            "result": result,
            "rollback": rollback,
        }
        self._atomic_json_write(self.operations_path, document)
        return operation_id

    def execute(
        self,
        tool: str,
        arguments: dict[str, Any],
        decision: ToolDecision,
    ) -> dict[str, Any]:
        self._verify_authorization(tool, arguments, decision)
        rollback: dict[str, Any] | None = None

        if tool == "check_disk":
            usage = shutil.disk_usage(self.root)
            result = {"total": usage.total, "used": usage.used, "free": usage.free}
        elif tool == "get_service_status":
            services = json.loads(self.services_path.read_text(encoding="utf-8"))
            result = {"name": arguments["name"], **services[arguments["name"]]}
        elif tool == "read_log":
            roots = self.gateway.tools[tool]["parameters"]["path"]["allowed_roots"]
            mapped = self._map_virtual_path(arguments["path"], allowed_roots=roots)
            if not mapped.is_file():
                raise SandboxExecutionError("沙箱日志文件不存在")
            lines = mapped.read_text(encoding="utf-8").splitlines()
            result = {
                "path": arguments["path"],
                "lines": lines[-arguments["lines"] :],
            }
        elif tool == "restart_service":
            services = json.loads(self.services_path.read_text(encoding="utf-8"))
            name = arguments["name"]
            before = dict(services[name])
            services[name] = {
                "status": "running",
                "restart_count": before["restart_count"] + 1,
                "last_restart": self.clock(),
            }
            self._atomic_json_write(self.services_path, services)
            result = {"name": name, **services[name]}
            rollback = {"kind": "restore_service", "name": name, "before": before}
        elif tool == "update_config":
            roots = self.gateway.tools[tool]["parameters"]["path"]["allowed_roots"]
            mapped = self._map_virtual_path(arguments["path"], allowed_roots=roots)
            existed = mapped.exists()
            before = mapped.read_text(encoding="utf-8") if existed else None
            mapped.parent.mkdir(parents=True, exist_ok=True)
            mapped.write_text(arguments["content"], encoding="utf-8")
            result = {"path": arguments["path"], "bytes": len(arguments["content"].encode("utf-8"))}
            rollback = {
                "kind": "restore_file",
                "path": arguments["path"],
                "existed": existed,
                "before": before,
            }
        else:  # pragma: no cover - guarded above
            raise SandboxExecutionError("未知工具")

        operation_id = self._record_operation(
            tool=tool,
            arguments=arguments,
            call_digest=decision.call_digest,
            result=result,
            rollback=rollback,
        )
        self._audit(
            "sandbox_operation_executed",
            {
                "operation_id": operation_id,
                "tool": tool,
                "call_digest": decision.call_digest,
                "rollback_available": rollback is not None,
            },
        )
        return {"operation_id": operation_id, "result": result, "rollback_available": rollback is not None}

    def rollback(self, operation_id: str) -> dict[str, Any]:
        document = json.loads(self.operations_path.read_text(encoding="utf-8"))
        operation = document["operations"].get(operation_id)
        if operation is None:
            raise SandboxExecutionError("操作记录不存在")
        if operation["status"] != "executed":
            raise SandboxExecutionError("操作已经回滚或状态不可回滚")
        rollback = operation["rollback"]
        if rollback is None:
            raise SandboxExecutionError("该只读操作没有回滚动作")

        if rollback["kind"] == "restore_service":
            services = json.loads(self.services_path.read_text(encoding="utf-8"))
            services[rollback["name"]] = rollback["before"]
            self._atomic_json_write(self.services_path, services)
        elif rollback["kind"] == "restore_file":
            roots = self.gateway.tools["update_config"]["parameters"]["path"]["allowed_roots"]
            mapped = self._map_virtual_path(rollback["path"], allowed_roots=roots)
            if rollback["existed"]:
                mapped.parent.mkdir(parents=True, exist_ok=True)
                mapped.write_text(rollback["before"], encoding="utf-8")
            elif mapped.exists():
                mapped.unlink()
        else:
            raise SandboxExecutionError("未知回滚类型")

        operation["status"] = "rolled_back"
        operation["rolled_back_at"] = self.clock()
        self._atomic_json_write(self.operations_path, document)
        self._audit(
            "sandbox_operation_rolled_back",
            {"operation_id": operation_id, "tool": operation["tool"]},
        )
        return {"operation_id": operation_id, "status": "rolled_back"}

    def list_operations(self) -> list[dict[str, Any]]:
        document = json.loads(self.operations_path.read_text(encoding="utf-8"))
        return sorted(
            document["operations"].values(),
            key=lambda item: item["executed_at"],
            reverse=True,
        )

