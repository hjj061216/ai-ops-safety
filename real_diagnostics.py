"""Fixed-resource, read-only local observations; never executes system changes."""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ops_catalog import KNOWN_SERVICE_LOGS, SERVICE_NAMES
from sandbox_executor import SandboxExecutionError, SandboxExecutor
from structured_tools import StructuredToolGateway


_SECRET_NAME = r"(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|token|(?:access|refresh|auth)[_-]?token|api[_-]?key|secret|private[_-]?key|access[_-]?key(?:[_-]?id)?|authorization|cookie|set-cookie)"
_SECRET_FIELD = re.compile(rf"(?i)^\s*{_SECRET_NAME}\s*$")
_ASSIGNMENT = re.compile(
    rf'''(?im)((?:["']?\b{_SECRET_NAME}["']?)\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|\Z)|'(?:\\.|[^'\\])*(?:'|\Z)|[^\s,;}}]+)'''
)
_PEM = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)", re.DOTALL)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_CREDENTIAL_HEADER = re.compile(r"(?im)(\b(?:set-cookie|cookie|authorization)\s*[:=][ \t]*)[^\r\n]*")


def redact_sensitive(value: Any) -> Any:
    """Hide recognizable credential fields before observation persistence or display."""
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET_FIELD.fullmatch(str(key)) else redact_sensitive(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if not isinstance(value, str):
        return value
    value = _PEM.sub("[REDACTED PRIVATE KEY]", value)
    # A bounded tail may begin in the middle of a multiline private key.
    end = re.search(r"-----END [^-\r\n]*PRIVATE KEY-----", value)
    if end:
        value = "[REDACTED PRIVATE KEY]" + value[end.end():]
    # Header values can contain several independent credentials separated by
    # semicolons or spaces. Removing a single assignment would expose the rest.
    value = _CREDENTIAL_HEADER.sub(lambda match: match.group(1) + "[REDACTED]", value)
    value = _BEARER.sub(lambda match: match.group(1) + " [REDACTED]", value)
    return _ASSIGNMENT.sub(lambda match: match.group(1) + "[REDACTED]", value)


def _clip(text: str, limit: int) -> str:
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


class _DeadlineSocket(socket.socket):
    """Each blocking I/O shares one monotonic deadline, including header reads.

    socket.makefile() uses this socket's recv_into, so HTTPResponse cannot reset
    the budget when a peer keeps a header line or body alive one byte at a time.
    No background request survives a returned timeout.
    """

    def __init__(self, deadline):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.deadline = deadline

    def _remaining_timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("health observation deadline exceeded")
        self.settimeout(remaining)

    def connect(self, address):
        self._remaining_timeout()
        return super().connect(address)

    def sendall(self, data, flags=0):
        self._remaining_timeout()
        return super().sendall(data, flags)

    def recv_into(self, buffer, nbytes=0, flags=0):
        self._remaining_timeout()
        return super().recv_into(buffer, nbytes, flags)


class _DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(self, port, deadline):
        super().__init__("127.0.0.1", port)
        self.deadline = deadline

    def connect(self):
        # Fixed IPv4 literal: no DNS lookup, environment proxy or alternate host.
        connection = _DeadlineSocket(self.deadline)
        try:
            connection.connect(("127.0.0.1", self.port))
        except BaseException:
            connection.close()
            raise
        self.sock = connection


class ReadOnlyDiagnosticsExecutor(SandboxExecutor):
    """Reuse authorization/operation protocol without creating simulated service state."""

    SUPPORTED_TOOLS = {"get_service_status", "read_log", "check_disk"}
    HTTP_TIMEOUT = 2
    HTTP_BODY_BYTES = 16 * 1024
    HTTP_EXCERPT_BYTES = 2 * 1024
    LOG_TAIL_BYTES = 64 * 1024
    LOG_RESULT_BYTES = 12 * 1024

    def __init__(self, root: Path | str, config_path: Path | str, *, audit=None):
        self.gateway = StructuredToolGateway()
        self.audit = audit
        self.clock = time.time
        self._lock = threading.RLock()
        self.services, self.logs = self._load_config(Path(config_path))
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.operations_path = self.root / ".operations.json"
        if not self.operations_path.exists():
            self._atomic_json_write(self.operations_path, {"operations": {}})

    @staticmethod
    def _validate_url(url: Any) -> str:
        if not isinstance(url, str) or any(ord(char) <= 32 or ord(char) == 127 for char in url) or "?" in url or "#" in url or "\\" in url:
            raise SandboxExecutionError("健康地址必须是固定本机 HTTP 地址，不能包含凭据或附加参数")
        try:
            parts = urlsplit(url)
            port = parts.port or 80
            if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.username is not None or parts.password is not None or port == 8765 or not 1 <= port <= 65535:
                raise ValueError()
            # Literal authority avoids alternative spellings and parser disagreement.
            if parts.netloc not in {"127.0.0.1", f"127.0.0.1:{port}"}:
                raise ValueError()
        except (ValueError, TypeError):
            raise SandboxExecutionError("健康地址只允许 127.0.0.1 的非控制台 HTTP 端口") from None
        return url

    @staticmethod
    def _validate_log_path(path: Path) -> os.stat_result:
        if not path.is_absolute() or ".." in path.parts or any(ord(char) < 32 for char in str(path)):
            raise SandboxExecutionError("日志必须使用固定绝对文件路径")
        # Windows alternate data streams and UNC/device paths are not regular configured files.
        if os.name == "nt" and (str(path).startswith("\\\\") or ":" in str(path)[len(path.drive):]):
            raise SandboxExecutionError("日志不能使用设备、网络或备用数据流路径")
        for component in (*reversed(path.parents), path):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise SandboxExecutionError("日志路径不允许符号链接或重解析点")
        if not stat.S_ISREG(info.st_mode):
            raise SandboxExecutionError("日志必须是已存在的常规文件")
        return info

    def _load_config(self, config_path: Path):
        try:
            document = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or set(document) != {"version", "services", "logs"} or type(document["version"]) is not int or document["version"] != 1:
                raise ValueError()
            services, logs = document["services"], document["logs"]
            if not isinstance(services, dict) or not isinstance(logs, dict):
                raise ValueError()
            validated_services = {}
            for name, entry in services.items():
                if name not in SERVICE_NAMES or not isinstance(entry, dict) or set(entry) != {"health_url"}:
                    raise ValueError()
                validated_services[name] = self._validate_url(entry["health_url"])
            validated_logs = {}
            for virtual_path, local_path in logs.items():
                if virtual_path not in KNOWN_SERVICE_LOGS.values() or not isinstance(local_path, str):
                    raise ValueError()
                path = Path(local_path)
                self._validate_log_path(path)
                validated_logs[virtual_path] = path
            return validated_services, validated_logs
        except (OSError, ValueError, TypeError, KeyError):
            # Configuration can contain credentials: never echo raw input or exceptions.
            raise SandboxExecutionError("真实诊断配置无效：仅允许固定白名单资源和已存在的常规日志文件") from None

    def public_context(self):
        return {"backend": "local_readonly", "services": sorted(self.services), "log_paths": sorted(self.logs), "tools": ["get_service_status", "read_log", "check_disk"]}

    @staticmethod
    def _observation(source):
        return {"backend": "local_readonly", "source": str(source), "observed_at": datetime.now(timezone.utc).isoformat()}

    def _health(self, name):
        url = self.services[name]
        result = {"name": name, "status": "unreachable", "healthy": None, "http_status": None, "body_excerpt": "", "truncated": False, **self._observation(url)}
        started = time.perf_counter()
        connection = None
        try:
            parts = urlsplit(url)
            connection = _DeadlineHTTPConnection(parts.port or 80, time.monotonic() + self.HTTP_TIMEOUT)
            connection.request("GET", parts.path or "/", headers={"Accept": "text/plain, application/json", "Accept-Encoding": "identity", "Connection": "close"})
            with connection.getresponse() as response:
                result["http_status"] = response.status
                if 300 <= response.status < 400:
                    result["status"] = "redirect"
                    return result
                raw = response.read(self.HTTP_BODY_BYTES)
                text = redact_sensitive(raw.decode("utf-8", errors="replace"))
                result.update(status="healthy" if 200 <= response.status < 300 else "http_error", healthy=200 <= response.status < 300, body_excerpt=_clip(text, self.HTTP_EXCERPT_BYTES), truncated=len(raw) >= self.HTTP_BODY_BYTES or len(text.encode("utf-8")) > self.HTTP_EXCERPT_BYTES)
        except (socket.timeout, TimeoutError):
            result.update(status="timeout", healthy=None)
        except (OSError, http.client.HTTPException, ValueError):
            result.update(status="unreachable", healthy=None)
        finally:
            if connection is not None:
                connection.close()
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return result

    def _read_log(self, virtual_path, requested_lines):
        path = self.logs[virtual_path]
        result = {"path": virtual_path, "lines": [], "content": "", "available": False, "truncated": False, **self._observation(path)}
        try:
            before = self._validate_log_path(path)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as handle:
                opened = os.fstat(handle.fileno())
                after = self._validate_log_path(path)
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
                    raise SandboxExecutionError("读取期间日志路径发生变化")
                offset = max(0, opened.st_size - self.LOG_TAIL_BYTES)
                handle.seek(offset)
                raw = handle.read(self.LOG_TAIL_BYTES)
            # Drop a partial line at the read boundary, which could contain a cut credential.
            if offset:
                raw = raw.partition(b"\n")[2]
            text = redact_sensitive(raw.decode("utf-8", errors="replace"))
            all_lines = text.splitlines()
            lines = all_lines[-min(requested_lines, 200):]
            content = "\n".join(lines)
            truncated = offset > 0 or len(all_lines) > requested_lines or len(content.encode("utf-8")) > self.LOG_RESULT_BYTES
            # Keep the newest complete lines. Bound an unusually long last line too.
            while len(lines) > 1 and len("\n".join(lines).encode("utf-8")) > self.LOG_RESULT_BYTES:
                lines.pop(0)
            content = _clip("\n".join(lines), self.LOG_RESULT_BYTES)
            result.update(available=True, lines=content.splitlines(), content=content, truncated=truncated)
        except FileNotFoundError:
            result["error"] = "missing"
        except SandboxExecutionError:
            result["error"] = "unsafe_path"
        except PermissionError:
            result["error"] = "permission_denied"
        except OSError:
            result["error"] = "read_failed"
        return result

    def _audit(self, event, payload):
        super()._audit(event, redact_sensitive(payload))

    def execute(self, tool, arguments, decision):
        if tool not in self.SUPPORTED_TOOLS or not isinstance(arguments, dict):
            raise SandboxExecutionError("真实诊断后端只支持已配置的只读工具")
        self._verify_authorization(tool, arguments, decision)
        if tool == "get_service_status":
            if arguments["name"] not in self.services:
                raise SandboxExecutionError("该服务未配置真实健康地址")
            result = self._health(arguments["name"])
        elif tool == "read_log":
            if arguments["path"] not in self.logs:
                raise SandboxExecutionError("该日志未配置真实文件映射")
            result = self._read_log(arguments["path"], arguments["lines"])
        else:
            usage = shutil.disk_usage(self.root)
            result = {"total": usage.total, "used": usage.used, "free": usage.free, **self._observation(self.root)}
        result = redact_sensitive(result)
        with self._lock:
            operation_id = self._record_operation(tool=tool, arguments=redact_sensitive(arguments), call_digest=decision.call_digest, result=result, rollback=None)
            self._audit("readonly_diagnostic_executed", {"operation_id": operation_id, "tool": tool, "call_digest": decision.call_digest, "backend": "local_readonly", "rollback_available": False})
        return {"operation_id": operation_id, "result": result, "rollback_available": False}

    def list_operations(self):
        with self._lock:
            return redact_sensitive(super().list_operations())

    def rollback(self, operation_id):
        raise SandboxExecutionError("真实诊断后端仅可读取，不能回滚或变更真实资源")
