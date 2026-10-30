"""仅绑定本机的 AI 运维安全控制台，使用 Python 标准库。"""
from __future__ import annotations

import json
import hashlib
import re
import threading
import time
from contextvars import ContextVar
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, parse_qs
from auth import AuthStore, AuthenticationError, PermissionDenied

from approval_manager import ApprovalManager
from audit_log import HashChainAuditLog
from sandbox_executor import SandboxExecutionError, SandboxExecutor
from secure_tool_service import SecureToolService
from natural_language_agent import NaturalLanguageInterpreter
from offline_requests import READ_ONLY_TOOLS
from candidate_store import BoundCandidate, CandidateBindingError, CandidateStore
from task_agent import TaskCoordinator
from ops_catalog import KNOWN_SERVICE_LOGS
from real_diagnostics import ReadOnlyDiagnosticsExecutor


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
DEFAULT_RUNTIME = ROOT / "data" / "web_runtime"
MAX_BODY_BYTES = 1024 * 1024
CLIENT_DECISION_FIELDS = {"llm_risk", "risk", "effective_risk", "model_risk", "hard_risk", "source", "candidate_source", "decision", "approved"}
MANUAL_RISK_FLOOR = "medium"


class ExecutionAttemptError(RuntimeError):
    """已开始一次性执行尝试；异常不代表一定没有业务副作用。"""


class LocalSafetyApp:
    def __init__(self, runtime_root: Path | str = DEFAULT_RUNTIME, *, candidate_ttl_seconds: float = 900, candidate_clock: Callable[[], float] = time.time, diagnostics_config: Path | str | None = None) -> None:
        self.runtime_root = Path(runtime_root)
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.auth = AuthStore(self.runtime_root / "users.json")
        self.identity = ContextVar("ops_principal", default=None)
        self.backend = "local_readonly" if diagnostics_config is not None else "sandbox"
        self.audit = HashChainAuditLog(self.runtime_root / "security_audit.jsonl")
        self.approvals = ApprovalManager(self.runtime_root / "approvals.json")
        self.service = SecureToolService(approvals=self.approvals, audit=self.audit)
        self.interpreter = NaturalLanguageInterpreter()
        self.executor = (ReadOnlyDiagnosticsExecutor(self.runtime_root / "diagnostics", diagnostics_config, audit=self.audit)
                         if diagnostics_config is not None else SandboxExecutor(self.runtime_root / "sandbox", audit=self.audit))
        self.execution_context = self.executor.public_context() if diagnostics_config is not None else {"backend":"sandbox"}
        self.candidates = CandidateStore(ttl_seconds=candidate_ttl_seconds, clock=candidate_clock)
        self._operation_lock = threading.RLock()
        self._approval_candidates: dict[str, str] = {}
        self._approval_grants: dict[str, dict] = {}
        self._ownership_path = self.runtime_root / "operation_owners.json"
        self._operation_owners = json.loads(self._ownership_path.read_text(encoding="utf-8")) if self._ownership_path.exists() else {}
        self.tasks = TaskCoordinator(self)
        self.tasks.planner.environment = self.backend
        self.tasks.planner.execution_context = self.execution_context
        self.interpreter.environment = self.backend
        if self.backend == "sandbox":
            self._seed_demo_files()

    def _ensure_backend_call(self, tool, arguments):
        if self.backend != "local_readonly":
            return
        context = self.execution_context
        if tool not in context["tools"]:
            raise CandidateBindingError("真实只读模式不支持该操作；不能重启、修改配置或回滚")
        if tool == "get_service_status" and arguments.get("name") not in context["services"]:
            raise CandidateBindingError("该服务未配置真实健康接口")
        if tool == "read_log" and arguments.get("path") not in context["log_paths"]:
            raise CandidateBindingError("该日志未配置真实文件映射")

    def owner_id(self):
        principal = self.identity.get()
        return principal.username if principal else None

    def task_run(self, payload):
        return self.tasks.run(payload)

    def task_stop(self, payload):
        return self.tasks.stop(payload)

    def task_state(self, task_id):
        return self.tasks.view(task_id)

    def task_start(self, payload):
        with self._operation_lock:
            return self.tasks.start(payload)

    def task_reply(self, payload):
        with self._operation_lock:
            return self.tasks.reply(payload)

    def task_continue(self, payload):
        with self._operation_lock:
            return self.tasks.continue_task(payload)

    def _seed_demo_files(self) -> None:
        log = self.runtime_root / "sandbox" / KNOWN_SERVICE_LOGS["nginx"].lstrip("/")
        if not log.exists():
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                "2026-09-30 startup ok\n"
                "2026-09-30 upstream timeout\n"
                "2026-09-30 health recovered\n",
                encoding="utf-8",
            )

    @staticmethod
    def _reject_client_decisions(payload: dict[str, Any]) -> None:
        if CLIENT_DECISION_FIELDS.intersection(payload):
            raise CandidateBindingError("风险、来源和决策由服务端保存，不接受客户端提供或改写")

    def _bound_call(self, payload: dict[str, Any]) -> tuple[BoundCandidate, str]:
        self._reject_client_decisions(payload)
        candidate = self.candidates.get(payload.get("candidate_id", ""))
        self.tasks.validate_candidate(candidate.candidate_id)
        principal = self.identity.get()
        if principal and candidate.owner_id != principal.username:
            raise PermissionDenied("候选不属于当前用户")
        role = principal.role if principal else payload.get("role", "viewer")
        if not isinstance(role, str):
            raise ValueError("role 必须是字符串")
        tool = payload.get("tool", candidate.tool)
        arguments = payload.get("arguments", candidate.arguments)
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            raise CandidateBindingError("客户端工具或参数类型无效")
        json.dumps(arguments, allow_nan=False)
        if self.service.gateway.call_digest(tool, arguments) != candidate.call_digest:
            raise CandidateBindingError("工具或参数与服务端候选不一致，请重新生成候选")
        self._ensure_backend_call(tool,arguments)
        return candidate, role

    def status(self) -> dict[str, Any]:
        principal = self.identity.get()
        approvals = self.approvals.list_public_records()
        operations = self.executor.list_operations()
        if principal:
            if principal.role not in {"admin", "approver"}:
                approvals = [item for item in approvals if item["requester"] == principal.username]
            if principal.role != "admin":
                operations = [item for item in operations if self._operation_owners.get(item["operation_id"]) == principal.username]
        return {
            "service": "AI 运维 Agent 安全控制台",
            "mode": "local_readonly_diagnostics" if self.backend == "local_readonly" else "local_sandbox_demo",
            "execution_backend": self.backend,
            "execution_resources": self.execution_context,
            "identity": {"username": principal.username, "role": principal.role} if principal else None,
            "tools": sorted(self.service.gateway.tools),
            "approvals": approvals,
            "operations": operations,
            "audit": self.audit.verify(),
            "natural_language": {
                "enabled": True,
                **self.interpreter.configuration_status(),
                "execution": "manual_confirmation_required",
                "backend_state": self.interpreter.backend_state,
                "fallback_available": True,
                "fallback_tools": list(READ_ONLY_TOOLS),
                "server_bound_candidates": True,
            },
            "candidate_policy": {"ttl_seconds": self.candidates.ttl_seconds, "manual_risk_floor": MANUAL_RISK_FLOOR, **self.candidates.counts()},
            "open_source_reproductions": [
                {"project": "NVIDIA NeMo Guardrails", "version": "0.24.1", "role": "input_and_execution_rails"},
                {"project": "Guardrails AI", "version": "0.11.0", "role": "input_and_candidate_validation"},
                {"project": "AgentDojo", "version": "0.1.35", "role": "prompt_injection_evaluation"},
            ],
        }

    def interpret(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_text = payload.get("request", "")
        if not isinstance(request_text, str):
            raise ValueError("request 必须是字符串")
        result = self.interpreter.interpret(request_text)
        result = dict(result)
        result.pop("candidate_id", None)
        result.pop("expires_at", None)
        if result.get("actionable") is True and result.get("decision") in {"allow", "require_human"}:
            spec = self.service.gateway.tools.get(result.get("tool"))
            if spec is None:
                raise CandidateBindingError("分析返回的工具不在后端白名单")
            if self.service.gateway.validate_arguments(result["tool"], result["arguments"]):
                result.update(
                    actionable=False, tool=None, arguments={}, effective_risk="critical", decision="deny",
                    reasons=[*result.get("reasons", []), "候选参数未通过后端工具白名单预检"],
                )
            else:
                result["effective_risk"] = max((result["effective_risk"], spec["risk"]), key=self.service.gateway.risk_order.__getitem__)
                result["decision"] = "require_human" if spec.get("requires_approval") or result["effective_risk"] in {"medium", "high"} else "allow"
        self.audit.append(
            "natural_language_interpretation",
            {
                "request_sha256": hashlib.sha256(
                    request_text.encode("utf-8")
                ).hexdigest(),
                "intent": result["intent"],
                "tool": result["tool"],
                "effective_risk": result["effective_risk"],
                "decision": result["decision"],
                "matched_rules": result["matched_rules"],
                "engine": result.get("engine", "ollama"),
                "fallback_used": result.get("fallback_used", False),
            },
        )
        if result.get("actionable") is True and result.get("decision") in {"allow", "require_human"}:
            self._ensure_backend_call(result["tool"], result["arguments"])
            candidate = self.candidates.issue(result["tool"], result["arguments"], 
                                              effective_risk=result["effective_risk"], 
                                              source="offline_rules" if result.get("fallback_used") else "natural_language", owner_id=self.owner_id())
            result.update(candidate.public_fields())
        return result

    def prepare_manual(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._reject_client_decisions(payload)
        tool, arguments = payload.get("tool"), payload.get("arguments", {})
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            raise ValueError("tool 必须是字符串，arguments 必须是对象")
        self._ensure_backend_call(tool, arguments)
        text = json.dumps({"tool": tool, "arguments": arguments}, ensure_ascii=False, sort_keys=True, allow_nan=False)
        hard_risk, _, _ = self.interpreter.policy.evaluate_hard_rules(text)
        risk = max((hard_risk, MANUAL_RISK_FLOOR), key=self.service.gateway.risk_order.__getitem__)
        # admin仅用于预检参数；实际检查/执行仍验证用户提交的模拟角色。
        preliminary = self.service.gateway.authorize(tool, arguments, role="admin", llm_risk=risk)
        if preliminary.decision == "deny":
            raise CandidateBindingError("手动候选拒绝：" + "；".join(preliminary.reasons))
        self.audit.append("manual_candidate_prepared", {"tool": tool, "call_digest": preliminary.call_digest, "effective_risk": preliminary.effective_risk})
        candidate = self.candidates.issue(tool, arguments, effective_risk=preliminary.effective_risk, source="manual_form", owner_id=self.owner_id())
        return {"actionable": True, "intent": "人工结构化请求", "decision": "require_human", "message": "手动入口未进行模型语义分析，后端按至少medium风险处理，需要人工审批。", **candidate.public_fields()}

    def check(self, payload: dict[str, Any]) -> dict[str, Any]:
        candidate, role = self._bound_call(payload)
        return self.service.check_call(
            candidate.tool, candidate.arguments, role=role, llm_risk=candidate.effective_risk
        ).to_dict()

    def request_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        candidate, role = self._bound_call(payload)
        requester = self.owner_id() or payload.get("requester", "")
        reason = payload.get("reason", "")
        if not isinstance(requester, str) or not isinstance(reason, str):
            raise ValueError("requester 和 reason 必须是字符串")
        with self._operation_lock:
            self.candidates.get(candidate.candidate_id)
            request = self.service.request_approval(
                candidate.tool, candidate.arguments, requester=requester, requester_role=role,
                reason=reason, llm_risk=candidate.effective_risk,
            )
            self._approval_candidates[request["request_id"]] = candidate.candidate_id
            return request

    def approve(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._reject_client_decisions(payload)
        request_id = payload.get("request_id", "")
        principal = self.identity.get()
        approver = principal.username if principal else payload.get("approver", "")
        approver_role = principal.role if principal else payload.get("approver_role", "")
        if not all(isinstance(item, str) for item in (request_id, approver, approver_role)):
            raise ValueError("审批字段必须是字符串")
        with self._operation_lock:
            if principal and principal.role not in {"admin", "approver"}:
                raise PermissionDenied("当前登录账号无审批权限")
            candidate_id = self._approval_candidates.get(request_id)
            if candidate_id is None:
                raise CandidateBindingError("审批没有绑定当前服务器的有效候选，请重新生成并申请")
            self.candidates.get(candidate_id)
            if principal and self.approvals.get_public_record(request_id)["requester"] == principal.username:
                raise PermissionDenied("不能批准自己提交的请求")
            grant = self.service.approve_request(request_id, approver=approver, approver_role=approver_role)
            if principal:
                self._approval_grants[request_id] = grant
                self.tasks.resume_after_approval(request_id)
                return {key: value for key, value in grant.items() if key != "approval_token"}
            return grant

    def approval_grant(self, payload):
        principal = self.identity.get()
        if principal is None:
            raise AuthenticationError("请先登录")
        request_id = payload.get("request_id", "")
        record = self.approvals.get_public_record(request_id)
        if record["requester"] != principal.username:
            raise PermissionDenied("不能领取其他用户的审批结果")
        grant = self._approval_grants.get(request_id)
        if record["status"] != "approved" or time.time() >= record["expires_at"] or not grant:
            return {"approved": False, "status": record["status"]}
        return {"approved": True, **grant}

    def execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            candidate, role = self._bound_call(payload)
            self._ensure_backend_call(candidate.tool, candidate.arguments)
            request_id, token = payload.get("request_id"), payload.get("approval_token")
            if bool(request_id) != bool(token):
                raise CandidateBindingError("审批申请ID和令牌必须同时提供")
            if request_id:
                if not isinstance(request_id, str) or not isinstance(token, str):
                    raise CandidateBindingError("审批申请ID和令牌必须是字符串")
                if self._approval_candidates.get(request_id) != candidate.candidate_id:
                    raise CandidateBindingError("审批属于另一条候选，不能复用于当前调用")
            decision = self.service.check_call(candidate.tool, candidate.arguments, role=role, llm_risk=candidate.effective_risk)
            if decision.decision == "deny" or (decision.decision == "require_human" and not request_id):
                return {"executed": False, "decision": decision.to_dict(), "candidate_consumed": False}
            # 锁内复查有效期并在任何可能有副作用的执行尝试前消费；失败不恢复。
            self.candidates.consume(candidate.candidate_id)
            try:
                if decision.decision == "require_human":
                    decision = self.service.authorize_with_token(candidate.tool, candidate.arguments, role=role, 
                                                                 llm_risk=candidate.effective_risk, request_id=request_id, 
                                                                 approval_token=token)
                if decision.decision != "allow":
                    return {"executed": False, "decision": decision.to_dict(), "candidate_consumed": True}
                self._approval_grants.pop(request_id, None)
                operation = self.executor.execute(candidate.tool, candidate.arguments, decision)
                if self.owner_id():
                    self._operation_owners[operation["operation_id"]] = self.owner_id()
                    SandboxExecutor._atomic_json_write(self._ownership_path, self._operation_owners)
                    self.audit.append("operation_actor_bound", {"operation_id": operation["operation_id"], "actor": self.owner_id(), "role": role, "backend": self.backend})
                self.tasks.record_execution(candidate.candidate_id, operation)
            except Exception as exc:
                raise ExecutionAttemptError("执行尝试发生异常，可能部分完成；候选已作废，请核对操作与沙箱状态，不要重复提交。") from exc
            return {"executed": True, "decision": decision.to_dict(), "operation": operation, "candidate_consumed": True}

    def rollback(self, payload: dict[str, Any]) -> dict[str, Any]:
        operation_id = payload.get("operation_id", "")
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError("operation_id 不能为空")
        with self._operation_lock:
            principal = self.identity.get()
            if principal:
                if principal.role not in {"operator", "admin"}:
                    raise PermissionDenied("当前角色不能回滚")
                if principal.role != "admin" and self._operation_owners.get(operation_id) != principal.username:
                    raise PermissionDenied("只能回滚自己提交的操作")
                operation = next((item for item in self.executor.list_operations() if item["operation_id"] == operation_id), None)
                if not operation or principal.role not in self.service.gateway.tools[operation["tool"]]["allowed_roles"]:
                    raise PermissionDenied("当前角色无权恢复该工具的变更")
            result = self.executor.rollback(operation_id)
            if principal:
                self.audit.append("rollback_authorized", {"operation_id": operation_id, "actor": principal.username, "role": principal.role})
            return result

    def verify_audit(self) -> dict[str, Any]:
        return self.audit.verify()


class SafetyConsoleHandler(BaseHTTPRequestHandler):
    app: LocalSafetyApp
    server_version = "OpsSafetyConsole/1.0"
    auth_required = True

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def _session_cookie_name(self):
        tab = self.headers.get("X-Console-Tab")
        if tab is None:
            return "ops_session"  # Existing non-browser API clients.
        if not re.fullmatch(r"[a-f0-9]{32}", tab):
            raise PermissionDenied("标签页会话标识无效，请刷新页面")
        return "ops_session_" + tab

    def _token(self):
        name = self._session_cookie_name()
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        return cookie[name].value if name in cookie else ""

    def _authorize(self, *, write=False):
        if not self.auth_required:
            return None
        if write:
            self._check_origin()
        principal, _ = self.app.auth.session(self._token(), self.headers.get("X-CSRF-Token"), write=write)
        return self.app.identity.set(principal)

    def _check_origin(self):
        host = self.headers.get("Host", "")
        if urlparse("http://" + host).hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise PermissionDenied("仅接受本机访问")
        if self.headers.get("Origin") not in {None, "http://" + host}:
            raise PermissionDenied("请求来源不匹配")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise PermissionDenied("接口只接受 JSON 请求")

    def log_message(self, format: str, *args: Any) -> None:
        print("[local-app]", format % args)

    def _send_json(self, status: int, payload: dict[str, Any], *, cookie=None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.close_connection = True
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("请求体大小无效")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    def _serve_index(self) -> None:
        path = WEB_ROOT / "index.html"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(data)

    def _serve_workbench_asset(self, route: str) -> None:
        assets = {
            "/assets/workbench.css": ("workbench.css", "text/css; charset=utf-8"),
            "/assets/workbench.js": ("workbench.js", "text/javascript; charset=utf-8"),
        }
        filename, content_type = assets[route]
        data = (WEB_ROOT / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        context = None
        try:
            if path == "/":
                self._serve_index()
            elif path in {"/assets/workbench.css", "/assets/workbench.js"}:
                self._serve_workbench_asset(path)
            elif path == "/api/session":
                try:
                    principal, csrf = self.app.auth.session(self._token())
                    data = {"authenticated": True, "username": principal.username, "role": principal.role, "csrf": csrf}
                except AuthenticationError:
                    data = {"authenticated": False, "accounts_configured": bool(self.app.auth._users())}
                self._send_json(200, {"ok": True, "data": data})
            else:
                context = self._authorize()
                if path == "/api/status":
                    data = self.app.status()
                elif path == "/api/audit/verify":
                    data = self.app.verify_audit()
                elif path == "/api/tasks/state":
                    data = self.app.task_state(parse_qs(urlparse(self.path).query).get("task_id", [""])[0])
                elif path == "/api/tasks":
                    data = {"tasks": self.app.tasks.list_owned()}
                else:
                    self.send_error(404)
                    return
                self._send_json(200, {"ok": True, "data": data})
        except AuthenticationError as exc:
            self._send_json(401, {"ok": False, "error": str(exc)})
        except PermissionDenied as exc:
            self._send_json(403, {"ok": False, "error": str(exc)})
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            if context is not None:
                self.app.identity.reset(context)

    def do_POST(self) -> None:  # noqa: N802
        routes = {
            "/api/tasks/run": self.app.task_run,
            "/api/tasks/stop": self.app.task_stop,
            "/api/tasks/start": self.app.task_start,
            "/api/tasks/reply": self.app.task_reply,
            "/api/tasks/continue": self.app.task_continue,
            "/api/interpret": self.app.interpret,
            "/api/candidates/manual": self.app.prepare_manual,
            "/api/check": self.app.check,
            "/api/approvals/request": self.app.request_approval,
            "/api/approvals/approve": self.app.approve,
            "/api/approvals/grant": self.app.approval_grant,
            "/api/execute": self.app.execute,
            "/api/rollback": self.app.rollback,
        }
        context = None
        try:
            # Drain the bounded JSON body before returning authentication errors;
            # closing a socket with unread POST data can discard the response.
            payload = self._read_json()
            if urlparse(self.path).path == "/api/login":
                self._check_origin()
                cookie_name = self._session_cookie_name()
                previous_token = self._token()
                token, csrf, principal = self.app.auth.login(payload.get("username"), payload.get("password"))
                self.app.auth.logout(previous_token)
                self.app.audit.append("user_logged_in", {"actor": principal.username, "role": principal.role})
                self._send_json(200, {"ok": True, "data": {"authenticated": True, "username": principal.username, "role": principal.role, "csrf": csrf}},
                    cookie=f"{cookie_name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600")
                return
            context = self._authorize(write=True)
            if urlparse(self.path).path == "/api/logout":
                self.app.tasks.stop_for_owner(self.app.owner_id())
                self.app.auth.logout(self._token())
                self._send_json(200, {"ok": True, "data": {}}, cookie=f"{self._session_cookie_name()}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                return
            action = routes.get(urlparse(self.path).path)
            if action is None:
                self._send_json(404, {"ok": False, "error": "接口不存在"})
                return
            if self.auth_required and {"role", "requester", "approver", "approver_role"}.intersection(payload):
                raise PermissionDenied("身份与角色由登录会话确定，不能由请求指定")
            self._send_json(200, {"ok": True, "data": action(payload)})
        except AuthenticationError as exc:
            self._send_json(401, {"ok": False, "error": str(exc)})
        except PermissionDenied as exc:
            self._send_json(403, {"ok": False, "error": str(exc)})
        except (ValueError, KeyError, json.JSONDecodeError, SandboxExecutionError) as exc:
            self._send_json(400, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            if context is not None:
                self.app.identity.reset(context)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostics-config", type=Path, help="启用真实本机只读诊断，指定维护者配置的JSON资源映射")
    args = parser.parse_args()
    SafetyConsoleHandler.app = LocalSafetyApp(diagnostics_config=args.diagnostics_config)
    server = ThreadingHTTPServer(("127.0.0.1", 8765), SafetyConsoleHandler)
    print("AI 运维安全控制台已启动：http://127.0.0.1:8765")
    print("执行模式：" + ("真实本机只读诊断" if args.diagnostics_config else "本地模拟"))
    print("仅监听本机；按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n控制台已停止。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
