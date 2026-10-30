"""结构化工具调用授权网关。只验证调用，不执行任何系统操作。"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml
from ops_catalog import load_catalog


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "policy" / "tools.yml"
SAFE_SERVICE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}$")


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    decision: str
    tool_risk: str
    llm_risk: str
    effective_risk: str
    reasons: tuple[str, ...]
    call_digest: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        return data


class StructuredToolGateway:
    """验证工具名、参数、角色和审批；不包含 Shell 执行能力。"""

    def __init__(self, config_path: Path | str = DEFAULT_CONFIG) -> None:
        self.config_path = Path(config_path)
        self.config = load_catalog(self.config_path)
        self.tools: dict[str, dict[str, Any]] = self.config["tools"]
        self.risk_order: dict[str, int] = self.config["risk_order"]

    @staticmethod
    def call_digest(tool: str, arguments: dict[str, Any]) -> str:
        canonical = json.dumps(
            {"tool": tool, "arguments": arguments},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _max_risk(self, first: str, second: str) -> str:
        if first not in self.risk_order or second not in self.risk_order:
            raise ValueError("unknown risk level")
        return max((first, second), key=self.risk_order.__getitem__)

    @staticmethod
    def _path_within(path: str, roots: list[str]) -> bool:
        # 虚拟路径采用 POSIX 语义；Windows 会把反斜杠当分隔符，冒号还可能触发 ADS/驱动器语义。
        if not path.startswith("/") or "\\" in path or ":" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
            return False
        if any(part == ".." for part in path.split("/")):
            return False
        normalized = posixpath.normpath(path)
        return any(
            normalized == root or normalized.startswith(root.rstrip("/") + "/")
            for root in roots
        )

    def _validate_arguments(
        self, spec: dict[str, Any], arguments: dict[str, Any]
    ) -> list[str]:
        errors: list[str] = []
        parameters = spec.get("parameters", {})
        unknown = sorted(set(arguments) - set(parameters))
        if unknown:
            errors.append("存在未声明参数：" + ", ".join(unknown))

        for name, rule in parameters.items():
            if rule.get("required") and name not in arguments:
                errors.append(f"缺少必填参数：{name}")
                continue
            if name not in arguments:
                continue

            value = arguments[name]
            value_type = rule["type"]
            if value_type == "integer":
                if isinstance(value, bool) or not isinstance(value, int):
                    errors.append(f"参数 {name} 必须是整数")
                elif value < rule.get("minimum", value) or value > rule.get("maximum", value):
                    errors.append(f"参数 {name} 超出允许范围")
            elif value_type == "string":
                if not isinstance(value, str):
                    errors.append(f"参数 {name} 必须是字符串")
                elif not rule.get("minimum_length", 0) <= len(value) <= rule.get("maximum_length", len(value)):
                    errors.append(f"参数 {name} 长度超出允许范围")
            elif value_type == "service_name":
                if not isinstance(value, str) or not SAFE_SERVICE_NAME.fullmatch(value):
                    errors.append(f"参数 {name} 不是安全的服务名")
                elif value not in rule["allowed_values"]:
                    errors.append(f"服务 {value} 不在白名单")
            elif value_type == "absolute_posix_path":
                if not isinstance(value, str) or not self._path_within(
                    value, rule["allowed_roots"]
                ):
                    errors.append(f"路径 {name} 越出允许目录")
            else:
                errors.append(f"参数 {name} 使用未知类型 {value_type}")
        return errors

    def validate_arguments(self, tool: str, arguments: dict[str, Any]) -> list[str]:
        """复用执行网关的参数规则，供候选生成阶段预检。"""
        spec = self.tools.get(tool)
        if spec is None:
            return ["工具不存在或未列入白名单"]
        if not isinstance(arguments, dict):
            return ["工具参数必须是对象"]
        return self._validate_arguments(spec, arguments)

    def authorize(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        role: str,
        llm_risk: str = "low",
        approval: dict[str, Any] | None = None,
    ) -> ToolDecision:
        digest = self.call_digest(tool, arguments)
        if tool not in self.tools:
            return ToolDecision(
                tool, "deny", "critical", llm_risk, "critical",
                ("工具不存在或未列入白名单",), digest,
            )

        spec = self.tools[tool]
        tool_risk = spec["risk"]
        effective_risk = self._max_risk(tool_risk, llm_risk)
        reasons: list[str] = []

        if role not in spec["allowed_roles"]:
            reasons.append(f"角色 {role} 无权调用该工具")
        reasons.extend(self._validate_arguments(spec, arguments))
        if reasons:
            return ToolDecision(
                tool, "deny", tool_risk, llm_risk, effective_risk,
                tuple(reasons), digest,
            )

        if effective_risk == "critical":
            return ToolDecision(
                tool, "deny", tool_risk, llm_risk, effective_risk,
                ("组合风险达到 critical",), digest,
            )

        if spec.get("requires_approval") or effective_risk in {"medium", "high"}:
            valid_approval = bool(
                approval
                and approval.get("approved") is True
                and approval.get("tool") == tool
                and approval.get("call_digest") == digest
            )
            if not valid_approval:
                return ToolDecision(
                    tool, "require_human", tool_risk, llm_risk, effective_risk,
                    ("需要与本次工具及参数绑定的人工审批",), digest,
                )

        return ToolDecision(
            tool, "allow", tool_risk, llm_risk, effective_risk,
            ("工具、参数、角色和审批检查通过",), digest,
        )


if __name__ == "__main__":
    gateway = StructuredToolGateway()
    result = gateway.authorize(
        "read_log",
        {"path": "/var/log/nginx/error.log", "lines": 50},
        role="viewer",
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))

