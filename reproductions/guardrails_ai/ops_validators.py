"""Guardrails AI 的本地运维验证器；只检查数据，不执行工具。"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from guardrails.classes.validation.validation_result import FailResult, PassResult
from guardrails.validator_base import Validator, register_validator

from offline_requests import parse_read_only_request
from structured_tools import StructuredToolGateway


@lru_cache(maxsize=1)
def _gateway() -> StructuredToolGateway:
    return StructuredToolGateway()


_INJECTION_PATTERNS = (
    re.compile(r"(?i)<\|(?:im_start|system|developer|assistant)\|>|\[/?INST\]|<\s*/?\s*(?:system|developer)\s*>"),
    re.compile(r"(?i)(?:忽略|无视|覆盖|绕过).{0,24}(?:之前|上述|系统|开发者|安全|规则|指令|策略)"),
    re.compile(r"(?i)\b(?:ignore|disregard|override)\b.{0,45}\b(?:previous|system|developer|safety|instructions|rules)\b"),
    re.compile(r"(?i)(?:你现在是|扮演|假装是).{0,12}(?:系统|开发者|管理员)"),
    re.compile(r"(?i)\byou are now (?:the )?(?:system|developer|administrator|admin)\b"),
    re.compile(r"(?i)(?:把|将).{0,15}(?:risk|风险等级|actionable|decision).{0,15}(?:设为|设置为|改成|写成).{0,15}(?:low|allow|true|低风险|通过)"),
    re.compile(r"(?i)\b(?:set|mark|return)\b.{0,20}\b(?:risk|actionable|decision)\b.{0,15}\b(?:low|allow|true)\b"),
)

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token|secret|token)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
)


@register_validator(name="ops/prompt-injection", data_type="string")
class PromptInjectionValidator(Validator):
    """识别明确的角色伪造和要求篡改安全判断的输入。"""

    def _validate(self, value: Any, metadata: dict[str, Any]):
        if not isinstance(value, str) or any(pattern.search(value) for pattern in _INJECTION_PATTERNS):
            return FailResult(error_message="请求包含提示注入或安全判断篡改指令")
        return PassResult()


@register_validator(name="ops/sensitive-input", data_type="string")
class SensitiveInputValidator(Validator):
    """避免用户把完整凭据交给模型处理。"""

    def _validate(self, value: Any, metadata: dict[str, Any]):
        if not isinstance(value, str) or any(pattern.search(value) for pattern in _SECRET_PATTERNS):
            return FailResult(error_message="请求包含疑似凭据或私钥")
        return PassResult()


@register_validator(name="ops/sensitive-content", data_type="object")
class SensitiveContentValidator(Validator):
    """拒绝模型输出中的凭据及高风险配置内容。"""

    def _validate(self, value: Any, metadata: dict[str, Any]):
        if not isinstance(value, dict):
            return FailResult(error_message="候选结果不是对象")
        arguments = value.get("arguments", {})
        fields = [value.get("intent", ""), value.get("reason", "")]
        if isinstance(arguments, dict):
            fields.extend(item for item in arguments.values() if isinstance(item, str))
        if any(pattern.search(field) for field in fields for pattern in _SECRET_PATTERNS):
            return FailResult(error_message="候选结果包含疑似凭据或私钥")
        if value.get("tool") == "update_config" and isinstance(arguments, dict):
            content = arguments.get("content")
            if isinstance(content, str) and (
                re.search(r"(?im)^\s*(?:PermitRootLogin|PasswordAuthentication)\s+yes\b", content)
                or re.search(r"(?im)^\s*(?:audit_enabled|authentication_enabled|tls_verify)\s*[:=]\s*(?:false|off|0)\b", content)
                or re.search(r"(?i)\b(?:curl|wget)\b.{0,80}\|\s*(?:sh|bash)\b", content)
            ):
                return FailResult(error_message="候选配置包含削弱安全控制或执行外部脚本的内容")
        return PassResult()


@register_validator(name="ops/tool-parameters", data_type="object")
class ToolParametersValidator(Validator):
    """候选阶段复用执行网关的工具参数白名单。"""

    def _validate(self, value: Any, metadata: dict[str, Any]):
        if not isinstance(value, dict):
            return FailResult(error_message="候选结果不是对象")
        if value.get("actionable") is not True:
            return PassResult()
        if _gateway().validate_arguments(value.get("tool"), value.get("arguments")):
            return FailResult(error_message="工具参数不符合白名单、类型、范围或目录限制")
        return PassResult()


def _requested_tools(user_text: str) -> set[str]:
    # 配置正文和绝对路径是数据，不应把 log.conf、disk 等词误识别为第二个操作。
    intent_text = re.split(r"完整内容\s*[:：]", user_text, maxsplit=1)[0]
    intent_text = re.sub(r"/[A-Za-z0-9_./-]+", " ", intent_text)
    text = re.sub(
        r"(?:不要|无需|不必|禁止|不应|不用)\s*(?:重启|停止|关闭|修改|更新|编辑)\s*(?:[A-Za-z0-9_-]+\s*)?(?:服务|配置)?",
        "",
        intent_text,
    )
    lowered = text.lower()
    tools: set[str] = set()
    read_verb = r"(?:查看|读取|检查|查询|显示|获取|show|read|check|get)"
    if re.search(read_verb + r".{0,32}(?:磁盘|硬盘|\bdisk\b|\bdf\b|\bdu\b)", lowered):
        tools.add("check_disk")
    if re.search(read_verb + r".{0,40}(?:日志|\blog\b|journalctl|\btail\b)", lowered):
        tools.add("read_log")
    if re.search(r"重启|重新启动|\brestart\b", lowered):
        tools.add("restart_service")
    if re.search(r"(?:修改|更新|编辑|更改|写入|设置|change|edit|update).{0,40}(?:配置|config|\.conf\b)|(?:配置|config|\.conf\b).{0,40}(?:修改|更新|编辑|更改|写入|设置|change|edit|update)", lowered):
        tools.add("update_config")
    if re.search(r"状态|是否正常|是否运行|\bstatus\b", lowered) and re.search(r"服务|nginx|payment|\bapi\b", lowered):
        tools.add("get_service_status")
    return tools


@register_validator(name="ops/intent-tool-match", data_type="object")
class IntentToolMatchValidator(Validator):
    """约束模型候选必须与用户明确请求的唯一工具和关键参数一致。"""

    def _validate(self, value: Any, metadata: dict[str, Any]):
        user_text = metadata.get("user_text")
        if not isinstance(user_text, str) or not isinstance(value, dict) or value.get("actionable") is not True:
            return PassResult()
        tool = value.get("tool")
        arguments = value.get("arguments", {})
        exact = parse_read_only_request(user_text, _gateway().tools["get_service_status"]["parameters"]["name"]["allowed_values"])
        if exact is not None:
            return PassResult() if (tool, arguments) == exact else FailResult(error_message="候选工具或参数与用户请求不一致")
        requested = _requested_tools(user_text)
        if len(requested) != 1 or tool not in requested:
            return FailResult(error_message="请求未明确对应唯一白名单工具，或候选工具与请求不一致")
        if tool in {"get_service_status", "restart_service"}:
            name = arguments.get("name") if isinstance(arguments, dict) else None
            if not isinstance(name, str) or not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", user_text, re.I):
                return FailResult(error_message="候选服务名称不是用户明确指定的服务")
        if tool == "read_log" and isinstance(arguments, dict):
            paths = re.findall(r"/[A-Za-z0-9_./-]+", user_text)
            # 仅完整匹配的离线语法可推导 nginx 默认路径；其他表达必须指定唯一的完整路径和行数。
            if len(paths) != 1 or arguments.get("path") != paths[0]:
                return FailResult(error_message="读取日志必须明确指定唯一的完整路径")
            count = re.search(r"(?<!\d)(\d{1,4})\s*行", user_text)
            if count is None or arguments.get("lines") != int(count.group(1)):
                return FailResult(error_message="读取日志必须明确指定行数，且候选行数必须一致")
        if tool == "update_config" and isinstance(arguments, dict):
            path, content = arguments.get("path"), arguments.get("content")
            specified = re.search(r"完整内容\s*[:：](?P<content>[\s\S]+)\Z", user_text)
            target_paths = re.findall(r"/[A-Za-z0-9_./-]+", user_text[:specified.start()]) if specified else []
            expected_content = specified.group("content").strip() if specified else ""
            if (
                len(target_paths) != 1 or path != target_paths[0]
                or not expected_content or content != expected_content
            ):
                return FailResult(error_message="修改配置必须由用户明确提供目标路径和完整内容")
        return PassResult()
