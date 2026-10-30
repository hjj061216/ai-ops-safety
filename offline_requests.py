"""完整匹配少量只读请求；不推测复杂意图，也不执行工具。"""
from __future__ import annotations

import re
from typing import Any, Iterable


from ops_catalog import READ_ONLY_TOOLS, KNOWN_SERVICE_LOGS
PREFIX = r"(?:请(?:帮我)?|帮我)?\s*"
ENDING = r"[。.!?？]?"
COUNT = r"(?P<count>[0-9]{1,3}|[一二两三四五六七八九十百]{1,4})"
DIGITS = dict(zip("一二三四五六七八九", range(1, 10))) | {"两": 2}


def _line_count(value: str) -> int | None:
    if value.isascii() and value.isdecimal():
        return int(value)
    if value in DIGITS:
        return DIGITS[value]
    if value in {"一百", "二百", "两百"}:
        return 100 if value == "一百" else 200
    if value.count("十") == 1:
        tens, units = value.split("十")
        if (not tens or tens in DIGITS) and (not units or units in DIGITS):
            return DIGITS.get(tens, 1) * 10 + DIGITS.get(units, 0)
    return None


def parse_read_only_request(
    text: str, service_names: Iterable[str]
) -> tuple[str, dict[str, Any]] | None:
    """仅接受完整的单条查询；附带额外指令或缺少参数时不生成调用。"""
    if "\n" in text or "\r" in text:
        return None
    request = text.strip()
    disk = PREFIX + r"(?:查看|检查)\s*(?:当前|服务器|当前服务器)?\s*磁盘(?:使用情况|使用率|空间|剩余空间)?" + ENDING
    if re.fullmatch(disk, request):
        return "check_disk", {}

    names = "|".join(re.escape(name) for name in service_names)
    if names:
        service = PREFIX + rf"(?:查看|检查)\s*(?P<name>{names})\s*服务(?:的)?(?:状态|运行状态|是否正常)" + ENDING
        matched = re.fullmatch(service, request, flags=re.I)
        if matched:
            return "get_service_status", {"name": matched["name"].lower()}

    # nginx 的错误日志路径明确；其他日志必须给出完整路径。
    log_patterns = (
        PREFIX + r"(?:查看|读取)\s*nginx\s*(?:最近|最后)\s*" + COUNT + r"\s*行\s*错误日志" + ENDING,
        PREFIX + r"(?:查看|读取)\s*nginx\s*错误日志\s*(?:最近|最后)\s*" + COUNT + r"\s*行" + ENDING,
        PREFIX + r"(?:查看|读取)\s*(?:应用日志\s*)?(?P<path>/[A-Za-z0-9_./-]+)\s+(?:最近|最后)\s*" + COUNT + r"\s*行" + ENDING,
    )
    for pattern in log_patterns:
        matched = re.fullmatch(pattern, request, flags=re.I)
        if matched:
            lines = _line_count(matched["count"])
            if lines is None:
                return None
            path = matched.groupdict().get("path") or KNOWN_SERVICE_LOGS["nginx"]
            return "read_log", {"path": path, "lines": lines}
    return None
