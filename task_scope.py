"""Server-side task scope checks; model observations never authorize new writes."""
import re
from dataclasses import dataclass, asdict
from offline_requests import _line_count, KNOWN_SERVICE_LOGS
from ops_catalog import DEFAULT_LOG_LINES, SERVICE_NAMES, READ_ONLY_TOOLS

DIAGNOSTIC = r"排查|诊断|故障|异常|不可用|打不开|有问题|分析|检查|看看"
TRIGGERS = {"check_disk": r"磁盘|硬盘|disk|\bdf\b", "get_service_status": r"状态|运行|健康|可达|存活|health|status|重启|restart",
            "read_log": r"日志|log", "restart_service": r"重启|重新启动|\brestart\b", "update_config": r"修改|更新|写入|设置|编辑|update|edit"}
NEGATIVE = r"不要|不许|禁止|不必|无需|不用|不得|不允许|别|do not|don't|never"
UNHEALTHY_STATUSES = {"stopped", "exited", "dead", "unhealthy", "restarting"}


def service_facts(result):
    status = result.get("status")
    healthy = result.get("healthy")
    if type(healthy) is not bool:
        healthy = True if status == "running" else False if status in UNHEALTHY_STATUSES else None
    return {"status":status, "healthy":healthy}


def positive_request(text):
    return re.sub(r"(?:" + NEGATIVE + r")[^，,。；;\n]*", "", text, flags=re.I)


def forbidden_tools(text):
    # A restriction ends at a clause boundary. “不要重启，查看日志” permits logs.
    clauses = re.split(r"[，,。；;\n]", re.split(r"完整内容\s*[:：]", text, maxsplit=1)[0])
    restrictions = {**TRIGGERS, "get_service_status":r"(?:检查|查看|查询).{0,8}(?:状态|运行|健康|可达|存活)|\bstatus\b|\bhealth\b"}
    return {tool for tool, trigger in restrictions.items() if any(
        re.search(r"(?:" + NEGATIVE + r").{0,12}(?:" + trigger + r")", clause, re.I) for clause in clauses)}


@dataclass
class TaskIntent:
    goal: str
    services: list
    log_paths: list
    log_lines: list
    allowed_tools: list
    forbidden_tools: list
    missing: list
    unsupported: list
    required: list
    defaults: list

    def public(self):
        return asdict(self)


def analyze_task(user_text):
    """Conservative server-owned scope, never inferred from model/tool text."""
    intent_text = re.split(r"完整内容\s*[:：]", user_text, maxsplit=1)[0]
    positive = positive_request(intent_text)
    services = [name for name in SERVICE_NAMES if mentions_service(positive, name)]
    logs = task_log_paths(user_text)
    forbidden = forbidden_tools(user_text)
    diagnostic = bool(re.search(r"排查|诊断|故障|异常|不可用|打不开|有问题|分析|看看", positive))
    allowed = [tool for tool in READ_ONLY_TOOLS if (diagnostic or re.search(TRIGGERS[tool], positive, re.I)) and tool not in forbidden]
    for tool in ("restart_service", "update_config"):
        if tool not in forbidden and re.search(TRIGGERS[tool], intent_text, re.I) and (tool != "update_config" or re.search(r"配置|/[A-Za-z0-9_./-]+", intent_text)):
            allowed.append(tool)
    if "read_log" not in allowed:
        logs = []
    missing, required, defaults = [], [], []
    if "get_service_status" in allowed and not services and (re.search(r"服务|重启|restart|状态", intent_text, re.I) or (diagnostic and not logs and "check_disk" not in allowed)):
        missing.append("要处理哪个服务？当前支持：" + "、".join(SERVICE_NAMES))
    if "read_log" in allowed and not logs and re.search(r"日志|log", intent_text, re.I):
        missing.append("请提供日志完整路径（允许 /var/log/nginx 或 /var/log/app 目录内的文件）。")
    lines = task_log_lines(user_text)
    if "read_log" in allowed and (len(lines) != 1 or lines[0] is None or not 1 <= lines[0] <= 200):
        missing.append("请指定统一的日志行数，范围为1至200行。")
    if logs:
        if not re.search(r"/[A-Za-z0-9_./-]+", intent_text):
            defaults.append("使用已配置的 nginx 错误日志：" + logs[0])
        if not re.search(r"[0-9一二两三四五六七八九十百]\s*行", intent_text):
            defaults.append(f"未指定行数，默认读取最近{DEFAULT_LOG_LINES}行")
    if "update_config" in allowed and (len(re.findall(r"/[A-Za-z0-9_./-]+", intent_text)) != 1 or not re.search(r"完整内容\s*[:：][\s\S]+", user_text)):
        missing.append("请提供配置文件完整路径，并用“完整内容：”给出修改后的全文。")
    for tool in READ_ONLY_TOOLS:
        if tool not in allowed:
            continue
        explicit = bool(re.search(TRIGGERS[tool], positive, re.I))
        # A diagnostic goal requires at least a service observation, even if
        # the model attempts an unsupported evidence-free completion.
        if not explicit and not (tool == "get_service_status" and diagnostic and services):
            continue
        targets = services if tool == "get_service_status" else logs if tool == "read_log" else [""]
        required.extend({"tool":tool, "target":target} for target in targets)
    unsupported = []
    if re.search(r"系统时间|当前时间|执行\s*(?:shell|任意命令)|重启\s*(?:mysql|数据库)|安装软件|删除文件", intent_text, re.I):
        unsupported.append("任务包含当前工具未支持的操作；目前支持磁盘、日志、服务状态、审批后模拟重启及配置修改。")
    if not allowed and not forbidden:
        unsupported.append("未识别到可支持的运维操作，请说明要查询的服务、日志或磁盘。")
    if not allowed and forbidden:
        missing.append("已记录禁止事项。你希望执行什么查询或操作？")
    return TaskIntent(user_text, services, logs, lines, allowed, sorted(forbidden), missing, unsupported, required, defaults)


def remaining_requirements(intent, history):
    remaining = [item for item in intent.required if not any(
        record["tool"] == item["tool"] and record.get("target", "") == item["target"] for record in history)]
    for name in intent.services:
        if "restart_service" not in intent.allowed_tools:
            continue
        restarts = [i for i, record in enumerate(history) if record["tool"] == "restart_service" and record.get("target") == name]
        conditional = bool(re.search(r"如果|只有|若", intent.goal))
        facts = [record.get("facts", {}) for record in history if record["tool"] == "get_service_status" and record.get("target") == name]
        needed = not conditional or (facts and (facts[-1].get("healthy") is False or facts[-1].get("status") in UNHEALTHY_STATUSES))
        if needed and not restarts:
            remaining.append({"tool":"restart_service", "target":name})
        if restarts and not any(record["tool"] == "get_service_status" and record.get("target") == name for record in history[restarts[-1] + 1:]):
            remaining.append({"tool":"get_service_status", "target":name, "reason":"变更后核验"})
    if "update_config" in intent.allowed_tools and not any(record["tool"] == "update_config" for record in history):
        remaining.append({"tool":"update_config", "target":"用户指定配置"})
    return remaining


def mentions_service(text: str, name: str) -> bool:
    # Python's Unicode \b treats both Chinese and Latin letters as word chars.
    # Use identifier boundaries so 查看nginx日志 works, but nginx_test does not.
    return bool(re.search(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])", text, re.I))


def task_log_paths(user_text: str) -> list[str]:
    intent = re.split(r"完整内容\s*[:：]", user_text, maxsplit=1)[0]
    explicit = list(dict.fromkeys(path for path in re.findall(r"/[A-Za-z0-9_./-]+", intent)
                                  if path.startswith("/var/log/") or path.endswith(".log")))
    if explicit:
        return explicit
    # Only the existing nginx error log is configured; an access log request
    # must not silently become an error log read.
    if re.search(r"访问日志|access\s*(?:log|日志)", intent, re.I):
        return []
    return [path for name, path in KNOWN_SERVICE_LOGS.items() if mentions_service(intent, name)]


def task_log_lines(user_text: str) -> list[int]:
    counts = {_line_count(item) for item in re.findall(r"([0-9]{1,4}|[一二两三四五六七八九十百]{1,4})\s*行", user_text)}
    return sorted(counts, key=lambda count: -1 if count is None else count) if counts else [DEFAULT_LOG_LINES]


def check_task_scope(value: dict, user_text: str) -> None:
    if value["status"] == "clarify" and not analyze_task(user_text).missing:
        raise ValueError("任务目标与必要参数已齐全，无需重复追问；请依据任务范围继续规划")
    if value["status"] != "propose":
        return
    tool, args = value["tool"], value["arguments"]
    if tool != "update_config":
        user_text = re.split(r"完整内容\s*[:：]", user_text, maxsplit=1)[0]
    if tool in forbidden_tools(user_text):
        raise ValueError("用户明确限制了该查询，请先澄清")
    diagnostic = bool(re.search(r"排查|诊断|故障|异常|不可用|打不开|有问题|分析|检查|看看", user_text))
    if tool == "check_disk":
        if not diagnostic and not re.search(r"磁盘|硬盘|disk|\bdf\b", user_text, re.I):
            raise ValueError("磁盘查询不在用户任务范围内")
    elif tool == "read_log":
        counts = {_line_count(item) for item in re.findall(r"([0-9]{1,4}|[一二两三四五六七八九十百]{1,4})\s*行", user_text)}
        if counts and (len(counts) != 1 or args.get("lines") not in counts):
            raise ValueError("候选日志行数与用户要求不一致")
        if not diagnostic and not re.search(r"日志|log", user_text, re.I):
            raise ValueError("日志查询不在用户任务范围内")
        path = args.get("path", "")
        if path not in task_log_paths(user_text):
            raise ValueError("日志目标不在本任务已指定或已配置的日志范围内")
    elif tool in {"get_service_status", "restart_service"}:
        name = args.get("name")
        if not isinstance(name, str) or not mentions_service(positive_request(user_text), name):
            raise ValueError("服务名称必须由用户明确指定，请先追问")
        if tool == "get_service_status" and not diagnostic and not re.search(TRIGGERS["get_service_status"], user_text, re.I):
            raise ValueError("服务查询不在用户任务范围内")
        if tool == "restart_service":
            conditional = bool(re.search(r"如果|只有|否则|若|\bif\b|\bunless\b", user_text, re.I))
            if conditional and not re.search(r"(?:如果|若|只有).{0,35}(?:异常|不正常|不可用|未运行|不健康|失败).{0,35}(?:重启|restart)", user_text, re.I):
                raise ValueError("尚不支持该条件，请明确服务异常时重启的条件")
            # Read an explicit positive restart clause, excluding a negative clause.
            clauses = re.split(r"[，,。；;\n]", user_text)
            unique_service = sum(mentions_service(positive_request(user_text), service) for service in SERVICE_NAMES) == 1
            if any(re.search(r"重启|restart", clause, re.I) and re.search(r"不要|不许|禁止|无需|不用|不必|不得|不允许|别|do not|don't|never", clause, re.I) for clause in clauses):
                raise ValueError("存在禁止重启的约束，请先明确任务范围")
            if not any(re.search(r"重启|重新启动|\brestart\b", clause, re.I)
                       and not re.search(r"不要|不许|禁止|无需|不用|不必|不得|不允许|别|do not|don't|never", clause, re.I)
                       and (mentions_service(clause, name)
                            or (conditional and unique_service)
                            # A targetless restart can bind to one user-supplied
                            # service, including a subsequent clarification.
                            # Explicitly named other services never match this.
                            or (unique_service and re.fullmatch(r"\s*(?:请|帮我)?\s*(?:重启|重新启动|restart)\s*(?:(?:这个|该|此)\s*)?(?:服务|service)?\s*[!！?？]?\s*", clause, re.I))) for clause in clauses):
                raise ValueError("用户未明确要求重启该服务；诊断结果不能授权变更")
    elif tool == "update_config":
        if re.search(r"不要|不许|禁止|不必|不得|别修改|do not|don't", user_text, re.I):
            raise ValueError("用户限制了配置变更，请先澄清")
        match = re.search(r"完整内容\s*[:：]([\s\S]+)\Z", user_text)
        prefix = user_text[:match.start()] if match else ""
        paths = re.findall(r"/[A-Za-z0-9_./-]+", prefix)
        if (not match or len(paths) != 1 or args.get("path") != paths[0]
                or args.get("content") != match[1].strip()
                or not re.search(r"修改|更新|写入|设置|编辑|update|edit", prefix, re.I)):
            raise ValueError("配置修改必须由用户提供唯一目标路径和完整内容")
    else:
        raise ValueError("任务包含不支持的工具")


def check_task_preconditions(value, user_text, history):
    if value.get("tool") != "restart_service":
        return
    name = value["arguments"]["name"]
    # Explicit “check first” is an execution dependency, not just plan text.
    if re.search(r"先.{0,25}(?:检查|查看|查询).{0,20}(?:状态|运行)", user_text) and not any(
            item["tool"] == "get_service_status" and item.get("target") == name for item in history):
        raise ValueError("用户要求先检查状态，必须先完成该查询")
    if not re.search(r"如果|只有|若", user_text):
        return
    observations = [item for item in history if item["tool"] == "get_service_status" and item.get("target") == name]
    if not observations:
        raise ValueError("条件重启必须先查询服务状态")
    facts = observations[-1].get("facts", {})
    if facts.get("healthy") is not False and facts.get("status") not in UNHEALTHY_STATUSES:
        raise ValueError("现有执行证据未证明服务异常，不满足重启条件")
