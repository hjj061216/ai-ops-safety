"""Small, deterministic evidence rules inside an already authorized read scope."""
from __future__ import annotations

import re

from ops_catalog import KNOWN_SERVICE_LOGS


def observation_facts(tool, result):
    """Extract bounded facts from collector output, never interpret log instructions."""
    if tool == "get_service_status":
        healthy = result.get("healthy")
        code = result.get("http_status")
        status = result.get("status")
        return {"status":status if status in {"healthy","http_error","unreachable","timeout","redirect"} else "unknown",
                "healthy":healthy if type(healthy) is bool else None,
                "http_status":code if type(code) is int and 100 <= code <= 599 else None}
    if tool == "read_log":
        text = str(result.get("content", ""))[:12000]
        patterns = {"disk_full":r"no space left on device|\bENOSPC\b|磁盘空间不足",
                    "connection_refused":r"connection refused|连接被拒绝",
                    "upstream_timeout":r"upstream timed out|upstream timeout|上游超时"}
        return {"available":result.get("available") is True,
                "signals":[name for name, pattern in patterns.items() if re.search(pattern,text,re.I)]}
    if tool == "check_disk":
        return {key:result.get(key) for key in ("total","used","free")
                if type(result.get(key)) is int and result[key] >= 0}
    return {}


def _diagnostic(intent, context):
    return context.get("backend") == "local_readonly" and bool(re.search(r"排查|诊断|故障|异常|不可用|打不开|有问题|分析|看看",intent.goal))


def pending_health_targets(intent, history, context):
    if not _diagnostic(intent,context) or "get_service_status" not in intent.allowed_tools:
        return []
    return [name for name in intent.services if not any(item["tool"] == "get_service_status" and item.get("target") == name for item in history)]


def check_diagnostic_preconditions(value, intent, history, context):
    if value["status"] == "propose" and pending_health_targets(intent,history,context) and value["tool"] != "get_service_status":
        raise ValueError("真实服务诊断必须先完成已授权的健康检查，再按结果选择日志或磁盘取证")


def diagnostic_requirements(intent, history, context):
    """No tool outside the user's read scope or fixed backend can be added."""
    if not _diagnostic(intent,context):
        return []
    allowed = set(intent.allowed_tools) & set(context.get("tools",[]))
    completed = {(item["tool"],item.get("target","")) for item in history}
    required = []
    for name in intent.services:
        probes = [item for item in history if item["tool"] == "get_service_status" and item.get("target") == name]
        if not probes or probes[-1].get("facts",{}).get("healthy") is True:
            continue
        path = KNOWN_SERVICE_LOGS.get(name)
        if path in context.get("log_paths",[]) and path in intent.log_paths and "read_log" in allowed and ("read_log",path) not in completed:
            required.append({"tool":"read_log","target":path,"reason":"健康检查异常或未知，读取已配置日志取证"})
    if "check_disk" in allowed and ("check_disk","") not in completed and any(
            item["tool"] == "read_log" and "disk_full" in item.get("facts",{}).get("signals",[]) for item in history):
        required.append({"tool":"check_disk","target":"","reason":"日志出现空间不足线索，核对本机磁盘容量"})
    return required


def diagnostic_assessment(intent, history, context):
    if context.get("backend") != "local_readonly":
        return {}
    report = {"confirmed":[],"hypotheses":[],"unknowns":[],"evidence":[],
              "required_checks":diagnostic_requirements(intent,history,context)}
    for item in history:
        facts = item.get("facts",{})
        ref = item.get("operation_id", "未编号证据")
        report["evidence"].append({key:item.get(key) for key in ("operation_id","tool","target","observed_at","source","truncated")})
        if item["tool"] == "get_service_status":
            name = item.get("target", "")
            code = facts.get("http_status")
            if code:
                report["confirmed"].append(f"[{ref}] {name} 的已配置健康接口返回 HTTP {code}。")
            elif facts.get("status") == "timeout":
                report["confirmed"].append(f"[{ref}] {name} 的健康检查超时。")
            else:
                report["confirmed"].append(f"[{ref}] 未获得 {name} 的有效健康响应。")
            if facts.get("healthy") is True:
                report["unknowns"].append(f"健康接口通过不能证明 {name} 的全部业务正常。")
            else:
                report["unknowns"].append(f"仅凭健康检查不能确定 {name} 的故障根因或进程是否停止。")
                path = KNOWN_SERVICE_LOGS.get(name)
                if "read_log" in intent.forbidden_tools:
                    report["unknowns"].append("用户禁止读取日志，未自动获取该项证据。")
                elif path not in context.get("log_paths",[]):
                    report["unknowns"].append(f"{name} 未配置可用的关联日志，缺少日志证据。")
        elif item["tool"] == "read_log":
            if facts.get("available"):
                report["confirmed"].append(f"[{ref}] 已读取配置日志 {item.get('target','')} 的受限尾部片段。")
            else:
                report["unknowns"].append("日志本次读取不可用，未获得有效日志证据。")
            if "disk_full" in facts.get("signals",[]):
                report["hypotheses"].append("日志出现空间不足线索；不能据此确认当前服务分区已满，需结合磁盘与时间信息核对。")
            if "connection_refused" in facts.get("signals",[]):
                report["hypotheses"].append("日志出现连接拒绝线索，可能涉及上游不可达，尚未独立确认原因。")
            if "upstream_timeout" in facts.get("signals",[]):
                report["hypotheses"].append("日志出现上游超时线索，尚未独立确认是网络、负载还是上游故障。")
        elif item["tool"] == "check_disk" and type(facts.get("free")) is int:
            report["confirmed"].append(f"[{ref}] 本机采集器所在磁盘剩余 {facts['free']} 字节。")
    if any(item.get("truncated") for item in history):
        report["unknowns"].append("部分响应或日志已截断，结论仅依据已采集片段。")
    if history:
        report["unknowns"].append("这些结果反映采集时刻；本轮只读诊断没有执行修复。")
    else:
        report["unknowns"].append("尚未执行查询，暂无可用于诊断的实际证据。")
    for key in ("confirmed","hypotheses","unknowns"):
        report[key] = list(dict.fromkeys(report[key]))
    return report
