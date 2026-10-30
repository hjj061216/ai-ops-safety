"""真实Guardrails安全验证器的教学示例，不执行任何工具。"""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8")
from guardrails_output_validator import GuardrailsAIOutputValidator
from structured_tools import StructuredToolGateway


sample = {"actionable": True, "intent": "查看日志", "tool": "read_log", "arguments": {"path": "/var/log/nginx/error.log", "lines": 2}, "risk": "low", "reason": "只读查询"}
cases = {"valid_log": copy.deepcopy(sample), "invalid_risk_enum": copy.deepcopy(sample), "too_many_lines": copy.deepcopy(sample), "wrong_intent": copy.deepcopy(sample)}
cases["invalid_risk_enum"]["risk"] = "safe"
cases["too_many_lines"]["arguments"]["lines"] = 201
requests = {
    "valid_log": "查看 nginx 最近两行错误日志",
    "invalid_risk_enum": "查看 nginx 最近两行错误日志",
    "too_many_lines": "查看 nginx 最近 201 行错误日志",
    "wrong_intent": "查看服务器当前系统时间",
}
validator, gateway = GuardrailsAIOutputValidator(), StructuredToolGateway()
results = {}
for name, case in cases.items():
    try:
        validated = validator.validate_with_context(json.dumps(case, ensure_ascii=False), requests[name])
        decision = gateway.authorize(validated["tool"], validated["arguments"], role="viewer", llm_risk=validated["risk"])
        results[name] = {"guardrails_passed": True, "gateway_decision": decision.decision, "reasons": list(decision.reasons)}
    except ValueError as error:
        results[name] = {"guardrails_passed": False, "gateway_decision": "not_called", "reason": str(error)}
print(json.dumps({"real_validator": True, "tool_execution": False, "results": results}, ensure_ascii=False, indent=2))
