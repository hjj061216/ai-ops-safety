"""隔离验证：先读取输入，再加载Guardrails依赖；stdout只输出结果JSON。"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

os.environ["OTEL_SDK_DISABLED"] = "true"
# Windows 的默认 asyncio loop 在受限环境中创建 self-pipe 可能阻塞；本地验证器按顺序执行。
os.environ["GUARDRAILS_RUN_SYNC"] = "true"
PHASE_PREFIX = "GUARDRAILS_PHASE "
STARTED = time.perf_counter()
CALL_ID = "standalone"


def phase(name: str) -> None:
    print(PHASE_PREFIX + json.dumps({"call_id": CALL_ID, "phase": name, "elapsed_seconds": round(time.perf_counter() - STARTED, 6)}, ensure_ascii=False), file=sys.stderr, flush=True)


@lru_cache(maxsize=1)
def build_guard():
    timings = {}
    phase("import_start")
    started = time.perf_counter()
    from guardrails import Guard
    from guardrails.settings import settings
    from pydantic import BaseModel, ConfigDict, Field, model_validator

    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from reproductions.guardrails_ai.ops_validators import (
        IntentToolMatchValidator,
        PromptInjectionValidator,
        SensitiveContentValidator,
        SensitiveInputValidator,
        ToolParametersValidator,
    )
    timings["imports"] = round(time.perf_counter() - started, 6)
    phase("import_done")

    started = time.perf_counter()
    class ToolCandidate(BaseModel):
        model_config = ConfigDict(extra="forbid")
        actionable: bool
        intent: str = Field(min_length=1, max_length=200)
        tool: Literal["check_disk", "get_service_status", "read_log", "restart_service", "update_config"] | None
        arguments: dict[str, Any]
        risk: Literal["low", "medium", "high", "critical"]
        reason: str = Field(min_length=1, max_length=1000)

        @model_validator(mode="after")
        def require_tool_for_action(self) -> "ToolCandidate":
            if self.actionable and self.tool is None:
                raise ValueError("actionable=true 时必须给出白名单工具")
            if not self.actionable and self.tool is not None:
                raise ValueError("actionable=false 时 tool 必须为 null")
            return self

    timings["schema_definition"] = round(time.perf_counter() - started, 6)
    phase("guard_init_start")
    started = time.perf_counter()
    settings.disable_tracing = True
    guard = Guard.for_pydantic(output_class=ToolCandidate, name="ops-tool-candidate")
    # configure重新读取RC；显式参数使关闭metrics的意图不被RC覆盖。
    guard.configure(allow_metrics_collection=False)
    guard.use(
        SensitiveContentValidator(on_fail="refrain"),
        ToolParametersValidator(on_fail="refrain"),
        IntentToolMatchValidator(on_fail="refrain"),
        on="output",
    )
    input_guard = Guard.for_string(
        validators=[
            PromptInjectionValidator(on_fail="refrain"),
            SensitiveInputValidator(on_fail="refrain"),
        ],
        name="ops-request-input",
    )
    input_guard.configure(allow_metrics_collection=False)
    settings.rc.enable_metrics = False
    timings["guard_initialization"] = round(time.perf_counter() - started, 6)
    phase("guard_init_done")
    return guard, input_guard, ToolCandidate, timings


def _failure(error: str, timings: dict[str, float]) -> dict[str, Any]:
    return {
        "validation_passed": False,
        "validated_output": None,
        "error": error,
        "timings_seconds": timings,
    }


def _failure_reason(outcome: Any, fallback: str) -> str:
    summaries = getattr(outcome, "validation_summaries", []) or []
    reasons = [
        summary.failure_reason for summary in summaries
        if summary.validator_status == "fail" and isinstance(summary.failure_reason, str)
    ]
    return "；".join(reasons)[:500] if reasons else fallback


def validate_input(user_text: str) -> dict[str, Any]:
    """先验证原始请求，调用方必须在发送给 Ollama 前执行。"""
    reused = build_guard.cache_info().currsize > 0
    _, input_guard, _, initial = build_guard()
    timings = {name: 0.0 if reused else value for name, value in initial.items()}
    phase("validation_start")
    started = time.perf_counter()
    outcome = input_guard.parse(user_text, num_reasks=0)
    timings["validation"] = round(time.perf_counter() - started, 6)
    phase("validation_done")
    if outcome.validation_passed is not True:
        return _failure(_failure_reason(outcome, "请求未通过输入安全校验"), timings)
    return {
        "validation_passed": True,
        "validated_output": {"accepted": True},
        "error": None,
        "timings_seconds": timings,
    }


def validate(raw_output: str, *, user_text: str | None = None) -> dict[str, Any]:
    reused = build_guard.cache_info().currsize > 0
    guard, input_guard, ToolCandidate, initial = build_guard()
    timings = {name: 0.0 if reused else value for name, value in initial.items()}
    phase("validation_start")
    started = time.perf_counter()
    if user_text is not None:
        input_outcome = input_guard.parse(user_text, num_reasks=0)
        if input_outcome.validation_passed is not True:
            timings["validation"] = round(time.perf_counter() - started, 6)
            phase("validation_done")
            return _failure(_failure_reason(input_outcome, "请求未通过输入安全校验"), timings)

    # Guard.parse 会先裁剪额外字段并转换类型；在此校验原始 JSON，确保 strict 与 model_validator 真正生效。
    try:
        parsed = json.loads(raw_output)
        if not isinstance(parsed, dict):
            raise ValueError("candidate must be an object")
        ToolCandidate.model_validate(parsed, strict=True)
    except (TypeError, ValueError):
        timings["validation"] = round(time.perf_counter() - started, 6)
        phase("validation_done")
        return _failure("原始 JSON 的字段、类型或字段关系不符合要求", timings)

    outcome = guard.parse(raw_output, metadata={"user_text": user_text}, num_reasks=0)
    timings["validation"] = round(time.perf_counter() - started, 6)
    phase("validation_done")
    return {
        "validation_passed": bool(outcome.validation_passed),
        "validated_output": outcome.validated_output if outcome.validation_passed else None,
        "error": None if outcome.validation_passed else _failure_reason(outcome, "候选未通过 Guardrails 安全验证"),
        "timings_seconds": timings,
    }


def validate_task(raw_output: str, user_text: str) -> dict[str, Any]:
    from guardrails import Guard
    from guardrails.validator_base import Validator, register_validator
    from guardrails.classes.validation.validation_result import PassResult, FailResult
    from pydantic import BaseModel, ConfigDict, Field, model_validator

    _, input_guard, _, timings = build_guard()
    from task_scope import check_task_scope
    from reproductions.guardrails_ai.ops_validators import SensitiveContentValidator, ToolParametersValidator

    class TaskResponse(BaseModel):
        model_config = ConfigDict(extra="forbid")
        status: Literal["clarify", "propose", "complete"]
        message: str = Field(min_length=1, max_length=2000)
        plan: list[str] = Field(max_length=6)
        tool: Literal["check_disk", "get_service_status", "read_log", "restart_service", "update_config"] | None
        arguments: dict[str, Any]
        risk: Literal["low", "medium", "high", "critical"]

        @model_validator(mode="after")
        def check_action(self):
            if any(not item.strip() or len(item) > 300 for item in self.plan):
                raise ValueError("计划步骤必须是简短非空文本")
            if self.status == "propose" and self.tool is None:
                raise ValueError("提议步骤必须提供工具")
            if self.status == "propose" and not self.plan:
                raise ValueError("提议步骤必须给出计划")
            if self.status != "propose" and (self.tool is not None or self.arguments):
                raise ValueError("追问和总结不能包含工具调用")
            return self

    @register_validator(name="ops/task-scope", data_type="object")
    class TaskScopeValidator(Validator):
        def _validate(self, value, metadata):
            try:
                check_task_scope(value, metadata["user_text"])
                # Reuse candidate content/parameter checks for proposed task steps.
                candidate = {"actionable": value["status"] == "propose", "tool": value["tool"],
                    "arguments": value["arguments"], "intent": value["message"], "reason": "\n".join(value["plan"])}
                for validator in (SensitiveContentValidator(), ToolParametersValidator()):
                    result = validator.validate(candidate, metadata)
                    if isinstance(result, FailResult):
                        return result
            except (ValueError, KeyError, TypeError) as exc:
                return FailResult(error_message=str(exc))
            return PassResult()

    if input_guard.parse(user_text, num_reasks=0).validation_passed is not True:
        return _failure("任务输入安全校验失败", timings)
    try:
        TaskResponse.model_validate(json.loads(raw_output), strict=True)
    except (ValueError, TypeError) as exc:
        fields = []
        if hasattr(exc, "errors"):
            fields = [".".join(map(str, item["loc"])) + ":" + item["type"] for item in exc.errors(include_input=False)]
        return _failure("任务响应结构不符合要求" + ("（" + "；".join(fields)[:300] + "）" if fields else ""), timings)
    guard = Guard.for_pydantic(output_class=TaskResponse, name="ops-task-response")
    guard.configure(allow_metrics_collection=False)
    guard.use(TaskScopeValidator(on_fail="refrain"), on="output")
    outcome = guard.parse(raw_output, metadata={"user_text": user_text}, num_reasks=0)
    return {"validation_passed": bool(outcome.validation_passed),
            "validated_output": outcome.validated_output if outcome.validation_passed else None,
            "error": None if outcome.validation_passed else _failure_reason(outcome, "任务范围校验失败"),
            "timings_seconds": timings}


def demo() -> int:
    cases = {
        "valid": '{"actionable":true,"intent":"查看磁盘","tool":"check_disk","arguments":{},"risk":"low","reason":"只读操作"}',
        "unknown_tool": '{"actionable":true,"intent":"执行命令","tool":"shell_command","arguments":{"command":"whoami"},"risk":"low","reason":"用户要求"}',
        "invalid_risk": '{"actionable":true,"intent":"查看磁盘","tool":"check_disk","arguments":{},"risk":"safe","reason":"错误等级"}',
        "malformed_json": "not-json",
    }
    results = {name: validate(value) for name, value in cases.items()}
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if results["valid"]["validation_passed"] and all(
        not results[name]["validation_passed"]
        for name in ("unknown_tool", "invalid_risk", "malformed_json")
    ) else 1


def main() -> int:
    global CALL_ID
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--input-file", type=Path)
    parser.add_argument("--call-id", default="standalone")
    parser.add_argument("--mode", choices=("output", "context", "input", "task"), default="output")
    args = parser.parse_args()
    CALL_ID = args.call_id
    phase("boot")
    if args.demo:
        return demo()
    started = time.perf_counter()
    raw = args.input_file.read_text(encoding="utf-8") if args.input_file else sys.stdin.read()
    input_seconds = round(time.perf_counter() - started, 6)
    phase("input_read_done")
    if args.mode == "input":
        result = validate_input(raw)
    elif args.mode in {"context", "task"}:
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("raw_output"), str) or not isinstance(envelope.get("user_text"), str):
                raise ValueError("invalid context envelope")
        except (ValueError, TypeError):
            result = _failure("验证上下文格式不正确", {})
        else:
            result = (validate_task(envelope["raw_output"], envelope["user_text"]) if args.mode == "task"
                      else validate(envelope["raw_output"], user_text=envelope["user_text"]))
    else:
        result = validate(raw)
    result["timings_seconds"]["input_read"] = input_seconds
    started = time.perf_counter()
    encoded = json.dumps(result, ensure_ascii=False)
    phase("output_ready")
    print(PHASE_PREFIX + json.dumps({"call_id": CALL_ID, "phase": "serialization_done", "elapsed_seconds": round(time.perf_counter() - STARTED, 6), "serialization_seconds": round(time.perf_counter() - started, 6)}), file=sys.stderr, flush=True)
    print(encoded, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
