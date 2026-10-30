"""通过独立虚拟环境调用 Guardrails AI，避免与 NeMo 依赖冲突。"""
from __future__ import annotations

import json
import math
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_PYTHON = (
    ROOT / "reproductions" / "guardrails_ai" / ".venv"
    / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
)
VALIDATOR_SCRIPT = (
    ROOT / "reproductions" / "guardrails_ai" / "validate_output.py"
)
PHASE_PREFIX = "GUARDRAILS_PHASE "


class ValidatorCallError(ValueError):
    """保持失败关闭接口，同时提供不含原始模型文本的诊断数据。"""

    def __init__(self, message: str, metrics: dict[str, Any]) -> None:
        super().__init__(message)
        self.metrics = metrics


class GuardrailsAIOutputValidator:
    def __init__(
        self,
        python_path: Path | str | None = None,
        *,
        script_path: Path | str = VALIDATOR_SCRIPT,
        timeout_seconds: float = 20,
        cleanup_timeout_seconds: float = 2,
    ) -> None:
        configured = os.environ.get("GUARDRAILS_AI_PYTHON")
        self.python_path = Path(python_path or configured or DEFAULT_PYTHON)
        self.script_path = Path(script_path)
        for name, value in (("timeout_seconds", timeout_seconds), ("cleanup_timeout_seconds", cleanup_timeout_seconds)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name}必须是有限的正数")
        self.timeout_seconds = float(timeout_seconds)
        self.cleanup_timeout_seconds = float(cleanup_timeout_seconds)

    def validate(self, raw_output: str) -> dict[str, Any]:
        validated, _ = self.validate_with_metrics(raw_output)
        return validated

    def validate_input(self, user_text: str) -> None:
        """在把用户请求发送给模型前运行 Guardrails 输入验证。"""
        validated, _ = self.validate_with_metrics(user_text, mode="input")
        if validated.get("accepted") is not True:
            raise ValueError("Guardrails AI 未确认输入安全")

    def validate_with_context(self, raw_output: str, user_text: str) -> dict[str, Any]:
        """在同一个隔离进程中校验用户输入和模型候选。"""
        if not isinstance(raw_output, str) or not isinstance(user_text, str):
            raise ValueError("验证上下文必须是文本")
        envelope = json.dumps(
            {"raw_output": raw_output, "user_text": user_text}, ensure_ascii=False
        )
        validated, _ = self.validate_with_metrics(envelope, mode="context")
        return validated

    def validate_task_with_context(self, raw_output: str, user_text: str) -> dict[str, Any]:
        envelope = json.dumps({"raw_output": raw_output, "user_text": user_text}, ensure_ascii=False)
        validated, _ = self.validate_with_metrics(envelope, mode="task")
        return validated

    @staticmethod
    def _collect_phases(stderr: str | bytes, metrics: dict[str, Any]) -> None:
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        phases = []
        for line in stderr.splitlines():
            if not line.startswith(PHASE_PREFIX):
                continue
            try:
                event = json.loads(line[len(PHASE_PREFIX):])
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("call_id") == metrics["call_id"] and isinstance(event.get("phase"), str):
                phases.append(event)
        metrics["child_phases"] = phases
        metrics["last_child_phase"] = phases[-1]["phase"] if phases else None

    def _cleanup(self, process: subprocess.Popen, metrics: dict[str, Any]) -> None:
        started = time.perf_counter()
        try:
            if process.poll() is None:
                process.kill()
            _, stderr = process.communicate(timeout=self.cleanup_timeout_seconds)
            self._collect_phases(stderr or "", metrics)
            metrics["cleanup_completed"] = True
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            metrics["cleanup_completed"] = False
            metrics["cleanup_error_type"] = type(exc).__name__
        finally:
            metrics["cleanup_seconds"] = round(time.perf_counter() - started, 6)
            metrics["child_returncode"] = process.returncode

    def validate_with_metrics(self, raw_output: str, *, mode: str = "output") -> tuple[dict[str, Any], dict[str, Any]]:
        if mode not in {"output", "context", "input", "task"}:
            raise ValueError("未知验证模式")
        started = time.perf_counter()
        metrics: dict[str, Any] = {"call_id": uuid.uuid4().hex, "timeout_seconds": self.timeout_seconds, "last_child_phase": None}
        process = None
        input_path = None
        stage = "input"
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            if not isinstance(raw_output, str):
                raise ValueError("模型输出必须是字符串")
            metrics["input_bytes"] = len(raw_output.encode("utf-8"))
            stage = "environment"
            if not self.python_path.is_file() or not self.script_path.is_file():
                raise ValueError("Guardrails AI 独立验证环境不存在，安全失败关闭")
            stage = "input_file"
            prepared = time.perf_counter()
            # 私有临时文件避免Windows同步stdin写入阻塞，finally清理。
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="guardrails-input-", suffix=".json", delete=False) as handle:
                input_path = Path(handle.name)
                handle.write(raw_output)
            metrics["input_file_seconds"] = round(time.perf_counter() - prepared, 6)
            stage = "spawn"
            spawned = time.perf_counter()
            child_environment = os.environ.copy()
            child_environment["PYTHONIOENCODING"] = "utf-8"
            command = [str(self.python_path), "-B", "-u", str(self.script_path), "--input-file", str(input_path), "--call-id", metrics["call_id"]]
            if mode != "output":
                command.extend(("--mode", mode))
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment,
                # 在父线程严格解码，避免Windows管道读取线程吞掉解码异常。
                creationflags=creationflags,
            )
            metrics["spawn_seconds"] = round(time.perf_counter() - spawned, 6)
            metrics["child_pid"] = process.pid
            remaining = self.timeout_seconds - (time.perf_counter() - started)
            if remaining <= 0:
                stage = "startup_timeout"
                raise subprocess.TimeoutExpired(process.args, self.timeout_seconds)
            stage = "communicate"
            waited = time.perf_counter()
            stdout, stderr = process.communicate(timeout=remaining)
            metrics["communicate_seconds"] = round(time.perf_counter() - waited, 6)
            self._collect_phases(stderr or "", metrics)
            metrics["child_returncode"] = process.returncode
            if time.perf_counter() - started > self.timeout_seconds:
                stage = "deadline_timeout"
                raise subprocess.TimeoutExpired(process.args, self.timeout_seconds)
            stage = "child_exit"
            if process.returncode != 0:
                diagnostic = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr or ""
                detail = "\n".join(line for line in diagnostic.splitlines() if not line.startswith(PHASE_PREFIX))
                raise ValueError("Guardrails AI 验证器异常：" + (detail[:1000].strip() or f"exit={process.returncode}"))
            stage = "decode_response"
            decoded = time.perf_counter()
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8")
            if not isinstance(stdout, str):
                raise ValueError("Guardrails AI 验证器未返回有效文本")
            result = json.loads(stdout)
            if not isinstance(result, dict):
                raise ValueError("Guardrails AI 验证器结果必须是对象")
            metrics["decode_seconds"] = round(time.perf_counter() - decoded, 6)
            if isinstance(result.get("timings_seconds"), dict):
                metrics["child_timings_seconds"] = result["timings_seconds"]
            stage = "validation_result"
            if result.get("validation_passed") is not True:
                raise ValueError("Guardrails AI 拒绝模型结构化输出：" + str(result.get("error") or "字段、枚举或结构不符合要求")[:1000])
            validated = result.get("validated_output")
            if not isinstance(validated, dict):
                raise ValueError("Guardrails AI 未返回结构化对象")
            if time.perf_counter() - started > self.timeout_seconds:
                stage = "deadline_timeout"
                raise subprocess.TimeoutExpired(process.args, self.timeout_seconds)
            metrics["status"] = "passed"
            return validated, metrics
        except (OSError, subprocess.TimeoutExpired) as exc:
            metrics.update(status="timeout" if isinstance(exc, subprocess.TimeoutExpired) else "error", failure_stage=stage, error_type=type(exc).__name__)
            if process is not None:
                self._cleanup(process, metrics)
            if isinstance(exc, subprocess.TimeoutExpired):
                spent = time.perf_counter() - started
                message = f"Guardrails AI 验证器调用超时：预算{self.timeout_seconds:g}秒，已耗时{spent:.3f}秒，最后阶段{metrics['last_child_phase'] or stage}；安全失败关闭"
            else:
                message = f"Guardrails AI 验证器调用失败：{exc}"
            raise ValidatorCallError(message, metrics) from exc
        except ValueError as exc:
            metrics.update(status="rejected" if stage == "validation_result" else "error", failure_stage=stage, error_type=type(exc).__name__)
            if process is not None and process.poll() is None:
                self._cleanup(process, metrics)
            raise ValidatorCallError(f"Guardrails AI 验证失败：{exc}", metrics) from exc
        finally:
            cleanup_error = None
            if input_path is not None:
                try:
                    input_path.unlink(missing_ok=True)
                except OSError as exc:
                    metrics["input_cleanup_error_type"] = type(exc).__name__
                    if metrics.get("status") == "passed":
                        metrics.update(status="error", failure_stage="input_cleanup")
                        cleanup_error = exc
            metrics["total_seconds"] = round(time.perf_counter() - started, 6)
            if cleanup_error is not None:
                raise ValidatorCallError("Guardrails AI 临时输入清理失败，安全失败关闭", metrics) from cleanup_error
