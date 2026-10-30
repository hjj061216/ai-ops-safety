"""覆盖文件传输、子进程异常、超时回收和解释器失败关闭。"""
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from guardrails_output_validator import GuardrailsAIOutputValidator, ValidatorCallError
from local_app import LocalSafetyApp

FIXTURE = Path(__file__).with_name("fixtures") / "validator_process_fixture.py"


class GuardrailsOutputValidatorTests(unittest.TestCase):
    def validator(self, **kwargs):
        return GuardrailsAIOutputValidator(python_path=sys.executable, script_path=FIXTURE, **kwargs)

    def test_valid_output_keeps_public_interface_and_cleans_input(self):
        result = self.validator().validate('{"mode":"valid"}')
        self.assertEqual(result["tool"], "check_disk")
        self.assertFalse(Path(result["arguments"]["input_path"]).exists())
        self.assertNotIn("timings_seconds", result)

    def test_metrics_record_child_phase_and_positive_wall_time(self):
        result, metrics = self.validator().validate_with_metrics('{"mode":"valid"}')
        self.assertEqual(metrics["status"], "passed")
        self.assertEqual(metrics["last_child_phase"], "input_read_done")
        self.assertEqual(metrics["input_bytes"], result["arguments"]["received_bytes"])
        self.assertGreater(metrics["total_seconds"], 0)
        self.assertEqual(metrics["child_timings_seconds"]["validation"], 0.001)

    def test_large_unicode_input_is_not_truncated(self):
        raw = json.dumps({"mode": "valid", "content": "中文数据" * 50000}, ensure_ascii=False)
        result = self.validator().validate(raw)
        self.assertEqual(result["arguments"]["received_bytes"], len(raw.encode("utf-8")))

    def test_chinese_response_round_trips_without_locale_corruption(self):
        result = self.validator().validate('{"mode":"unicode"}')
        self.assertEqual(result["intent"], "查看应用日志")
        self.assertEqual(result["reason"], "只读请求")

    def test_missing_environment_fails_closed(self):
        with self.assertRaises(ValidatorCallError) as captured:
            GuardrailsAIOutputValidator(python_path=FIXTURE.with_name("missing.exe")).validate("{}")
        self.assertEqual(captured.exception.metrics["failure_stage"], "environment")

    def test_invalid_input_type_is_value_error(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate(None)

    def test_invalid_timeout_configuration_is_rejected(self):
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validator(timeout_seconds=value)

    def test_spawn_error_is_wrapped_as_value_error(self):
        with patch("guardrails_output_validator.subprocess.Popen", side_effect=OSError("launch failed")):
            with self.assertRaises(ValidatorCallError) as captured:
                self.validator().validate("{}")
        self.assertEqual(captured.exception.metrics["failure_stage"], "spawn")

    def test_timeout_reaps_process_with_bounded_cleanup(self):
        started = time.perf_counter()
        with self.assertRaises(ValidatorCallError) as captured:
            self.validator(timeout_seconds=.4, cleanup_timeout_seconds=.7).validate('{"mode":"hang"}')
        metrics = captured.exception.metrics
        self.assertEqual(metrics["status"], "timeout")
        self.assertTrue(metrics["cleanup_completed"])
        self.assertIsNotNone(metrics["child_returncode"])
        self.assertEqual(metrics["last_child_phase"], "input_read_done")
        self.assertLess(time.perf_counter() - started, 3)
        self.assertIn("预算0.4秒", str(captured.exception))

    def test_spawn_time_consumes_the_same_deadline(self):
        process = MagicMock()
        process.pid = 123
        process.returncode = -1
        process.poll.return_value = None
        process.communicate.return_value = ("", "")
        def delayed_spawn(*args, **kwargs):
            time.sleep(.05)
            return process
        with patch("guardrails_output_validator.subprocess.Popen", side_effect=delayed_spawn):
            with self.assertRaises(ValidatorCallError) as captured:
                self.validator(timeout_seconds=.01).validate("{}")
        self.assertEqual(captured.exception.metrics["failure_stage"], "startup_timeout")
        process.kill.assert_called_once()
        process.communicate.assert_called_once_with(timeout=2)

    def test_cleanup_timeout_still_rejects(self):
        process = MagicMock()
        process.pid = 123
        process.returncode = None
        process.poll.return_value = None
        process.communicate.side_effect = subprocess.TimeoutExpired("fixture", .2)
        with patch("guardrails_output_validator.subprocess.Popen", return_value=process):
            with self.assertRaises(ValidatorCallError) as captured:
                self.validator(timeout_seconds=.2, cleanup_timeout_seconds=.1).validate("{}")
        self.assertEqual(captured.exception.metrics["status"], "timeout")
        self.assertFalse(captured.exception.metrics["cleanup_completed"])
        self.assertEqual(process.communicate.call_args_list[-1].kwargs["timeout"], .1)

    def test_deadline_expired_while_decoding_valid_response_still_rejects(self):
        process = MagicMock()
        process.args = ["fixture"]
        process.pid = 123
        process.returncode = 0
        process.poll.return_value = 0
        process.communicate.return_value = (b'{"validation_passed":true,"validated_output":{}}', b"")
        original_loads = json.loads
        def delayed_decode(value):
            time.sleep(.05)
            return original_loads(value)
        with patch("guardrails_output_validator.subprocess.Popen", return_value=process), patch("guardrails_output_validator.json.loads", side_effect=delayed_decode):
            with self.assertRaises(ValidatorCallError) as captured:
                self.validator(timeout_seconds=.03).validate("{}")
        self.assertEqual(captured.exception.metrics["status"], "timeout")
        self.assertEqual(captured.exception.metrics["failure_stage"], "deadline_timeout")

    def test_nonzero_exit_is_rejected(self):
        with self.assertRaises(ValidatorCallError) as captured:
            self.validator().validate('{"mode":"crash"}')
        self.assertEqual(captured.exception.metrics["child_returncode"], 7)
        self.assertEqual(captured.exception.metrics["failure_stage"], "child_exit")

    def test_invalid_json_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"garbage"}')

    def test_empty_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"empty"}')

    def test_list_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"list"}')

    def test_null_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"null"}')

    def test_invalid_utf8_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"invalid_utf8"}')

    def test_validation_rejection_is_not_promoted_to_success(self):
        with self.assertRaises(ValidatorCallError) as captured:
            self.validator().validate('{"mode":"rejected"}')
        self.assertEqual(captured.exception.metrics["status"], "rejected")

    def test_non_boolean_pass_flag_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"non_boolean_pass"}')

    def test_non_object_validated_output_is_rejected(self):
        with self.assertRaises(ValidatorCallError):
            self.validator().validate('{"mode":"non_object_output"}')


class ValidationFailureIntegrationTests(unittest.TestCase):
    def assert_no_side_effect(self, mode, timeout=5):
        with tempfile.TemporaryDirectory() as directory:
            app = LocalSafetyApp(Path(directory) / "runtime")
            services_before = app.executor.services_path.read_bytes()
            app.interpreter._ollama_client = lambda _: json.dumps({"mode": mode})
            app.interpreter._output_validator = GuardrailsAIOutputValidator(python_path=sys.executable, script_path=FIXTURE, timeout_seconds=timeout).validate
            result = app.interpret({"request": "查看 nginx 最近两行错误日志"})
            self.assertFalse(result["actionable"])
            self.assertEqual(result["decision"], "deny")
            self.assertEqual(result["effective_risk"], "critical")
            self.assertIsNone(result["tool"])
            self.assertNotIn("candidate_id", result)
            self.assertEqual(app.candidates.counts()["active"], 0)
            with self.assertRaises(ValueError):
                app.execute({"tool": "read_log", "arguments": {"path": "/var/log/nginx/error.log", "lines": 2}, "role": "viewer"})
            self.assertEqual(app.executor.list_operations(), [])
            self.assertEqual(app.executor.services_path.read_bytes(), services_before)
            self.assertTrue(app.verify_audit()["valid"])

    def test_timeout_does_not_create_tool_call_or_change_service(self):
        self.assert_no_side_effect("hang", timeout=.4)

    def test_process_failure_does_not_create_tool_call(self):
        self.assert_no_side_effect("crash")

    def test_bad_response_does_not_create_tool_call(self):
        self.assert_no_side_effect("list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
