"""Real interpreter/planner with only the external HTTP boundary replaced."""
import io
import json
import os
import unittest
from http.client import BadStatusLine, HTTPException, IncompleteRead
from unittest.mock import patch
from urllib.error import HTTPError

from natural_language_agent import NaturalLanguageInterpreter
from task_agent import TaskPlanner


ANALYSIS = '{"actionable":true,"intent":"查看磁盘","tool":"check_disk","arguments":{},"risk":"low","reason":"只读查询"}'


class DeepSeekAPITests(unittest.TestCase):
    def setUp(self):
        self.environment=patch.dict(os.environ, {"LLM_PROVIDER":"deepseek", "DEEPSEEK_API_KEY":"synthetic-api-key", "DEEPSEEK_MODEL":"deepseek-flash"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.calls=[]

    def capture(self, opener, request, data=None, timeout=None):
        self.calls.append((request, timeout))
        # The old local transport can consume its own envelope, so the first
        # failures identify wrong routing/payload rather than a missing import.
        return io.BytesIO(json.dumps({"message":{"content":ANALYSIS}, "choices":[{"message":{"role":"assistant","content":ANALYSIS}, "finish_reason":"stop"}],
            "usage":{"prompt_tokens":100,"completion_tokens":30,"total_tokens":130}}).encode())

    def test_default_analysis_routes_to_deepseek_with_json_and_fast_mode(self):
        agent=NaturalLanguageInterpreter(output_validator=json.loads)
        with patch("urllib.request.OpenerDirector.open", new=lambda opener,*args,**kwargs:self.capture(opener,*args,**kwargs)):
            result=agent.interpret("查看磁盘")
        self.assertTrue(result["actionable"], result)
        request,timeout=self.calls[0]
        self.assertEqual(request.full_url, "https://api.deepseek.com/chat/completions")
        body=json.loads(request.data)
        self.assertEqual(body["model"], "deepseek-flash")
        self.assertEqual(body["response_format"], {"type":"json_object"})
        self.assertEqual(body["thinking"], {"type":"disabled"})
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-api-key")
        self.assertNotIn("format", body)
        self.assertEqual(result["engine"], "deepseek")

    def test_task_planner_uses_same_cloud_transport_and_sends_schema_in_prompt(self):
        planner=TaskPlanner()
        with patch("urllib.request.OpenerDirector.open", new=lambda opener,*args,**kwargs:self.capture(opener,*args,**kwargs)):
            planner._ollama_client('{"user_request":"查看磁盘","observations":[]}')
        request,_=self.calls[0]
        self.assertEqual(request.full_url, "https://api.deepseek.com/chat/completions")
        body=json.loads(request.data)
        self.assertEqual(body["response_format"], {"type":"json_object"})
        self.assertIn('"required"',body["messages"][0]["content"])
        self.assertIn('"propose"',body["messages"][0]["content"])

    def test_missing_api_key_does_not_send_a_request_or_propose_a_write(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY":""}):
            agent=NaturalLanguageInterpreter(output_validator=json.loads)
            with patch("urllib.request.OpenerDirector.open", new=lambda opener,*args,**kwargs:self.capture(opener,*args,**kwargs)):
                result=agent.interpret("重启nginx服务")
        self.assertEqual(self.calls, [])
        self.assertFalse(result["actionable"])
        self.assertIn("DEEPSEEK_API_KEY", json.dumps(result,ensure_ascii=False))

    def test_authentication_failure_does_not_leak_remote_error_body(self):
        def reject(opener,request,*args,**kwargs):
            raise HTTPError(request.full_url,401,"unauthorized",{},io.BytesIO(b'private remote diagnostic synthetic-api-key'))
        agent=NaturalLanguageInterpreter(output_validator=json.loads)
        with patch("urllib.request.OpenerDirector.open", new=reject):
            result=agent.interpret("重启nginx服务")
        encoded=json.dumps(result,ensure_ascii=False)
        self.assertFalse(result["actionable"])
        self.assertIn("DeepSeek",encoded)
        self.assertNotIn("synthetic-api-key", encoded)
        self.assertNotIn("private remote",encoded)
        self.assertNotIn("启动 Ollama",encoded)

    def test_truncated_cloud_output_is_refused_without_offline_fallback(self):
        def truncated(opener,request,*args,**kwargs):
            return io.BytesIO(json.dumps({"choices":[{"message":{"content":ANALYSIS},"finish_reason":"length"}]}).encode())
        agent=NaturalLanguageInterpreter(output_validator=json.loads)
        with patch("urllib.request.OpenerDirector.open",new=truncated):
            result=agent.interpret("查看磁盘")
        self.assertFalse(result["actionable"])
        self.assertFalse(result["fallback_used"])
        self.assertIn("截断", " ".join(result["reasons"]))

    def test_rate_limit_credit_and_server_failures_never_propose_writes(self):
        for status,description in ((402,"余额"),(429,"限流"),(503,"暂不可用")):
            with self.subTest(status=status):
                def reject(opener,request,*args,**kwargs):
                    raise HTTPError(request.full_url,status,"error",{},io.BytesIO(b'synthetic-api-key'))
                agent=NaturalLanguageInterpreter(output_validator=json.loads)
                with patch("urllib.request.OpenerDirector.open",new=reject):
                    result=agent.interpret("重启nginx")
                self.assertFalse(result["actionable"])
                self.assertIn(description, " ".join(result["reasons"]))
                self.assertNotIn("synthetic-api-key",json.dumps(result))

    def test_bad_empty_refused_and_oversized_responses_fail_closed(self):
        values=[b'not-json',b'{"choices":[]}',
                json.dumps({"choices":[{"message":{"content":""},"finish_reason":"stop"}]}).encode(),
                json.dumps({"choices":[{"message":{"content":ANALYSIS,"refusal":"blocked"},"finish_reason":"stop"}]}).encode(),
                b' '*(1024*1024+1)]
        for response in values:
            with self.subTest(size=len(response)):
                def invalid(opener,request,*args,**kwargs):return io.BytesIO(response)
                agent=NaturalLanguageInterpreter(output_validator=json.loads)
                with patch("urllib.request.OpenerDirector.open",new=invalid):result=agent.interpret("查看磁盘")
                self.assertFalse(result["actionable"])
                self.assertFalse(result["fallback_used"])

    def test_cloud_status_contains_provider_but_not_secret(self):
        import tempfile
        from pathlib import Path
        from local_app import LocalSafetyApp
        with tempfile.TemporaryDirectory() as directory:
            status=LocalSafetyApp(Path(directory)).status()
        self.assertEqual(status["natural_language"]["provider"],"deepseek")
        self.assertTrue(status["natural_language"]["api_key_configured"])
        self.assertNotIn("synthetic-api-key",json.dumps(status))

    def test_model_settings_reject_nonofficial_and_credential_bearing_addresses(self):
        from model_client import ModelSettings,ModelUnavailableError
        for base in ("http://api.deepseek.com","https://evil.example/v1","https://api.deepseek.com@evil.example",
                     "https://synthetic-api-key@api.deepseek.com","https://api.deepseek.com?key=synthetic-api-key"):
            with self.subTest(base=base):
                with self.assertRaises(ModelUnavailableError) as raised:
                    ModelSettings.load(environ={"DEEPSEEK_BASE_URL":base})
                self.assertNotIn("synthetic-api-key",str(raised.exception))

    def test_environment_overrides_env_file_without_expanding_secret_text(self):
        import tempfile
        from pathlib import Path
        from model_client import ModelSettings
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/".env"
            path.write_text('DEEPSEEK_API_KEY="file-secret"\nDEEPSEEK_MODEL=deepseek-flash\n',encoding="utf-8")
            settings=ModelSettings.load(env_file=path,environ={"DEEPSEEK_API_KEY":"environment-secret"})
            self.assertEqual(settings.api_key,"environment-secret")
            self.assertEqual(settings.model,"deepseek-flash")
            self.assertNotIn("environment-secret",repr(settings))

    def test_api_redirect_is_not_followed(self):
        from model_client import NoModelRedirect
        from urllib.request import Request
        redirected=NoModelRedirect().redirect_request(Request("https://api.deepseek.com/chat/completions",headers={"Authorization":"Bearer synthetic-api-key"}),
            None,302,"redirect",{},"https://evil.example")
        self.assertIsNone(redirected)

    def test_protocol_failures_are_redacted_and_never_enable_read_only_fallback(self):
        for failure in (BadStatusLine("synthetic-api-key"),IncompleteRead(b"synthetic-api-key",100)):
            with self.subTest(kind=type(failure).__name__):
                def broken(opener,request,*args,**kwargs):raise failure
                agent=NaturalLanguageInterpreter(output_validator=json.loads)
                try:
                    with patch("urllib.request.OpenerDirector.open",new=broken):result=agent.interpret("查看磁盘")
                except HTTPException:
                    self.fail("An untrusted protocol error escaped the model boundary")
                self.assertFalse(result["actionable"])
                self.assertFalse(result["fallback_used"])
                self.assertNotIn("synthetic-api-key",json.dumps(result))


if __name__ == "__main__":
    unittest.main()
