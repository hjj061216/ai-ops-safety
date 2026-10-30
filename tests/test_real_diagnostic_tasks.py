"""Real probe/log execution through candidate binding and evidence-based planning."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

from auth import Principal
from local_app import LocalSafetyApp
from scripts.diagnostic_demo import create_demo_server


def action(tool=None, arguments=None, status="propose"):
    return {"status":status,"tool":tool,"arguments":arguments or {},"risk":"low",
            "message":"依据当前证据选择下一步","plan":["检查健康接口，再按证据处理"] if tool else []}


class RealDiagnosticTaskTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.server,self.config=create_demo_server(self.root / "target",scenario="disk_full",port=0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.app=LocalSafetyApp(self.root / "console",diagnostics_config=self.config)
        self.context=self.app.identity.set(Principal("alice","operator"))

    def tearDown(self):
        if hasattr(self,"app"):
            self.app.identity.reset(self.context)
        self.server.shutdown();self.server.server_close();self.thread.join(3)
        self.temp.cleanup()

    def execute(self,result):
        executed=self.app.execute({"candidate_id":result["candidate_id"]})
        self.assertTrue(executed["executed"])
        return executed["operation"]

    def test_real_results_drive_health_log_disk_sequence_and_evidence_summary(self):
        self.app.tasks.planner.suggest=Mock(side_effect=[action("get_service_status",{"name":"nginx"}),
            action("read_log",{"path":"/var/log/nginx/error.log","lines":20}),action("check_disk"),action(status="complete")])
        result=self.app.task_start({"request":"排查nginx异常，不要重启或修改配置","autonomy":"read_only"})
        operation=self.execute(result)
        self.assertEqual(operation["result"]["http_status"],503)
        state=self.app.task_state(result["task_id"])
        self.assertTrue(any(item["tool"]=="read_log" for item in state["remaining_requirements"]))
        result=self.app.task_continue({"task_id":result["task_id"]});self.execute(result)
        state=self.app.task_state(result["task_id"])
        self.assertTrue(any(item["tool"]=="check_disk" for item in state["remaining_requirements"]))
        result=self.app.task_continue({"task_id":result["task_id"]});self.execute(result)
        result=self.app.task_continue({"task_id":result["task_id"]})
        self.assertEqual(result["task_status"],"complete")
        self.assertEqual([item["tool"] for item in result["observations"]],["get_service_status","read_log","check_disk"])
        self.assertEqual(result["execution_backend"],"local_readonly")
        self.assertTrue(any("503" in text for text in result["diagnostic_assessment"]["confirmed"]))
        self.assertTrue(result["diagnostic_assessment"]["hypotheses"])
        self.assertTrue(all(item["observed_at"] and item["source"] for item in result["observations"]))
        self.assertNotIn("服务与配置操作使用本地模拟环境",result["message"])
        self.assertNotIn("body_excerpt",result["message"],"raw evidence belongs in the evidence view, not the main conclusion")

    def test_false_completion_cannot_skip_log_evidence_after_failed_probe(self):
        self.app.tasks.planner.suggest=Mock(side_effect=[action("get_service_status",{"name":"nginx"}),action(status="complete")])
        result=self.app.task_start({"request":"排查nginx故障","autonomy":"read_only"});self.execute(result)
        result=self.app.task_continue({"task_id":result["task_id"]})
        self.assertEqual(result["task_status"],"blocked")
        self.assertTrue(any(item["tool"]=="read_log" for item in result["remaining_requirements"]))

    def test_diagnostic_cannot_read_logs_before_initial_health_probe(self):
        self.app.tasks.planner.suggest=Mock(return_value=action("read_log",{"path":"/var/log/nginx/error.log","lines":20}))
        result=self.app.task_start({"request":"排查nginx异常","autonomy":"read_only"})
        self.assertEqual(result["task_status"],"blocked")
        self.assertFalse(result["actionable"])
        self.assertEqual(self.app.executor.list_operations(),[])

    def test_log_only_request_does_not_require_health_endpoint_configuration(self):
        from task_agent import _scoped_intent
        intent=_scoped_intent("查看nginx最近20行日志",{"backend":"local_readonly","services":[],
            "log_paths":["/var/log/nginx/error.log"],"tools":["read_log","check_disk"]})
        self.assertEqual(intent.unsupported,[])
        self.assertEqual(intent.required,[{"tool":"read_log","target":"/var/log/nginx/error.log"}])

    def test_readonly_mode_rejects_write_candidates_and_unconfigured_resources(self):
        for tool,args in (("restart_service",{"name":"nginx"}),("update_config",{"path":"/etc/myapp/test.conf","content":"mode=safe"}),
                          ("get_service_status",{"name":"payment"}),("read_log",{"path":"/var/log/app/private.log","lines":2})):
            with self.subTest(tool=tool),self.assertRaises(ValueError):
                self.app.prepare_manual({"tool":tool,"arguments":args})
        self.assertEqual(self.app.executor.list_operations(),[])
        self.assertEqual(self.app.status()["execution_backend"],"local_readonly")

    def test_planner_gets_only_real_authorized_tools_and_evidence_feedback(self):
        planner=self.app.tasks.planner
        planner._guardrails_validator.validate_input=Mock()
        planner._guardrails_validator.validate_task_with_context=Mock(side_effect=lambda raw,text:json.loads(raw))
        planner._ollama_client=Mock(side_effect=[json.dumps(action(status="complete")),json.dumps(action("read_log",{"path":"/var/log/nginx/error.log","lines":20}))])
        history=[{"tool":"get_service_status","target":"nginx","operation_id":"probe-1","facts":{"healthy":False,"http_status":503},"result_excerpt":"HTTP 503"}]
        result=planner.suggest("排查nginx异常，不要重启",history)
        self.assertEqual(result["tool"],"read_log")
        payload=json.loads(planner._ollama_client.call_args_list[-1].args[0])
        self.assertTrue(payload["diagnostic_assessment"]["confirmed"])
        self.assertTrue(payload["remaining_requirements"])
        self.assertNotIn("restart_service",planner._task_tools)
        self.assertIn("local_readonly",planner._system_prompt())

    def test_real_write_request_returns_unsupported_before_cloud_call(self):
        planner=self.app.tasks.planner
        planner._guardrails_validator.validate_input=Mock()
        planner._ollama_client=Mock()
        result=self.app.task_start({"request":"重启nginx服务","autonomy":"read_only"})
        self.assertEqual(result["task_status"],"unsupported")
        planner._ollama_client.assert_not_called()
