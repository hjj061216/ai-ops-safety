"""Actual authenticated HTTP + cloud transport + real Guardrails, synthetic API responses."""
import io
import json
import os
import time
import unittest
from http.client import BadStatusLine
from unittest.mock import patch
from urllib.request import OpenerDirector

import test_authenticated_api as authenticated_helpers


def proposal(tool=None, arguments=None, status="propose"):
    return {"status":status,"message":"根据实际记录继续处理", "plan":["核对本步结果"] if tool else [],
            "tool":tool,"arguments":arguments or {},"risk":"high" if tool=="restart_service" else "low"}


class DeepSeekTaskTests(unittest.TestCase):
    MODEL_ENV = {"LLM_PROVIDER":"deepseek","DEEPSEEK_API_KEY":"synthetic-task-key"}
    MODEL_URL_PREFIX = 'https://api.deepseek.com/'

    def setUp(self):
        self.environment=patch.dict(os.environ,self.MODEL_ENV)
        self.environment.start()
        self.fixture=authenticated_helpers.AuthenticatedAPITests();self.fixture.setUp()
        self.owner=self.fixture.login("alice");self.reviewer=self.fixture.login("bob")
        self.responses=[];self.cloud_requests=[]
        self.finish_reason="stop"
        self.transport_error=None
        original=OpenerDirector.open
        def network(opener,request,*args,**kwargs):
            url=request.full_url if hasattr(request,"full_url") else str(request)
            if not url.startswith(self.MODEL_URL_PREFIX):
                return original(opener,request,*args,**kwargs)
            self.cloud_requests.append(json.loads(request.data))
            if self.transport_error:raise self.transport_error
            if not self.responses:raise AssertionError("Unexpected cloud call")
            content=json.dumps(self.responses.pop(0),ensure_ascii=False)
            return io.BytesIO(json.dumps({"model":self.fixture.app.interpreter.model, "choices":[{"index":0,"message":{"role":"assistant","content":content},"finish_reason":self.finish_reason}],
                "usage":{"prompt_tokens":100,"completion_tokens":30,"total_tokens":130}}).encode())
        self.transport=patch("urllib.request.OpenerDirector.open",new=network)
        self.transport.start()

    def tearDown(self):
        self.fixture.app.tasks.stop_for_owner("alice")
        for task in self.fixture.app.tasks.tasks.values():
            if task["worker"]:task["worker"].join(60)
        self.transport.stop();self.fixture.tearDown();self.environment.stop()

    def api(self,path,body=None,session=None):
        code,envelope,_=self.fixture.request(path,body,session or self.owner,timeout=90)
        self.assertEqual(code,200,envelope)
        return envelope["data"]

    def wait(self,task_id,expected):
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            state=self.api("/api/tasks/state?task_id="+task_id)
            if state["runner_state"] in expected:return state
            time.sleep(.05)
        self.fail("Task timeout: "+str(state))

    def test_cloud_json_queries_execute_and_complete_with_actual_evidence(self):
        self.responses=[proposal("get_service_status",{"name":"nginx"}),
            proposal("read_log",{"path":"/var/log/nginx/error.log","lines":2}),proposal("check_disk"),proposal(status="complete")]
        task=self.api("/api/tasks/start",{"request":"先检查nginx状态，再查看最近2行错误日志，再检查磁盘，不要重启","autonomy":"read_only"})
        self.api("/api/tasks/run",{"task_id":task["task_id"]})
        state=self.wait(task["task_id"],{"complete","blocked"})
        self.assertEqual(state["runner_state"],"complete",state)
        self.assertEqual([item["tool"] for item in state["observations"]],["get_service_status","read_log","check_disk"])
        self.assertEqual(self.fixture.app.approvals.list_public_records(),[])
        for body in self.cloud_requests:
            self.assertEqual(body["response_format"],{"type":"json_object"})
            self.assertNotIn("format",body)
        last=json.loads(self.cloud_requests[-1]["messages"][-1]["content"])
        self.assertEqual(len(last["observations"]),3)

    def test_cloud_cannot_substitute_another_service_even_with_valid_json(self):
        self.responses=[proposal("restart_service",{"name":"payment"})]*2
        task=self.api("/api/tasks/start",{"request":"重启nginx服务","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"blocked",task)
        self.assertEqual(self.fixture.app.candidates.counts()["active"],0)
        self.assertEqual(self.fixture.app.executor.list_operations(),[])
        self.assertEqual(len(self.cloud_requests),2)

    def test_explicit_nginx_recovers_from_redundant_service_question(self):
        question=proposal(status="clarify")
        question["message"]="请补充需要重启的服务名称。"
        self.responses=[question,proposal("restart_service",{"name":"nginx"})]
        task=self.api("/api/tasks/start",{"request":"重启nginx服务","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"propose",task)
        self.assertEqual(task["arguments"],{"name":"nginx"})
        self.assertEqual(task["effective_risk"],"high")
        checked=self.api("/api/check",{"candidate_id":task["candidate_id"]})
        self.assertEqual(checked["decision"],"require_human")
        self.assertEqual(self.fixture.app.executor.list_operations(),[])
        corrected=json.loads(self.cloud_requests[-1]["messages"][-1]["content"])
        self.assertEqual(corrected["task_scope"]["services"],["nginx"])
        self.assertIn("validation_feedback",corrected)

    def test_repeated_unnecessary_questions_stop_without_asking_user_again(self):
        question=proposal(status="clarify")
        question["message"]="请补充服务名称"
        self.responses=[question,question]
        task=self.api("/api/tasks/start",{"request":"重启nginx服务","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"blocked",task)
        self.assertEqual(self.fixture.app.candidates.counts()["active"],0)
        self.assertEqual(self.fixture.app.executor.list_operations(),[])
        self.assertEqual(len(self.cloud_requests),2)

    def test_real_missing_service_question_ends_after_user_supplies_nginx(self):
        task=self.api("/api/tasks/start",{"request":"重启服务","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"clarify",task)
        self.assertEqual(self.cloud_requests,[])
        self.responses=[proposal("restart_service",{"name":"nginx"})]
        task=self.api("/api/tasks/reply",{"task_id":task["task_id"],"answer":"nginx"})
        self.assertEqual(task["task_status"],"propose",task)
        self.assertEqual(task["arguments"],{"name":"nginx"})
        self.assertEqual(self.fixture.app.executor.list_operations(),[])

    def test_truncated_json_never_creates_a_candidate(self):
        self.finish_reason="length"
        self.responses=[proposal("check_disk")]
        task=self.api("/api/tasks/start",{"request":"查看磁盘","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"blocked",task)
        self.assertIn("截断",task["message"])
        self.assertEqual(self.fixture.app.candidates.counts()["active"],0)

    def test_protocol_failure_is_a_safe_task_rejection_without_candidates(self):
        self.transport_error=BadStatusLine("synthetic-task-key")
        task=self.api("/api/tasks/start",{"request":"查看磁盘","autonomy":"read_only"})
        self.assertEqual(task["task_status"],"blocked",task)
        self.assertNotIn("synthetic-task-key",json.dumps(task))
        self.assertEqual(self.fixture.app.candidates.counts()["active"],0)
        self.assertEqual(self.fixture.app.executor.list_operations(),[])

    def test_cloud_change_pauses_for_independent_approval_and_verifies_after_resume(self):
        self.responses=[proposal("get_service_status",{"name":"nginx"}),proposal("restart_service",{"name":"nginx"}),
            proposal("get_service_status",{"name":"nginx"}),proposal(status="complete")]
        task=self.api("/api/tasks/start",{"request":"先检查nginx状态，然后重启nginx，再检查状态","autonomy":"read_only"})
        self.api("/api/tasks/run",{"task_id":task["task_id"]})
        waiting=self.wait(task["task_id"],{"waiting_approval","blocked"})
        self.assertEqual(waiting["runner_state"],"waiting_approval",waiting)
        self.assertEqual(len(self.fixture.app.executor.list_operations()),1)
        self.api("/api/approvals/approve",{"request_id":waiting["approval_request_id"]},self.reviewer)
        state=self.wait(task["task_id"],{"complete","blocked"})
        self.assertEqual(state["runner_state"],"complete",state)
        self.assertEqual([item["tool"] for item in state["observations"]],["get_service_status","restart_service","get_service_status"])
        self.assertEqual(state["observations"][-1]["facts"]["status"],"running")


if __name__=="__main__":unittest.main()
