import json
import re
import tempfile
import threading
import unittest
from http.server import HTTPServer
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from local_app import LocalSafetyApp, SafetyConsoleHandler


class PageStructure(HTMLParser):
    """Inspect served control ownership without pinning quote/order/accordion markup."""
    def __init__(self, html):
        super().__init__()
        self.nodes={}; self.stack=[]; self.duplicates=[]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node={"tag":tag,"attrs":dict(attrs),"ancestors":list(self.stack)}
        identity=node["attrs"].get("id")
        if identity:
            if identity in self.nodes: self.duplicates.append(identity)
            self.nodes[identity]=node
        if tag not in {"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack)-1,-1,-1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def inside(self, identity, ancestor_id):
        return any(node["attrs"].get("id")==ancestor_id for node in self.nodes[identity]["ancestors"])


class LocalHTTPBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.app = LocalSafetyApp(Path(self.directory.name) / "runtime")
        self.app.interpreter._output_validator = json.loads
        self.app.interpreter._ollama_client = lambda _: json.dumps({"actionable": True, "intent": "查看状态", "tool": "get_service_status", "arguments": {"name": "nginx"}, "risk": "high", "reason": "test risk"})
        class Handler(SafetyConsoleHandler):
            # Legacy in-process fixtures exercise the old protocol, not the public server.
            auth_required = False
            def log_message(self, *args):
                pass
        Handler.app = self.app
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def post(self, route, data):
        request = Request(self.base + route, data=json.dumps(data).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_http_rejects_legacy_execution_and_client_risk_override(self):
        status, envelope = self.post("/api/execute", {"tool": "get_service_status", "arguments": {"name": "nginx"}})
        self.assertEqual(status, 400)
        self.assertFalse(envelope["ok"])
        _, interpreted = self.post("/api/interpret", {"request": "查看 nginx 服务状态"})
        candidate_id = interpreted["data"]["candidate_id"]
        status, envelope = self.post("/api/check", {"candidate_id": candidate_id, "role": "viewer", "llm_risk": "low"})
        self.assertEqual(status, 400)
        self.assertFalse(envelope["ok"])
        _, checked = self.post("/api/check", {"candidate_id": candidate_id, "role": "viewer"})
        self.assertEqual(checked["data"]["effective_risk"], "high")
        self.assertEqual(checked["data"]["decision"], "require_human")
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_http_manual_candidate_approval_execution_and_replay(self):
        status, prepared = self.post("/api/candidates/manual", {"tool": "get_service_status", "arguments": {"name": "nginx"}})
        self.assertEqual(status, 200)
        candidate = prepared["data"]
        self.assertEqual(candidate["effective_risk"], "medium")
        call = {"candidate_id": candidate["candidate_id"], "role": "viewer"}
        _, waiting = self.post("/api/execute", call)
        self.assertFalse(waiting["data"]["executed"])
        _, requested = self.post("/api/approvals/request", {**call, "requester": "alice", "reason": "test"})
        _, approved = self.post("/api/approvals/approve", {"request_id": requested["data"]["request_id"], "approver": "bob", "approver_role": "admin"})
        execution = {**call, "request_id": requested["data"]["request_id"], "approval_token": approved["data"]["approval_token"]}
        status, result = self.post("/api/execute", execution)
        self.assertEqual(status, 200)
        self.assertTrue(result["data"]["executed"])
        self.assertEqual(result["data"]["operation"]["result"]["name"], "nginx")
        status, result = self.post("/api/execute", execution)
        self.assertEqual(status, 400)
        self.assertFalse(result["ok"])
        self.assertEqual(len(self.app.executor.list_operations()), 1)

    def test_http_no_candidate_issued_after_validation_failure(self):
        def failed(_):
            raise ValueError("Guardrails validation failed")
        self.app.interpreter._output_validator = failed
        status, interpreted = self.post("/api/interpret", {"request": "查看 nginx 服务状态"})
        self.assertEqual(status, 200)
        self.assertEqual(interpreted["data"]["decision"], "deny")
        self.assertNotIn("candidate_id", interpreted["data"])
        self.assertEqual(self.app.candidates.counts()["active"], 0)

    def test_http_rejects_readonly_and_operator_approvers(self):
        _, prepared = self.post("/api/candidates/manual", {"tool": "get_service_status", "arguments": {"name": "nginx"}})
        call = {"candidate_id": prepared["data"]["candidate_id"], "role": "viewer"}
        _, requested = self.post("/api/approvals/request", {**call, "requester": "alice", "reason": "test"})
        approval = {"request_id": requested["data"]["request_id"], "approver": "bob"}
        for role in ("viewer", "operator"):
            with self.subTest(role=role):
                status, rejected = self.post("/api/approvals/approve", {**approval, "approver_role": role})
                self.assertEqual(status, 400)
                self.assertFalse(rejected["ok"])
                self.assertIn("当前角色无审批权限", rejected["error"])
                self.assertNotIn("approval_token", rejected)
                self.assertEqual(self.app.approvals.get_public_record(approval["request_id"])["status"], "pending")
        status, approved = self.post("/api/approvals/approve", {**approval, "approver_role": "approver"})
        self.assertEqual(status, 200)
        self.assertTrue(approved["data"]["approval_token"])
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_http_changed_parameters_are_rejected(self):
        _, interpreted = self.post("/api/interpret", {"request": "查看 nginx 服务状态"})
        status, envelope = self.post("/api/execute", {"candidate_id": interpreted["data"]["candidate_id"], "tool": "get_service_status", "arguments": {"name": "payment"}, "role": "viewer"})
        self.assertEqual(status, 400)
        self.assertFalse(envelope["ok"])
        self.assertEqual(self.app.executor.list_operations(), [])

    def test_http_task_uses_existing_candidate_and_execution_routes(self):
        from unittest.mock import Mock
        self.app.tasks.planner.suggest = Mock(side_effect=[
            {"status": "propose", "message": "查看状态", "plan": ["查看状态"], "tool": "get_service_status", "arguments": {"name": "nginx"}, "risk": "low"},
            {"status": "complete", "message": "模拟服务运行中", "plan": ["完成"], "tool": None, "arguments": {}, "risk": "low"}])
        status, envelope = self.post("/api/tasks/start", {"request": "查看 nginx 服务状态"})
        self.assertEqual(status, 200)
        candidate = envelope["data"]
        status, _ = self.post("/api/tasks/continue", {"task_id": candidate["task_id"]})
        self.assertEqual(status, 400)
        call = {"candidate_id": candidate["candidate_id"], "role": "viewer"}
        _, checked = self.post("/api/check", call)
        if checked["data"]["decision"] == "require_human":
            _, requested = self.post("/api/approvals/request", {**call, "requester": "alice", "reason": "task"})
            _, granted = self.post("/api/approvals/approve", {"request_id": requested["data"]["request_id"], "approver": "bob", "approver_role": "admin"})
            call.update(request_id=requested["data"]["request_id"], approval_token=granted["data"]["approval_token"])
        _, execution = self.post("/api/execute", call)
        self.assertTrue(execution["data"]["executed"])
        status, final = self.post("/api/tasks/continue", {"task_id": candidate["task_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(final["data"]["task_status"], "complete")
        self.assertEqual(len(self.app.executor.list_operations()), 1)

    def test_web_separates_feedback_execution_and_keeps_json_readonly(self):
        with urlopen(self.base + "/", timeout=5) as response:
            html = response.read().decode("utf-8")
        page=PageStructure(html)
        self.assertEqual(page.duplicates,[])
        for identity in ("candidateJson","feedbackDetails","executionOutput"):
            self.assertEqual(page.nodes[identity]["tag"],"pre")
            self.assertNotEqual(page.nodes[identity]["attrs"].get("contenteditable"),"true")
            self.assertTrue(page.inside(identity,"record-panel-raw"))
        self.assertIsNot(page.nodes["feedbackMessage"],page.nodes["executionStatus"])
        for identity in ("approvalPanel","rollbackControls"):
            self.assertIn("hidden",page.nodes[identity]["attrs"])
        for node in page.nodes.values():
            if node["tag"] in {"input","textarea","select"}:
                self.assertNotIn(node["attrs"].get("id"),{"risk","args"})

    def test_web_input_modes_are_buttons_and_manual_form_is_not_folded(self):
        with urlopen(self.base + "/", timeout=5) as response:
            html = response.read().decode("utf-8")
        page=PageStructure(html)
        for button,panel in (("naturalModeButton","naturalInputPanel"),("debugModeButton","manualInputPanel")):
            self.assertEqual(page.nodes[button]["tag"],"button")
            self.assertEqual(page.nodes[button]["attrs"]["aria-controls"],panel)
        for identity in ("manualTool","manualCandidateButton"):
            self.assertTrue(page.inside(identity,"view-tools"))
            self.assertFalse(any(node["tag"] in {"details","summary"} for node in page.nodes[identity]["ancestors"]))

    def test_web_automatically_checks_and_keeps_recheck_in_technical_details(self):
        with urlopen(self.base + "/", timeout=5) as response:
            html = response.read().decode("utf-8")
        page=PageStructure(html)
        self.assertTrue(page.inside("checkButton","record-panel-raw"))
        for identity in ("interpretButton","manualCandidateButton","checkButton","executeButton"):
            self.assertEqual(page.nodes[identity]["tag"],"button")

    def test_web_approval_roles_only_show_authorized_choices(self):
        with urlopen(self.base + "/", timeout=5) as response:
            html = response.read().decode("utf-8")
        approval_select = re.search(r'<select id="approverRole"[^>]*>(.*?)</select>', html, re.S)
        self.assertIsNotNone(approval_select)
        self.assertEqual(re.findall(r'<option value="([^"]+)"', approval_select.group(1)), ["admin", "approver"])
        requester_select = re.search(r'<select id="role"[^>]*>(.*?)</select>', html, re.S)
        self.assertIsNotNone(requester_select)
        self.assertEqual(re.findall(r'<option value="([^"]+)"', requester_select.group(1)), ["viewer", "operator", "admin"])
        self.assertIn('aria-describedby="approvalRoleHint"', html)
        self.assertIn('审批员不是运维操作员，申请人不能自批', html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
