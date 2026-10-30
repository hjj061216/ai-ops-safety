import json
import tempfile
import threading
import unittest
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from unittest.mock import Mock

from local_app import LocalSafetyApp, SafetyConsoleHandler


class AuthenticatedAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = LocalSafetyApp(Path(self.temp.name))
        self.password = "synthetic-test-password-2026"
        for username, role in (("alice", "operator"), ("bob", "approver"), ("carol", "admin"), ("dana", "viewer"), ("erin", "operator")):
            self.app.auth.add_user(username, self.password, role)
        class Handler(SafetyConsoleHandler):
            def log_message(self, *args):
                pass
        Handler.app = self.app
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.app.tasks.stop_for_owner("alice")
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.temp.cleanup()

    def request(self, path, body=None, session=None, headers=None, timeout=8):
        fields = {"Content-Type": "application/json", **(headers or {})}
        if session:
            fields.update(Cookie=session["cookie"], **{"X-CSRF-Token": session["csrf"]})
        request = Request(self.url + path, data=json.dumps(body).encode() if body is not None else None, headers=fields)
        try:
            response = urlopen(request, timeout=timeout)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.load(response), response.headers

    def login(self, username):
        code, result, headers = self.request("/api/login", {"username": username, "password": self.password})
        self.assertEqual(code, 200)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        return {"cookie": headers["Set-Cookie"].split(";")[0], "csrf": result["data"]["csrf"]}

    def prepare(self, session, tool="restart_service", arguments=None):
        code, result, _ = self.request("/api/candidates/manual", {"tool": tool, "arguments": arguments or {"name": "nginx"}}, session)
        self.assertEqual(code, 200)
        return result["data"]

    def test_login_required_wrong_password_and_no_plaintext_storage(self):
        self.assertEqual(self.request("/api/status")[0], 401)
        self.assertEqual(self.request("/api/execute", {})[0], 401)
        self.assertEqual(self.request("/api/login", {"username": "alice", "password": "wrong"})[0], 401)
        self.assertNotIn(self.password, self.app.auth.path.read_text())

    def test_two_tabs_share_cookie_jar_but_not_identity_or_logout(self):
        browser = build_opener(HTTPCookieProcessor(CookieJar()))
        first, second, fresh = "a" * 32, "b" * 32, "c" * 32
        def tab_request(tab, path, body=None, csrf=None):
            headers = {"Content-Type": "application/json", "X-Console-Tab": tab}
            if csrf:
                headers["X-CSRF-Token"] = csrf
            req = Request(self.url + path, headers=headers,
                data=json.dumps(body).encode() if body is not None else None)
            try:
                response = browser.open(req, timeout=8)
            except HTTPError as error:
                response = error
            with response:
                return response.status, json.load(response)

        _, alice = tab_request(first, "/api/login", {"username": "alice", "password": self.password})
        self.assertFalse(tab_request(second, "/api/session")[1]["data"]["authenticated"])
        _, bob = tab_request(second, "/api/login", {"username": "bob", "password": self.password})
        self.assertEqual(tab_request(first, "/api/session")[1]["data"]["username"], "alice")
        self.assertEqual(tab_request(second, "/api/session")[1]["data"]["username"], "bob")
        self.assertEqual(tab_request(fresh, "/api/status")[0], 401)
        self.assertEqual(tab_request(first, "/api/candidates/manual", {"tool": "check_disk", "arguments": {}}, bob["data"]["csrf"])[0], 403)
        _, candidate = tab_request(first, "/api/candidates/manual", {"tool": "restart_service", "arguments": {"name": "nginx"}}, alice["data"]["csrf"])
        call = {"candidate_id": candidate["data"]["candidate_id"], "reason": "independent approval test"}
        _, requested = tab_request(first, "/api/approvals/request", call, alice["data"]["csrf"])
        approval = {"request_id": requested["data"]["request_id"]}
        self.assertEqual(tab_request(first, "/api/approvals/approve", approval, alice["data"]["csrf"])[0], 403)
        self.assertEqual(tab_request(second, "/api/approvals/approve", approval, bob["data"]["csrf"])[0], 200)
        self.assertEqual(tab_request(second, "/api/logout", {}, bob["data"]["csrf"])[0], 200)
        self.assertFalse(tab_request(second, "/api/session")[1]["data"]["authenticated"])
        self.assertEqual(tab_request(first, "/api/session")[1]["data"]["username"], "alice")

    def test_tab_does_not_inherit_legacy_cookie_and_rejects_invalid_selector(self):
        legacy = self.login("alice")
        _, session, _ = self.request("/api/session", session=legacy, headers={"X-Console-Tab": "c" * 32})
        self.assertFalse(session["data"]["authenticated"])
        for tab in ("", "../ops_session", "a" * 33, "A" * 32):
            self.assertEqual(self.request("/api/session", session=legacy, headers={"X-Console-Tab": tab})[0], 403)

    def test_identity_forgery_csrf_and_cross_origin_are_rejected(self):
        alice = self.login("alice")
        self.assertEqual(self.request("/api/candidates/manual", {"tool":"check_disk","arguments":{},"role":"admin"}, alice)[0], 403)
        missing = {"cookie": alice["cookie"], "csrf": "wrong"}
        self.assertEqual(self.request("/api/candidates/manual", {"tool":"check_disk","arguments":{}}, missing)[0], 403)
        self.assertEqual(self.request("/api/login", {"username":"alice","password":self.password}, headers={"Origin":"https://example.invalid"})[0], 403)

    def test_candidate_ownership_and_independent_approval(self):
        alice, bob, erin = self.login("alice"), self.login("bob"), self.login("erin")
        candidate = self.prepare(alice)
        call = {"candidate_id":candidate["candidate_id"]}
        self.assertEqual(self.request("/api/check", call, erin)[0], 403)
        code, requested, _ = self.request("/api/approvals/request", {**call,"reason":"test"}, alice)
        self.assertEqual(code, 200)
        request_id = requested["data"]["request_id"]
        self.assertEqual(requested["data"]["requester"], "alice")
        self.assertEqual(self.request("/api/approvals/approve", {"request_id":request_id}, alice)[0], 403)
        code, approved, _ = self.request("/api/approvals/approve", {"request_id":request_id}, bob)
        self.assertEqual(code, 200)
        self.assertNotIn("approval_token", approved["data"])
        self.assertEqual(self.request("/api/approvals/grant", {"request_id":request_id}, bob)[0], 403)
        _, grant, _ = self.request("/api/approvals/grant", {"request_id":request_id}, alice)
        call.update(request_id=request_id, approval_token=grant["data"]["approval_token"])
        code, execution, _ = self.request("/api/execute", call, alice)
        self.assertEqual(code, 200)
        operation = execution["data"]["operation"]["operation_id"]
        self.assertEqual(self.request("/api/execute", call, alice)[0], 400)
        self.assertEqual(self.request("/api/rollback", {"operation_id":operation}, erin)[0], 403)
        self.assertEqual(self.request("/api/rollback", {"operation_id":operation}, self.login("dana"))[0], 403)
        self.assertEqual(self.request("/api/rollback", {"operation_id":operation}, alice)[0], 200)

    def test_admin_cannot_self_approve_and_config_role_cannot_be_forged(self):
        admin = self.login("carol")
        candidate = self.prepare(admin)
        _, requested, _ = self.request("/api/approvals/request", {"candidate_id":candidate["candidate_id"],"reason":"test"}, admin)
        self.assertEqual(self.request("/api/approvals/approve", {"request_id":requested["data"]["request_id"]}, admin)[0], 403)
        alice = self.login("alice")
        config = self.prepare(alice, "update_config", {"path":"/etc/myapp/test.conf","content":"mode=safe"})
        _, checked, _ = self.request("/api/check", {"candidate_id":config["candidate_id"]}, alice)
        self.assertEqual(checked["data"]["decision"], "deny")

    def test_task_ownership_logout_and_account_disable(self):
        alice, erin = self.login("alice"), self.login("erin")
        self.app.tasks.planner.suggest = Mock(return_value={"status":"clarify","message":"哪个服务？","plan":["确认目标"],"tool":None,"arguments":{},"risk":"low"})
        _, result, _ = self.request("/api/tasks/start", {"request":"排查服务异常"}, alice)
        task_id = result["data"]["task_id"]
        _, owned, _ = self.request("/api/tasks", session=alice)
        self.assertEqual(owned["data"]["tasks"][0]["task_id"], task_id)
        _, foreign, _ = self.request("/api/tasks", session=erin)
        self.assertEqual(foreign["data"]["tasks"], [])
        self.assertEqual(self.request("/api/tasks/state?task_id="+task_id, session=erin)[0], 403)
        self.assertEqual(self.request("/api/tasks/stop", {"task_id":task_id}, erin)[0], 403)
        self.assertEqual(self.request("/api/logout", {}, alice)[0], 200)
        self.assertEqual(self.request("/api/status", session=alice)[0], 401)
        users = self.app.auth._users(); users["erin"]["enabled"] = False
        self.app.auth.path.write_text(json.dumps(users))
        self.assertEqual(self.request("/api/status", session=erin)[0], 401)


if __name__ == "__main__":
    unittest.main()
