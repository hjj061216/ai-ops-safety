"""Real loopback HTTP and bounded local-file diagnostic contracts."""
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from audit_log import HashChainAuditLog
from real_diagnostics import ReadOnlyDiagnosticsExecutor
from sandbox_executor import SandboxExecutionError
from structured_tools import StructuredToolGateway


class Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        if self.path == "/slowheaders":
            try:
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                for _ in range(10):
                    time.sleep(0.35)
                    self.connection.sendall(b"x")
                self.connection.sendall(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return
        if self.path == "/disconnect":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if self.path == "/timeout":
            time.sleep(2.2)
        status = 503 if self.path == "/bad" else 302 if self.path == "/redirect" else 200
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/followed")
        self.end_headers()
        if self.path == "/slowdrip":
            try:
                for _ in range(10):
                    time.sleep(0.35)
                    self.wfile.write(b"x")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return
        body = b'password=hunter2 token=topsecret api_key=abc123\n'
        body += b"-----BEGIN PRIVATE KEY-----\nSECRETKEY\n-----END PRIVATE KEY-----\n"
        if self.path == "/large":
            body += b"x" * 100000
        if self.path == "/credential-headers":
            body = b"Cookie: session=topsecret; csrf=alsosecret\nSet-Cookie: sid=firstsecret; other=secondsecret; HttpOnly\nAuthorization: Custom initialsecret trailingsecret\n"
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, *args):
        pass


class RealDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / "service.log"
        self.log.write_text("first\nlast\n", encoding="utf-8")
        self.config = self.root / "config.json"
        self.gateway = StructuredToolGateway()
        self.audit = HashChainAuditLog(self.root / "audit.jsonl")
        self.document = {
            "version": 1,
            "services": {"nginx": {"health_url": self.url("/ok")}},
            "logs": {"/var/log/nginx/error.log": str(self.log)},
        }
        self.executor = self.build()

    def url(self, path):
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def build(self):
        self.config.write_text(json.dumps(self.document), encoding="utf-8")
        return ReadOnlyDiagnosticsExecutor(self.root / "runtime", self.config, audit=self.audit)

    def call(self, tool, args):
        return self.executor.execute(tool, args, self.gateway.authorize(tool, args, role="viewer"))["result"]

    def test_real_health_status_and_unknown_failures(self):
        for path, status, healthy, code in (("/ok", "healthy", True, 200), ("/bad", "http_error", False, 503), ("/disconnect", "unreachable", None, None), ("/timeout", "timeout", None, None)):
            with self.subTest(path=path):
                self.document["services"]["nginx"]["health_url"] = self.url(path)
                self.executor = self.build()
                result = self.call("get_service_status", {"name": "nginx"})
                self.assertEqual(result["status"], status)
                self.assertIs(result["healthy"], healthy)
                self.assertEqual(result["http_status"], code)
                self.assertGreaterEqual(result["latency_ms"], 0)
                self.assertTrue(result["observed_at"])
                self.assertEqual(result["backend"], "local_readonly")
                self.assertEqual(result["source"], self.url(path))

    def test_redirect_is_not_followed(self):
        Handler.hits.clear()
        self.document["services"]["nginx"]["health_url"] = self.url("/redirect")
        self.executor = self.build()
        result = self.call("get_service_status", {"name": "nginx"})
        self.assertEqual(result["status"], "redirect")
        self.assertIsNone(result["healthy"])
        self.assertNotIn("/followed", Handler.hits)

    def test_http_ignores_system_proxy_configuration(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""}):
            result = self.call("get_service_status", {"name": "nginx"})
        self.assertTrue(result["healthy"])

    def test_total_deadline_stops_slow_dripping_headers_and_body(self):
        for endpoint in ("/slowheaders", "/slowdrip"):
            with self.subTest(endpoint=endpoint):
                self.document["services"]["nginx"]["health_url"] = self.url(endpoint)
                self.executor = self.build()
                started = time.monotonic()
                result = self.call("get_service_status", {"name": "nginx"})
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 2.65, "new bytes must not reset the total deadline")
                self.assertGreater(elapsed, 1.6)
                self.assertEqual(result["status"], "timeout")
                self.assertIsNone(result["healthy"])

    def test_cookie_and_authorization_entire_values_hidden_in_results_and_storage(self):
        self.log.write_text("Cookie: session=topsecret; csrf=alsosecret\nSet-Cookie: sid=firstsecret; other=secondsecret; HttpOnly\nAuthorization: Custom initialsecret trailingsecret\n", encoding="utf-8")
        self.document["services"]["nginx"]["health_url"] = self.url("/credential-headers")
        self.executor = self.build()
        log_result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 3})
        http_result = self.call("get_service_status", {"name": "nginx"})
        combined = json.dumps([log_result, http_result, self.executor.list_operations()]) + self.executor.operations_path.read_text() + self.audit.log_path.read_text()
        for secret in ("topsecret", "alsosecret", "firstsecret", "secondsecret", "initialsecret", "trailingsecret"):
            self.assertNotIn(secret, combined)

    def test_health_response_bounded_and_redacted_in_result_storage_audit(self):
        self.document["services"]["nginx"]["health_url"] = self.url("/large")
        self.executor = self.build()
        result = self.call("get_service_status", {"name": "nginx"})
        self.assertLessEqual(len(result["body_excerpt"].encode()), 2048)
        self.assertTrue(result["truncated"])
        combined = json.dumps(result) + json.dumps(self.executor.list_operations()) + self.audit.log_path.read_text()
        for secret in ("hunter2", "topsecret", "abc123", "SECRETKEY"):
            self.assertNotIn(secret, combined)

    def test_connection_failure_is_unknown(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.document["services"]["nginx"]["health_url"] = f"http://127.0.0.1:{port}/health"
        self.executor = self.build()
        result = self.call("get_service_status", {"name": "nginx"})
        # Windows firewall can classify a closed local port as timeout instead of refusal.
        self.assertIn(result["status"], {"unreachable", "timeout"})
        self.assertIsNone(result["healthy"])

    def test_log_tail_redacts_before_persisting_and_preserves_source(self):
        self.log.write_text('first\npassword="secret with spaces"\n{"token":"json-secret"}\nlast\n', encoding="utf-8")
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 3})
        self.assertTrue(result["available"])
        self.assertEqual(result["lines"][-1], "last")
        self.assertEqual(result["source"], str(self.log))
        self.assertTrue(result["observed_at"])
        combined = json.dumps(result) + json.dumps(self.executor.list_operations())
        self.assertNotIn("secret with spaces", combined)
        self.assertNotIn("json-secret", combined)

    def test_log_read_is_bounded_and_reports_truncation(self):
        self.log.write_text("start\n" + "\n".join("汉" * 200 for _ in range(2000)), encoding="utf-8")
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 200})
        self.assertLessEqual(len(result["lines"]), 200)
        self.assertLessEqual(len(result["content"].encode()), 12288)
        self.assertTrue(result["truncated"])
        self.assertNotIn("start", result["content"])

    def test_missing_log_becomes_unavailable_without_exception_details(self):
        self.log.unlink()
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 3})
        self.assertFalse(result["available"])
        self.assertEqual(result["lines"], [])
        self.assertEqual(result["error"], "missing")

    def test_only_fixed_resources_and_valid_authorizations_execute(self):
        for tool, args in (("get_service_status", {"name": "api"}), ("read_log", {"path": "/var/log/app/secret.log", "lines": 1}), ("check_disk", {"url": self.url("/ok")})):
            with self.subTest(tool=tool, args=args), self.assertRaises(SandboxExecutionError):
                self.call(tool, args)
        args = {"name": "nginx"}
        decision = self.gateway.authorize("get_service_status", args, role="viewer")
        for modified in (replace(decision, call_digest="bad"), replace(decision, decision="deny")):
            with self.assertRaises(SandboxExecutionError):
                self.executor.execute("get_service_status", args, modified)
        self.assertEqual(self.executor.list_operations(), [])

    def test_approved_writes_and_rollback_are_always_refused(self):
        for tool, args in (("restart_service", {"name": "nginx"}), ("update_config", {"path": "/etc/myapp/a.conf", "content": "token=secret"})):
            decision = self.gateway.authorize(tool, args, role="admin", approval={"approved": True, "tool": tool, "call_digest": self.gateway.call_digest(tool, args)})
            self.assertEqual(decision.decision, "allow")
            with self.assertRaises(SandboxExecutionError):
                self.executor.execute(tool, args, decision)
        with self.assertRaises(SandboxExecutionError):
            self.executor.rollback("any")
        self.assertEqual(self.executor.list_operations(), [])

    def test_unsafe_urls_are_rejected_at_startup(self):
        for url in ("https://127.0.0.1:9001/a", "http://localhost:9001/a", "http://127.0.0.2:9001/a", "http://127.0.0.1:8765/a", "http://user:secret@127.0.0.1:9001/a", "http://127.0.0.1:9001/a?token=secret", "http://127.0.0.1:9001/a#x", "http://127.0.0.1:9001/a?", "http://127.0.0.1:9001/a\n"):
            with self.subTest(url=url):
                self.document["services"]["nginx"]["health_url"] = url
                with self.assertRaises(SandboxExecutionError):
                    self.build()

    def test_invalid_resource_config_is_rejected(self):
        for document in ({"version": 2, "services": {}, "logs": {}}, {"version": 1, "services": {"other": {"health_url": self.url("/ok")}}, "logs": {}}, {"version": 1, "services": {}, "logs": {"/var/log/nginx/other.log": str(self.log)}}, {"version": 1, "services": {}, "logs": {"/var/log/nginx/error.log": str(self.root / "absent")}}, {"version": 1, "services": {}, "logs": {"/var/log/nginx/error.log": str(self.root)}}):
            with self.subTest(document=document):
                self.document = document
                with self.assertRaises(SandboxExecutionError):
                    self.build()

    def test_symlink_paths_rejected_at_startup_and_runtime(self):
        alias = self.root / "alias.log"
        try:
            alias.symlink_to(self.log)
        except OSError:
            self.skipTest("local symlink privilege unavailable")
        self.document["logs"]["/var/log/nginx/error.log"] = str(alias)
        with self.assertRaises(SandboxExecutionError):
            self.build()
        alias.unlink()
        self.log.unlink()
        self.log.symlink_to(self.config)
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 2})
        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "unsafe_path")

    @unittest.skipUnless(os.name == "nt", "Windows junction contract")
    def test_windows_junction_rejected_at_startup_and_runtime(self):
        import _winapi
        actual = self.root / "actual"
        actual.mkdir()
        (actual / "service.log").write_text("junction-secret", encoding="utf-8")
        alias = self.root / "junction"
        _winapi.CreateJunction(str(actual), str(alias))
        self.document["logs"]["/var/log/nginx/error.log"] = str(alias / "service.log")
        with self.assertRaises(SandboxExecutionError):
            self.build()
        alias.rmdir()
        alias.mkdir()
        (alias / "service.log").write_text("ordinary", encoding="utf-8")
        self.executor = self.build()
        (alias / "service.log").unlink()
        alias.rmdir()
        _winapi.CreateJunction(str(actual), str(alias))
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 1})
        self.assertFalse(result["available"])
        self.assertEqual(result["error"], "unsafe_path")
        self.assertNotIn("junction-secret", json.dumps(self.executor.list_operations()))

    def test_partial_quoted_credentials_are_redacted(self):
        self.log.write_text('password="secret value that lacks closing quote', encoding="utf-8")
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 1})
        self.assertNotIn("secret", result["content"])
        self.assertNotIn("value", result["content"])

    def test_common_environment_and_header_secrets_are_hidden(self):
        self.log.write_text("DB_PASSWORD=db-secret\nAWS_SECRET_ACCESS_KEY=aws-secret\nAuthorization: Bearer header-secret\nprivatekey=plain-secret\n", encoding="utf-8")
        result = self.call("read_log", {"path": "/var/log/nginx/error.log", "lines": 4})
        for secret in ("db-secret", "aws-secret", "header-secret", "plain-secret"):
            self.assertNotIn(secret, result["content"])

    def test_disk_is_real_and_context_lists_only_configured_resources(self):
        result = self.call("check_disk", {})
        self.assertEqual(result["total"], result["free"] + result["used"])
        self.assertGreater(result["total"], 0)
        self.assertEqual(result["backend"], "local_readonly")
        self.assertTrue(result["observed_at"])
        self.assertEqual(self.executor.public_context(), {"backend": "local_readonly", "services": ["nginx"], "log_paths": ["/var/log/nginx/error.log"], "tools": ["get_service_status", "read_log", "check_disk"]})


if __name__ == "__main__":
    unittest.main()
