"""The public workbench serves only its two declared static assets."""
import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from local_app import LocalSafetyApp, SafetyConsoleHandler
from scripts import export_github


class WorkbenchAssetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        web = root / "web"
        web.mkdir()
        (web / "workbench.css").write_bytes("/* 工作台 */\nbody { color: blue; }".encode("utf-8"))
        (web / "workbench.js").write_bytes(b"window.workbenchReady = true;\n")
        (web / "private.txt").write_bytes(b"undeclared-file-marker")
        (root / ".env").write_bytes(b"outside-web-marker")
        app = LocalSafetyApp(root / "runtime")

        class Handler(SafetyConsoleHandler):
            def log_message(self, *args):
                pass

        Handler.app = app
        self.handler = Handler
        web_patch = patch("local_app.WEB_ROOT", web)
        web_patch.start()
        self.addCleanup(web_patch.stop)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 3)
        self.addCleanup(self.server.shutdown)

    def get(self, path):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            # http.client preserves traversal segments so the server receives them.
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_declared_assets_are_public_with_exact_content_and_safe_headers(self):
        for name, content_type, expected in (
            ("workbench.css", "text/css; charset=utf-8", "/* 工作台 */\nbody { color: blue; }".encode("utf-8")),
            ("workbench.js", "text/javascript; charset=utf-8", b"window.workbenchReady = true;\n"),
        ):
            for suffix in ("", "?version=1&path=../.env"):
                with self.subTest(name=name, suffix=suffix):
                    status, headers, body = self.get("/assets/" + name + suffix)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, expected)
                    self.assertEqual(headers["Content-Type"], content_type)
                    self.assertEqual(headers["Content-Length"], str(len(expected)))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_public_asset_routes_do_not_make_apis_public(self):
        for path in ("/api/status", "/api/tasks", "/api/audit/verify"):
            with self.subTest(path=path):
                status, _, body = self.get(path)
                self.assertEqual(status, 401)
                self.assertFalse(json.loads(body)["ok"])

    def test_undeclared_paths_never_serve_files_or_directory_listings(self):
        # Exercise the dispatch boundary after auth as well, without test accounts.
        self.handler.auth_required = False
        for path in (
            "/assets/", "/assets/private.txt", "/web/private.txt",
            "/assets/../.env", "/assets/../../.env", "/../.env",
            "/assets/%2e%2e/.env", "/assets/workbench.css/private.txt",
            "/assets/%2e%2e%5c.env", "/assets/workbench.css.bak",
        ):
            with self.subTest(path=path):
                status, _, body = self.get(path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"undeclared-file-marker", body)
                self.assertNotIn(b"outside-web-marker", body)
                self.assertNotIn(b"Directory listing", body)


class WorkbenchExportTests(unittest.TestCase):
    def test_source_collection_includes_both_workbench_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(export_github, "ROOT", root):
                collected = {path.relative_to(root).as_posix() for path in export_github.source_files()}
            self.assertIn("web/workbench.css", collected)
            self.assertIn("web/workbench.js", collected)


if __name__ == "__main__":
    unittest.main()
