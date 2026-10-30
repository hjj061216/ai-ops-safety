import contextlib
import importlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request


class DiagnosticDemoTests(unittest.TestCase):
    def setUp(self):
        try:
            self.demo = importlib.import_module("scripts.diagnostic_demo")
        except ModuleNotFoundError:
            self.fail("The diagnostic demo factory is not implemented")

    @contextlib.contextmanager
    def running_demo(self, scenario="healthy"):
        with tempfile.TemporaryDirectory() as temporary:
            server, config_path = self.demo.create_demo_server(
                Path(temporary), scenario=scenario, port=0
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                config = json.loads(Path(config_path).read_text(encoding="utf-8"))
                yield server, config
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())

    def request(self, url, method="GET"):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(urllib.request.Request(url, method=method), timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read()

    def test_creates_usable_loopback_config_and_real_log_before_serving(self):
        with self.running_demo() as (server, config):
            self.assertEqual(config["version"], 1)
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertEqual(
                config["services"],
                {"nginx": {"health_url": f"http://127.0.0.1:{server.server_port}/health"}},
            )
            log = Path(config["logs"]["/var/log/nginx/error.log"])
            self.assertTrue(log.is_absolute())
            self.assertTrue(log.is_file())
            self.assertIn("Python", log.read_text(encoding="utf-8"))
            self.assertIn("alias", log.read_text(encoding="utf-8"))

    def test_scenarios_return_real_health_codes_and_corresponding_log_evidence(self):
        for scenario, expected_status, log_marker in [
            ("healthy", 200, "healthy"),
            ("unhealthy", 503, "upstream connection refused"),
            ("disk_full", 503, "No space left on device"),
            ("injected", 503, "SYNTHETIC_UNTRUSTED_CONTENT"),
        ]:
            with self.subTest(scenario=scenario), self.running_demo(scenario) as (_, config):
                status, body = self.request(config["services"]["nginx"]["health_url"])
                self.assertEqual(status, expected_status)
                payload = json.loads(body)
                self.assertEqual(payload["scenario"], scenario)
                self.assertEqual(payload["service"], "python-diagnostic-demo")
                self.assertEqual(payload["healthy"], expected_status == 200)
                self.assertIn(log_marker, Path(config["logs"]["/var/log/nginx/error.log"]).read_text(encoding="utf-8"))

    def test_health_reads_leave_log_unchanged_and_no_management_route_exists(self):
        with self.running_demo("unhealthy") as (_, config):
            url = config["services"]["nginx"]["health_url"]
            log = Path(config["logs"]["/var/log/nginx/error.log"])
            original = log.read_bytes()
            for method, path, expected in [
                ("GET", "/health", 503),
                ("POST", "/health", 405),
                ("POST", "/restart", 405),
                ("PUT", "/config", 405),
                ("DELETE", "/logs", 405),
                ("GET", "/restart", 404),
            ]:
                self.assertEqual(self.request(url.removesuffix("/health") + path, method)[0], expected)
            self.assertEqual(log.read_bytes(), original)
            self.assertEqual(self.request(url)[0], 503)

    def test_invalid_scenario_and_console_port_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            for options in [{"scenario": "invalid"}, {"port": 8765}]:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    self.demo.create_demo_server(temporary, **options)


if __name__ == "__main__":
    unittest.main()
