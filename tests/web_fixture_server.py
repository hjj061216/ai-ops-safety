"""仅用于浏览器回归：临时沙箱、模拟模型输出、真实本地应用与验证器。"""
import argparse
import json
import sys
import tempfile
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local_app import LocalSafetyApp, SafetyConsoleHandler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ops-web-regression-") as directory:
        app = LocalSafetyApp(Path(directory) / "runtime")
        def model(text):
            if "格式错误" in text:
                return "not-json"
            if "重启" in text:
                tool, arguments, risk = "restart_service", {"name": "nginx"}, "high"
            elif "日志" in text:
                tool, arguments, risk = "read_log", {"path": "/var/log/nginx/error.log", "lines": 2}, "low"
            else:
                tool, arguments, risk = "get_service_status", {"name": "nginx"}, "low"
            return json.dumps({"actionable": True, "intent": "浏览器测试候选", "tool": tool, "arguments": arguments, "risk": risk, "reason": "模拟模型输出；真实验证器和后端控制"}, ensure_ascii=False)
        app.interpreter._ollama_client = model
        class Handler(SafetyConsoleHandler):
            def log_message(self, *args):
                pass
        Handler.app = app
        server = HTTPServer(("127.0.0.1", options.port), Handler)
        print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}", "runtime": "temporary", "model": "fixture", "validator": "real Guardrails AI"}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
