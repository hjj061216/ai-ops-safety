"""测试专用子进程：无Guardrails依赖、无网络、无运维工具执行。"""
import argparse
import json
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--input-file", type=Path, required=True)
parser.add_argument("--call-id", required=True)
args = parser.parse_args()
raw = args.input_file.read_text(encoding="utf-8")
request = json.loads(raw)
mode = request.get("mode", "valid")
print("GUARDRAILS_PHASE " + json.dumps({"call_id": args.call_id, "phase": "input_read_done", "elapsed_seconds": 0.0}), file=sys.stderr, flush=True)
if mode == "hang":
    time.sleep(10)
elif mode == "crash":
    print("fixture process failed", file=sys.stderr)
    raise SystemExit(7)
elif mode == "invalid_utf8":
    sys.stdout.buffer.write(b"\xff")
    raise SystemExit(0)
elif mode == "garbage":
    print("not-json")
    raise SystemExit(0)
elif mode == "empty":
    raise SystemExit(0)
elif mode == "list":
    print("[]")
    raise SystemExit(0)
elif mode == "null":
    print("null")
    raise SystemExit(0)
candidate = {"actionable": True, "intent": "fixture", "tool": "check_disk", "arguments": {"input_path": str(args.input_file), "received_bytes": len(raw.encode("utf-8"))}, "risk": "low", "reason": "fixture only"}
if mode == "unicode":
    candidate.update(intent="查看应用日志", reason="只读请求")
response = {"validation_passed": True, "validated_output": candidate, "error": None, "timings_seconds": {"validation": 0.001}}
if mode == "rejected":
    response.update(validation_passed=False, validated_output=None, error="fixture rejection")
elif mode == "non_boolean_pass":
    response["validation_passed"] = "true"
elif mode == "non_object_output":
    response["validated_output"] = []
print(json.dumps(response, ensure_ascii=False), flush=True)
