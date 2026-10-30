"""受控故障注入：模拟依赖初始化期间两秒不读取输入。"""
import argparse
import json
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--input-file", type=Path)
parser.add_argument("--call-id", default="baseline")
args = parser.parse_args()
print("GUARDRAILS_PHASE " + json.dumps({"call_id": args.call_id, "phase": "before_input_read", "elapsed_seconds": 0.0}), file=sys.stderr, flush=True)
time.sleep(2)
raw = args.input_file.read_text(encoding="utf-8") if args.input_file else sys.stdin.read()
json.loads(raw)
print(json.dumps({"validation_passed": True, "validated_output": {"actionable": True, "intent": "controlled fixture", "tool": "check_disk", "arguments": {}, "risk": "low", "reason": "fixture only"}, "error": None}), flush=True)
