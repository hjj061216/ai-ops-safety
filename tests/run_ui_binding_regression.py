"""生成本次回归的新报告，不覆盖历史实验或既有报告。"""
import argparse
import io
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("拒绝覆盖已存在的回归报告")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py")
    started = time.perf_counter()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    report = {"scope": "all local unit, HTTP and script regressions; not a new AgentDojo benchmark", "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped), "passed": result.wasSuccessful(), "elapsed_seconds": round(time.perf_counter() - started, 3), "details": stream.getvalue()}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    print(json.dumps({key: value for key, value in report.items() if key != "details"}, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
