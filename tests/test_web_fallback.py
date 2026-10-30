import shutil
import subprocess
import unittest
from pathlib import Path


class WebFallbackTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "页面行为测试需要 Node.js")
    def test_page_clears_stale_calls_and_offers_manual_recovery(self) -> None:
        result = subprocess.run(
            [shutil.which("node"), str(Path(__file__).with_name("web_fallback.test.js"))],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
