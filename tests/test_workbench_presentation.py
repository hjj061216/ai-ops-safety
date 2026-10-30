"""Run the native workbench presentation tests without a browser or backend."""
import shutil
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("node"), "工作台展示测试需要 Node.js")
class WorkbenchPresentationTests(unittest.TestCase):
    def test_native_presentation_behaviors(self):
        result = subprocess.run(
            [shutil.which("node"), str(Path(__file__).with_name("workbench_presentation.test.js"))],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
