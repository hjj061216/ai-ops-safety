"""Release export must exclude local data and refuse stale output directories."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import export_github

ROOT = Path(__file__).resolve().parents[1]


class GitHubExportTests(unittest.TestCase):
    def test_source_only_export_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            command = [sys.executable, "-X", "utf8", str(ROOT / "scripts/export_github.py"), "--output", str(output)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            manifest = json.loads((output / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
            for required in ("LICENSE", "local_app.py", "model_client.py", ".env.example", "web/index.html", "web/workbench.css", "web/workbench.js", "policy/tools.yml", ".github/workflows/tests.yml", "scripts/verify_release.py", "docs/REAL_DIAGNOSTICS.md", "docs/images/workbench.png", "tests/fixtures/validator_process_fixture.py"):
                self.assertIn(required, manifest)
            forbidden = {".venv", "data", "evaluations", "projects", "deliverables", ".git", ".codex"}
            for path in manifest:
                self.assertTrue(forbidden.isdisjoint(Path(path).parts), path)
                self.assertNotIn(Path(path).suffix, (".pptx", ".pem", ".key"))
                self.assertNotEqual(Path(path).name, ".env")
                self.assertNotIn("superpowers", Path(path).parts)
            marker = output / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertIsInstance(second.stderr, str, "Export failures must retain a readable diagnostic")
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_new_internal_documents_are_not_automatically_public(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("docs/REAL_DIAGNOSTICS.md", "docs/private-notes.md", "docs/superpowers/specs/internal.md", ".github/private-notes.md", "tests/fixtures/example.py"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("local note", encoding="utf-8")
            with patch.object(export_github, "ROOT", root):
                names = {path.relative_to(root).as_posix() for path in export_github.source_files()}
            self.assertIn("docs/REAL_DIAGNOSTICS.md", names)
            self.assertIn("tests/fixtures/example.py", names)
            self.assertNotIn("docs/private-notes.md", names)
            self.assertNotIn("docs/superpowers/specs/internal.md", names)
            self.assertNotIn(".github/private-notes.md", names)


if __name__ == "__main__":
    unittest.main()
