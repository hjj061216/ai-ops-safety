"""Release checks must use exported sources and ignore local model credentials."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_release


class ReleaseVerificationTests(unittest.TestCase):
    def test_missing_node_fails_before_install_instead_of_skipping_page_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('shutil.which', return_value=None), patch.object(verify_release.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'Node.js'):
                    verify_release.verify_source(Path(directory))
            run.assert_not_called()

    def test_install_and_real_validator_and_suite_use_exported_directory(self):
        with tempfile.TemporaryDirectory(prefix="release with spaces ") as directory:
            source = Path(directory)
            alias_child = source / 'input alias'
            alias_child.mkdir()
            with patch.dict(os.environ, {"DEEPSEEK_API_KEY":"private-local-key", "LLM_API_KEY":"private-compatible-key", "GUARDRAILS_AI_PYTHON":"old-environment", "OLLAMA_URL":"http://old-model", "PYTHONPATH":"old-source", "PIP_TARGET":"old-install"}), patch.object(verify_release.subprocess, "run") as run:
                verify_release.verify_source(alias_child / '..')
            self.assertEqual(run.call_count, 3)
            for call in run.call_args_list:
                # Windows short names and resolved long names may identify the
                # same directory without having identical path spellings.
                self.assertTrue(call.kwargs['cwd'].samefile(source))
                self.assertTrue(call.kwargs['check'])
                env = call.kwargs['env']
                self.assertNotIn('DEEPSEEK_API_KEY', env)
                self.assertNotIn('LLM_API_KEY', env)
                self.assertNotIn('GUARDRAILS_AI_PYTHON', env)
                self.assertNotIn('OLLAMA_URL', env)
                self.assertNotIn('PYTHONPATH', env)
                self.assertNotIn('PIP_TARGET', env)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn('scripts/setup.py', commands[0])
            self.assertTrue(any('validate_output.py' in str(arg) for arg in commands[1]))
            self.assertIn('--demo', commands[1])
            self.assertIn('unittest', commands[2])
            self.assertNotIn('old-environment', str(commands))

    def test_failed_install_does_not_report_validation_or_run_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(verify_release.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['install'])) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    verify_release.verify_source(Path(directory))
            self.assertEqual(run.call_count, 1)
