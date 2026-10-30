"""Export, install and test a fresh source copy without local model settings."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def clean_environment() -> dict[str, str]:
    # The verification copy must not reuse a paid key or a validator elsewhere.
    env = {key:value for key,value in os.environ.items()
           if not key.startswith(('DEEPSEEK_', 'OLLAMA_', 'LLM_', 'GUARDRAILS_AI_'))
           and key not in {'PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'}}
    env['PYTHONUTF8'] = '1'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONNOUSERSITE'] = '1'
    return env


def verify_source(source: Path) -> None:
    if shutil.which('node') is None:
        raise RuntimeError('Node.js is required for release verification; install it before running page tests.')
    source = source.resolve()
    interpreter = Path('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    core = source / '.venv' / interpreter
    validator = source / 'reproductions' / 'guardrails_ai' / '.venv' / interpreter
    steps = (
        ('Install both isolated environments', [sys.executable, 'scripts/setup.py']),
        ('Check real Guardrails', [str(validator), '-B', 'reproductions/guardrails_ai/validate_output.py', '--demo']),
        ('Run exported-source tests', [str(core), '-B', '-m', 'unittest', 'discover', '-v', '-s', 'tests', '-p', 'test_*.py']),
    )
    env = clean_environment()
    for title, command in steps:
        print(f'\n== {title} ==', flush=True)
        subprocess.run(command, cwd=source, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist' / 'release-check',
                        help='A new verification directory; it will contain temporary environments')
    args = parser.parse_args()
    source = args.output.resolve()
    subprocess.run([sys.executable, str(ROOT / 'scripts/export_github.py'), '--output', str(source)],
                   cwd=ROOT, env=clean_environment(), check=True)
    verify_source(source)
    print(f'\nRelease verification finished in {source}. Inspect skipped tests in the report.', flush=True)
    print('This directory includes test environments. Export a separate source-only directory for publication.', flush=True)


if __name__ == '__main__':
    main()
