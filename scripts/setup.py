"""Create separate core and Guardrails environments on Windows or POSIX."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def install(directory: Path, requirements: Path) -> Path:
    python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        venv.EnvBuilder(with_pip=True).create(directory)
    subprocess.run([str(python), "-m", "pip", "install", "-r", str(requirements)], check=True)
    return python


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-only", action="store_true", help="Skip Guardrails; manual tool mode remains available")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("Use Python 3.12 to reproduce the documented environment")
    core = install(ROOT / ".venv", ROOT / "requirements-core.txt")
    if not args.core_only:
        guardrails = ROOT / "reproductions" / "guardrails_ai"
        install(guardrails / ".venv", guardrails / "requirements.txt")
    print(f'\nStart the console: "{core}" "{ROOT / "local_app.py"}"')


if __name__ == "__main__":
    main()
