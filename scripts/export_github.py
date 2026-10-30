"""Export a new source-only directory using an explicit allowlist; never delete files."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "README.md", ".gitignore", ".env.example", "requirements-core.txt", "requirements.txt",
    "LICENSE", "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
    ".github/workflows/tests.yml",
    "docs/ARCHITECTURE.md", "docs/AUTONOMOUS_TASKS.md", "docs/DEEPSEEK_API.md",
    "docs/MODEL_CONFIGURATION.md",
    "docs/PUBLISHING.md", "docs/REAL_DIAGNOSTICS.md", "docs/TASK_WORKFLOW_TESTS.md",
    "docs/images/workbench.png",
    "approval_manager.py", "audit_log.py", "candidate_store.py",
    "full_safety_demo.py", "guardrails_output_validator.py", "hybrid_policy.py",
    "local_app.py", "natural_language_agent.py", "offline_requests.py", "model_client.py",
    "sandbox_executor.py", "secure_tool_service.py", "structured_tools.py",
    "task_agent.py", "task_scope.py", "ops_catalog.py",
    "real_diagnostics.py", "diagnostic_reasoning.py", "scripts/diagnostic_demo.py", "config/diagnostics.example.json",
    "auth.py", "scripts/manage_users.py",
    "scripts/launch_console.py",
    "run-local-app.bat", "scripts/setup.py", "scripts/export_github.py", "scripts/verify_release.py",
    "scripts/run-all-tests.bat", "scripts/run-full-demo.bat",
    "policy/hard_rules.yml", "policy/tools.yml", "web/index.html",
    "web/workbench.css", "web/workbench.js",
    "reproductions/guardrails_ai/requirements.txt",
    "reproductions/guardrails_ai/ops_validators.py",
    "reproductions/guardrails_ai/validate_output.py",
)


def source_files() -> list[Path]:
    files = {ROOT / name for name in FILES}
    for directory, patterns in (
        ("tests", ("*.py", "*.js")),
    ):
        for pattern in patterns:
            files.update((ROOT / directory).rglob(pattern))
    return sorted(files)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "ai-ops-safety")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or output in ROOT.parents:
        parser.error("The output must be a new directory, not the source or its parent")
    files = source_files()
    missing = [str(path.relative_to(ROOT)) for path in files if not path.is_file()]
    if missing:
        parser.error("Missing source files: " + ", ".join(missing))
    # Refuse existing paths so old secrets/artifacts cannot survive in an export.
    output.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for source in files:
        relative = source.relative_to(ROOT)
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        manifest[relative.as_posix()] = hashlib.sha256(target.read_bytes()).hexdigest()
    (output / "SOURCE_MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Exported {len(files)} source files to {output}")


if __name__ == "__main__":
    main()
