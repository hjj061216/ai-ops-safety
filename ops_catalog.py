"""Shared tool and resource definitions for planning, validation and execution."""
from pathlib import Path

import yaml

TOOLS_PATH = Path(__file__).resolve().parent / "policy" / "tools.yml"


def load_catalog(path=TOOLS_PATH):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


CATALOG = load_catalog()
READ_ONLY_TOOLS = tuple(name for name, spec in CATALOG["tools"].items() if spec["effect"] == "read")
WRITE_TOOLS = tuple(name for name, spec in CATALOG["tools"].items() if spec["effect"] == "write")
SERVICE_NAMES = tuple(CATALOG["tools"]["get_service_status"]["parameters"]["name"]["allowed_values"])
KNOWN_SERVICE_LOGS = dict(CATALOG["resources"]["service_error_logs"])
DEFAULT_LOG_LINES = CATALOG["resources"]["default_log_lines"]


def tool_label(name):
    return CATALOG["tools"].get(name, {}).get("description", name)
