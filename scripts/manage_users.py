"""Create a local account without putting its password in command arguments."""
import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from auth import AuthStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("role", choices=sorted(AuthStore.ROLES))
    parser.add_argument("--runtime", type=Path, default=ROOT / "data/web_runtime")
    args = parser.parse_args()
    password = getpass.getpass("Password (at least 12 characters): ")
    if password != getpass.getpass("Repeat password: "):
        parser.error("Passwords do not match")
    AuthStore(args.runtime / "users.json").add_user(args.username, password, args.role)
    print("Account created:", args.username, args.role)


if __name__ == "__main__":
    main()
