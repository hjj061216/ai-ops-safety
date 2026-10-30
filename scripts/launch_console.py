"""Open the browser only after the local HTTP console is ready."""
import json
from pathlib import Path
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
URL = "http://127.0.0.1:8765"


def ready():
    try:
        with urlopen(URL + "/api/session", timeout=.5) as response:
            return json.load(response).get("ok") is True
    except (OSError, ValueError, URLError):
        return False


def open_when_ready():
    for _ in range(50):
        if ready():
            webbrowser.open(URL)
            return
        time.sleep(.2)
    print("服务尚未就绪，请查看错误信息，修复后重新启动。")


def main():
    if ready():
        webbrowser.open(URL)
        return
    from local_app import main as serve
    threading.Thread(target=open_when_ready, daemon=True).start()
    serve()


if __name__ == "__main__":
    main()
