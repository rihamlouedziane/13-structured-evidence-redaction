import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_app(*arguments):
    return subprocess.run(
        [sys.executable, "-B", "app.py", *arguments],
        capture_output=True,
        text=True,
        check=False
    )


def run_app_with_payload(payload):
    with tempfile.TemporaryDirectory() as directory:
        input_path = Path(directory) / "input.json"

        input_path.write_text(
            json.dumps(payload),
            encoding="utf-8"
        )

        return run_app("--input", str(input_path))