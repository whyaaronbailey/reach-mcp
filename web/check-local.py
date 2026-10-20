"""Isolated relay integration test. Reads the desktop; never publishes a service."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from test_controls import ChildJob, select_test_mode

NATIVE_PORT = 18765
RELAY_TEST_PORT = 8899


def stop_child(process) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main() -> int:
    if os.name != "nt" or ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Run as the non-elevated Windows desktop user.")
    for port in (NATIVE_PORT, RELAY_TEST_PORT):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(f"Test port {port} is occupied.")

    with tempfile.TemporaryDirectory(prefix="reach-relay-test-") as directory:
        temp = Path(directory)
        state_dir = temp / ".state"
        config = {
            "public_url": "https://reach.example.test",
            "client_id": "dummy-client-id",
            "client_secret": "dummy-client-secret",
            "jwt_signing_key": secrets.token_urlsafe(48),
            "native_token": secrets.token_urlsafe(32),
            "native_url": f"http://127.0.0.1:{NATIVE_PORT}/mcp",
            "allowed_github_user_ids": [12345678],
        }
        config_path = temp / "relay-test.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        env = os.environ.copy()
        env.pop("REACH_MCP_CONFIG", None)
        env["REACH_MCP_HOME"] = str(temp)
        env["REACH_MCP_TOKEN"] = config["native_token"]
        env["PYTHONIOENCODING"] = "utf-8"
        job = ChildJob()
        native = relay_test = None
        try:
            with (temp / "native-stderr.log").open("w", encoding="utf-8") as stderr:
                native = subprocess.Popen(
                    [
                        str(ROOT / ".venv/Scripts/python.exe"), "-m", "reach_mcp",
                        "--transport", "http", "--port", str(NATIVE_PORT),
                        "--client", "isolated-relay-test",
                        "--control-port", "0", "--control-state-dir", str(state_dir),
                    ],
                    cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=stderr,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                job.attach(native)
                for _ in range(300):
                    if native.poll() is not None:
                        raise RuntimeError("Isolated native test server exited.")
                    with socket.socket() as probe:
                        if probe.connect_ex(("127.0.0.1", NATIVE_PORT)) == 0:
                            break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Isolated native test server did not start.")

                # This isolated child explicitly authorizes its own desktop/developer test calls.
                # It uses the same owner API as the panel, not a server bypass.
                select_test_mode(state_dir, "full", 300)
                relay_env = env.copy()
                relay_env.pop("REACH_MCP_TOKEN", None)
                print("Native ready; temporary isolated-test approval set.", flush=True)
                relay_test = subprocess.Popen(
                    [
                        str(ROOT / "web/.venv/Scripts/python.exe"), "-u",
                        str(ROOT / "web/test_relay.py"), "--config", str(config_path),
                    ],
                    cwd=ROOT, env=relay_env, creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                )
                job.attach(relay_test)
                output, _ = relay_test.communicate(timeout=180)
                print(output, end="", flush=True)
                code = relay_test.returncode
                print(f"Relay subprocess exit: {code}", flush=True)
                if "ALL PASS" not in output:
                    raise RuntimeError("Relay test did not report completed checks")
                return code
        finally:
            # Closing the job also removes descendants of the venv launchers.
            job.close()
            stop_child(relay_test)
            stop_child(native)
            # Windows may release inherited log handles shortly after job exit.
            for _ in range(100):
                try:
                    (temp / "native-stderr.log").unlink(missing_ok=True)
                    break
                except PermissionError:
                    time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
