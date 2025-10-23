# E.C.H.O -  Endpoint Command & Host Operations

Lightweight educational C2 (Command & Control) for lab use.  
**Purpose:** test basic agent/server interactions, remote command execution, file upload/download and a small admin GUI.

---

## About this project - note from the author

E.C.H.O is my very first full C2-style tool, developed for learning and lab use. I am the sole developer, I write, test, and maintain this project myself. The project is actively evolving, so expect occasional updates and improvements as I iterate.

Contributions, suggestions, and bug reports are welcome, feel free to open issues or submit pull requests.


## Key features

* FastAPI-based C2 server (`server/server.py`) with:

  * Agent beaconing and command queues
  * Results collection (JSON files stored in `server/uploads/`)
  * Endpoints for agent file uploads (`/upload/{agent_id}`) and operator->agent send (`/send_command/{agent_id}`)
  * Simple X-Auth-Token protection
* Minimal Python agent (`client/client.py`) that:

  * Beacons the server, receives tasks, runs commands (`EXEC`), performs `UPLOAD` and `DOWNLOAD`.
  * Sends structured results back to server.
* PySide6 Admin GUI (`server/admin_app/main.py`) for:

  * Viewing agents, last outputs and recent results
  * Sending `EXEC`, `UPLOAD`, `DOWNLOAD` commands
* Local CA + server certs helper (`server/certs/setup_certs.sh`) to create TLS certs for lab usage.

---

## Repo layout

```
.
├── client/
│   ├── certs/          # CA used by agent to verify server
│   ├── client.py
│   └── requirements.txt
├── server/
│   ├── admin_app/      # PySide6 GUI
│   ├── certs/          # CA, server key/cert, openssl conf & helper
│   ├── server.py
│   ├── start_server.sh
│   └── uploads/        # results & files uploaded by agents
└── LICENSE
```

---

## Quick start (local lab)

> Assumes you have Python 3.10+ and `openssl` installed.

### 1. Create a Python venv & install dependencies

```
# === On the server machine ===
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r server/requirements.txt

# === On the client machine ===
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r client/requirements.txt
```

> **Note**: The client machine needs a copy of the CA certificate (`ca.crt`) from the server to establish TLS connections.

### 2. Generate TLS certs for local lab (one-time)

```bash
# from server/certs
cd server/certs
chmod +x setup_certs.sh 
# edit openssl_ca.cnf if you need alternate IPs/DNS
./setup_certs.sh   # script automates CA + server cert creation
```

This produces:

* `ca.key`, `ca.crt` (CA)
* `server.key`, `server.crt` (server)  

The script copies `ca.crt` into `client/certs/`.

> **Screenshots to add:** `server/certs` directory listing after generation; terminal output showing success.

### 3. Start the server + GUI 

You can use the provided `server/start_server.sh`. It:

* generates an ephemeral `ECHO_AUTH_TOKEN` for the run,
* sets `ECHO_CA` / `ECHO_SERVER` env vars for admin client,
* launches `uvicorn server:app` with SSL,
* launches the admin GUI in background.

```bash
# ensure start_server.sh is executable
chmod +x server/start_server.sh
./server/start_server.sh
```

### 4. Run the agent (client)

On the agent (or local test machine) run:

```bash
# client side
python client/client.py --server https://<server-ip>:8443 --cert client/certs/ca.crt --interval 10 --token <ECHO_AUTH_TOKEN>
```

* The agent will register (beacon) and print an assigned `agent_id`.
* It polls for tasks and posts results to `/results`.

Example:

```
[+] Assigned agent_id: <uuid>
[+] Received task: EXEC whoami
[+] Uploaded successfully: ./secret.txt → uploads/
```

---

## How commands work (operator <> agent)

* Operator (Admin GUI or POST `/send_command/{agent_id}`) sends a task:

  * `EXEC <cmd>` → agent runs `<cmd>` and returns stdout/stderr
  * `UPLOAD <local_path> <remote_path>` (from admin -> agent) → admin GUI encodes file as base64 and agent decodes/writes it
  * `DOWNLOAD <remote_path> [<dest_on_server>]` → agent uploads local file to server via `/upload/{agent_id}`, optional destination can be requested via `X-Dest-Path` header
* Results are stored as JSON files in `server/uploads/` and listed by `/results_list` for the GUI.

---

## Endpoint summary

* `POST /beacon` - agent beacon (returns `task` or `agent_id`)
* `POST /send_command/{agent_id}` - queue a command for an agent
* `POST /results` - agent posts structured result JSON (saved under `server/uploads/`)
* `POST /upload/{agent_id}` - agent uploads a local file to the C2 (used by DOWNLOAD)
* `GET /agents` - list agents
* `GET /results_list` - list uploaded result files

---

## File download behavior (DOWNLOAD command)

* Agent receives `DOWNLOAD <src> [<dest>]`.

  * It reads the local `<src>` path on the agent machine.
  * It POSTs the file to `POST /upload/{agent_id}` as multipart form-data.
  * It optionally sets header `X-Dest-Path` to request server-side relocation of the stored file (server will attempt to move; may fail due to cross-device links — see Troubleshooting).
* On success, uploaded file is saved to `server/uploads/` with a unique name. The `/results_list` entry contains metadata.

**Which endpoint is used?** `/upload/{agent_id}` -  agent POSTs the file to this endpoint.

**If you specify** `DOWNLOAD .\file.txt /tmp/test.txt`

* Agent uploads local `.\file.txt` to server via `/upload/{agent_id}`.
* The agent includes header `X-Dest-Path: /tmp/test.txt` so the server may relocate the saved file to that path if permitted / possible.

---

## Security & Ethics

This project is an educational lab C2. Misuse against systems without explicit authorization is illegal and unethical. Use only on systems and networks you own or have permission to test.

---

## Development / Contributing

* Code is intentionally minimal and plain Python for learning.
* To contribute:

  * Open issues for bugs/features
  * PRs should include tests and documentation updates
  * Follow secure handling for any sensitive data (do not commit private keys)

---

## Example commands for daily use

Start server + GUI (one-liner):

```bash
./server/start_server.sh
```

Send a command to an agent (curl):

```bash
curl -k -H "X-Auth-Token: $ECHO_AUTH_TOKEN" -X POST https://localhost:8443/send_command/<agent_id> \
  -d '{"command":"EXEC whoami"}' -H 'Content-Type: application/json'
```

Manually post a result (debug):

```bash
curl -k -H "X-Auth-Token: $ECHO_AUTH_TOKEN" -X POST https://localhost:8443/results \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"<id>","command":"EXEC whoami","cmd_id":"abc","result":{"stdout":"user","stderr":""}}'
```

---

## License

See `LICENSE` in repo root.

