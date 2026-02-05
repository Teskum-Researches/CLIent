#! /usr/bin/env python3
import asyncio
import json
import ssl
import sys
from dataclasses import dataclass

import websockets
from PyQt6.QtCore import QObject, QThread, pyqtSignal as Signal, pyqtSlot as Slot
from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QWidget,
)

from config import allow_self_signed, ip, is_secure, port


@dataclass
class ConnectionConfig:
    ip: str
    port: int
    is_secure: bool
    allow_self_signed: bool

    @property
    def uri(self) -> str:
        protocol = "wss" if self.is_secure else "ws"
        return f"{protocol}://{self.ip}:{self.port}/ws"


def pretty_response_lines(response_text: str) -> list[str]:
    """Convert server response to user-friendly lines for UI output."""
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        return [response_text]

    lines: list[str] = []
    messages = data.get("messages", [])
    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict) and "user" in msg and "content" in msg:
                lines.append(f"{msg['user']}: {msg['content']}")
            else:
                lines.append(str(msg))

    if "status" in data and data["status"] != "OK":
        lines.append(f"Server status: {data['status']}")

    for key, value in data.items():
        if key in {"messages"}:
            continue
        if key == "status" and value == "OK":
            continue
        if isinstance(value, (dict, list)):
            lines.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            lines.append(f"{key}: {value}")

    return lines or ["(empty response)"]


class ClientWorker(QObject):
    message_received = Signal(str)
    connection_changed = Signal(bool)
    login_result = Signal(bool, str)
    error = Signal(str)

    def __init__(self, cfg: ConnectionConfig):
        super().__init__()
        self._cfg = cfg
        self._loop: asyncio.AbstractEventLoop | None = None
        self._websocket = None
        self._session = ""

    @Slot(str, str, str)
    def connect_and_auth(self, operation: str, username: str, password: str) -> None:
        if self._loop is None:
            self.error.emit("Internal error: event loop is not initialized.")
            return
        fut = asyncio.run_coroutine_threadsafe(
            self._connect_and_auth(operation, username, password), self._loop
        )
        fut.add_done_callback(self._emit_future_error)

    @Slot(str)
    def send_chat(self, content: str) -> None:
        if self._loop is None:
            self.error.emit("Internal error: event loop is not initialized.")
            return
        fut = asyncio.run_coroutine_threadsafe(self._send_chat(content), self._loop)
        fut.add_done_callback(self._emit_future_error)

    @Slot()
    def list_messages(self) -> None:
        if self._loop is None:
            self.error.emit("Internal error: event loop is not initialized.")
            return
        fut = asyncio.run_coroutine_threadsafe(self._list_messages(), self._loop)
        fut.add_done_callback(self._emit_future_error)

    @Slot()
    def close_connection(self) -> None:
        if self._loop is None:
            return
        fut = asyncio.run_coroutine_threadsafe(self._close_connection(), self._loop)
        fut.add_done_callback(self._emit_future_error)

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)

    def _emit_future_error(self, fut) -> None:
        exc = fut.exception()
        if exc:
            self.error.emit(str(exc))

    async def _send_and_emit(self, payload: dict) -> dict:
        if self._websocket is None:
            self.error.emit("Not connected.")
            return {}

        await self._websocket.send(json.dumps(payload, ensure_ascii=False))
        response_text = await self._websocket.recv()
        for line in pretty_response_lines(response_text):
            self.message_received.emit(line)
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return {}

    async def _connect_and_auth(self, operation: str, username: str, password: str) -> None:
        if self._websocket is not None:
            await self._close_connection()

        ssl_context = ssl.create_default_context()
        if self._cfg.allow_self_signed:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        if not self._cfg.is_secure:
            ssl_context = None

        self._websocket = await websockets.connect(
            self._cfg.uri,
            ping_interval=20,
            ping_timeout=10,
            ssl=ssl_context,
        )

        self.connection_changed.emit(True)
        self.message_received.emit(f"Connected to {self._cfg.ip}:{self._cfg.port}")

        if operation == "register":
            result = await self._send_and_emit(
                {"cmd": "register", "username": username, "pass": password}
            )
            if result.get("status") == "ERROR":
                await self._close_connection()
                self.login_result.emit(False, "Registration failed")
                return
            operation = "login"

        result = await self._send_and_emit(
            {"cmd": "login", "username": username, "pass": password}
        )
        if result.get("status") == "OK":
            self._session = result.get("session", "")
            self.login_result.emit(True, "Authenticated")
            self.message_received.emit("You can now type a message and press Send.")
        else:
            await self._close_connection()
            self.login_result.emit(False, "Login failed")

    async def _send_chat(self, content: str) -> None:
        if not self._session:
            self.error.emit("Not authenticated.")
            return
        await self._send_and_emit({"cmd": "send", "content": content, "session": self._session})

    async def _list_messages(self) -> None:
        if not self._session:
            self.error.emit("Not authenticated.")
            return
        await self._send_and_emit({"cmd": "list", "session": self._session})

    async def _close_connection(self) -> None:
        if self._websocket is not None:
            try:
                await self._websocket.close()
            finally:
                self._websocket = None
                self._session = ""
                self.connection_changed.emit(False)


class MainWindow(QMainWindow):
    connect_requested = Signal(str, str, str)
    send_requested = Signal(str)
    list_requested = Signal()
    disconnect_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CLIent Qt")
        self.resize(760, 520)

        central = QWidget(self)
        self.setCentralWidget(central)
        root = QGridLayout(central)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register + Login")
        self.logout_btn = QPushButton("Disconnect")
        self.logout_btn.setEnabled(False)

        auth_line = QHBoxLayout()
        auth_line.addWidget(QLabel("User:"))
        auth_line.addWidget(self.user_input)
        auth_line.addWidget(QLabel("Pass:"))
        auth_line.addWidget(self.pass_input)
        auth_line.addWidget(self.login_btn)
        auth_line.addWidget(self.register_btn)
        auth_line.addWidget(self.logout_btn)

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type message...")
        self.send_btn = QPushButton("Send")
        self.list_btn = QPushButton("List messages")
        self.send_btn.setEnabled(False)
        self.list_btn.setEnabled(False)

        send_line = QHBoxLayout()
        send_line.addWidget(self.msg_input)
        send_line.addWidget(self.send_btn)
        send_line.addWidget(self.list_btn)

        root.addLayout(auth_line, 0, 0)
        root.addWidget(self.log_output, 1, 0)
        root.addLayout(send_line, 2, 0)

        self.login_btn.clicked.connect(self._on_login_clicked)
        self.register_btn.clicked.connect(self._on_register_clicked)
        self.logout_btn.clicked.connect(self.disconnect_requested.emit)
        self.send_btn.clicked.connect(self._on_send_clicked)
        self.msg_input.returnPressed.connect(self._on_send_clicked)
        self.list_btn.clicked.connect(self.list_requested.emit)

    def append_log(self, line: str) -> None:
        self.log_output.appendPlainText(line)

    def _on_login_clicked(self) -> None:
        self._emit_connect("login")

    def _on_register_clicked(self) -> None:
        self._emit_connect("register")

    def _emit_connect(self, operation: str) -> None:
        username = self.user_input.text().strip()
        password = self.pass_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Input required", "Enter username and password.")
            return
        self.connect_requested.emit(operation, username, password)

    def _on_send_clicked(self) -> None:
        content = self.msg_input.text().strip()
        if not content:
            return
        self.send_requested.emit(content)
        self.msg_input.clear()

    @Slot(bool)
    def set_connected(self, is_connected: bool) -> None:
        self.logout_btn.setEnabled(is_connected)

    @Slot(bool, str)
    def set_authenticated(self, ok: bool, reason: str) -> None:
        self.send_btn.setEnabled(ok)
        self.list_btn.setEnabled(ok)
        if not ok:
            QMessageBox.warning(self, "Authentication", reason)

    @Slot(str)
    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Error", message)

    def closeEvent(self, event):
        self.disconnect_requested.emit()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)

    cfg = ConnectionConfig(
        ip=ip,
        port=port,
        is_secure=is_secure,
        allow_self_signed=allow_self_signed,
    )

    thread = QThread()
    worker = ClientWorker(cfg)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    window = MainWindow()

    window.connect_requested.connect(worker.connect_and_auth)
    window.send_requested.connect(worker.send_chat)
    window.list_requested.connect(worker.list_messages)
    window.disconnect_requested.connect(worker.close_connection)

    worker.message_received.connect(window.append_log)
    worker.connection_changed.connect(window.set_connected)
    worker.login_result.connect(window.set_authenticated)
    worker.error.connect(window.show_error)

    thread.start()
    window.show()

    exit_code = app.exec()

    worker.stop()
    thread.quit()
    thread.wait(3000)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
