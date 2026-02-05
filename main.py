#! /usr/bin/env python3
import asyncio
import json
import shlex
import ssl

import websockets

from config import allow_self_signed, ip, is_secure, port


async def ainput(prompt: str = "") -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


def print_server_response(response_text: str) -> None:
    """Pretty-print server response and gracefully handle unknown payloads."""
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        print(response_text)
        return

    messages = data.get("messages", [])
    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict) and "user" in msg and "content" in msg:
                print(f"{msg['user']}: {msg['content']}")
            else:
                print(msg)

    # Print status/errors and any additional payload from new server features.
    if "status" in data and data["status"] != "OK":
        print(f"Server status: {data['status']}")

    for key, value in data.items():
        if key in {"messages"}:
            continue
        if key == "status" and value == "OK":
            continue
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            print(f"{key}: {value}")


async def send_and_print(websocket, payload: dict) -> dict:
    await websocket.send(json.dumps(payload, ensure_ascii=False))
    response_text = await websocket.recv()
    print_server_response(response_text)
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        return {}


async def main():
    print("CLIent (c) Teskum Researches, 2025-2026")
    print("This software is under GNU GPLv3 license. Check LICENSE file for details.")
    uri = f"{'wss' if is_secure else 'ws'}://{ip}:{port}/ws"

    ssl_context = ssl.create_default_context()
    if allow_self_signed:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    if not is_secure:
        ssl_context = None

    async with websockets.connect(uri, ping_interval=20, ping_timeout=10, ssl=ssl_context) as websocket:
        print("CLIent: connected to server ", ip, ":", port)
        print("Register (r) or Login (l)?")
        operation = (await ainput("> ")).strip()
        print("Your username?")
        user = (await ainput("> ")).strip()
        print("Your password?")
        password = (await ainput("> ")).strip()

        session = ""
        if operation == "r":
            result = await send_and_print(
                websocket,
                {"cmd": "register", "username": user, "pass": password},
            )
            if result.get("status") == "ERROR":
                print("CLIent: Error registering user.")
                return

            result = await send_and_print(
                websocket,
                {"cmd": "login", "username": user, "pass": password},
            )
            if result.get("status") == "OK":
                session = result.get("session", "")
            else:
                print("Error while logging in after registration.")
                return

        elif operation == "l":
            result = await send_and_print(
                websocket,
                {"cmd": "login", "username": user, "pass": password},
            )
            if result.get("status") == "OK":
                session = result.get("session", "")
            else:
                print("Error while logging in.")
                return
        else:
            print("Unknown operation. Use 'r' or 'l'.")
            return

        running = True
        while running:
            command = (await ainput("> ")).strip()
            if command == "":
                continue

            # If input does NOT start with '/', treat it as message content to send.
            if not command.startswith("/"):
                await send_and_print(
                    websocket,
                    {"cmd": "send", "content": command, "session": session},
                )
                continue

            # Slash commands
            cmdline = command[1:]
            parts = shlex.split(cmdline)
            if not parts:
                continue

            cmd = parts[0]
            args = parts[1:]

            if cmd == "help":
                print("CLIent commands:")
                print("/help - command list")
                print("/list - list messages")
                print("/send - sends a message")
                print("/json <json> - send raw JSON payload to server")
                print("/<server_cmd> [args...] - forward command to server for new functionality")
                print("/exit - exit")
            elif cmd == "list":
                await send_and_print(websocket, {"cmd": "list", "session": session})
            elif cmd == "send":
                content = (await ainput("  Content?> ")).strip()
                await send_and_print(
                    websocket,
                    {"cmd": "send", "content": content, "session": session},
                )
            elif cmd == "json":
                raw_json = cmdline[len("json") :].strip()
                if not raw_json:
                    print("Usage: /json {\"cmd\": \"...\"}")
                    continue
                try:
                    payload = json.loads(raw_json)
                except json.JSONDecodeError as err:
                    print(f"Invalid JSON: {err}")
                    continue
                if isinstance(payload, dict):
                    payload.setdefault("session", session)
                else:
                    print("JSON payload must be an object.")
                    continue
                await send_and_print(websocket, payload)
            elif cmd == "exit":
                print("Exiting...")
                running = False
            else:
                # Forward unknown command to server to support newly added server functionality.
                await send_and_print(
                    websocket,
                    {"cmd": cmd, "args": args, "session": session},
                )


if __name__ == "__main__":
    asyncio.run(main())
