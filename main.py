#! /usr/bin/env python3
import asyncio
import websockets
import json
import ssl
from config import ip, port, is_secure, allow_self_signed


async def ainput(prompt: str = "") -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)

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
        
        if operation == "r":
            await websocket.send(json.dumps({"cmd": "register","username":user, "pass":password}))
            result_json = await websocket.recv()
            result = json.loads(result_json)
            if result["status"] == "ERROR":
                print("CLIent: Error registering user.")
                print(result_json)
                quit()
            else:
                print("OK")
                await websocket.send(json.dumps({"cmd": "login", "username":user, "pass":password}))
                result_json = await websocket.recv()
                result = json.loads(result_json)
                if result["status"] == "OK":
                    session = result["session"]
                else:
                    print("Error!")
                    print(result_json)
                    quit()
        elif operation == "l":
            await websocket.send(json.dumps({"cmd": "login", "username":user, "pass":password}))
            result_json = await websocket.recv()
            result = json.loads(result_json)
            if result["status"] == "OK":
                session = result["session"]
            else:
                print("Error!")
                print(result_json)
                quit()
        running = True
        while running:
            command = (await ainput("> ")).strip()
            if command == "":
                continue
            # If input does NOT start with '/', treat it as message content to send
            if not command.startswith('/'):
                content = command
                await websocket.send(json.dumps({"cmd": "send", "content": content, "session":session}))
                response = await websocket.recv()
                data = json.loads(response)
                for msg in data.get("messages", []):
                    print(f"{msg['user']}: {msg['content']}")
                continue

            # Commands must start with '/', e.g. '/help', '/list', '/send', '/exit'
            cmd = command[1:]
            if cmd == "help":
                print("CLIent commands:")
                print("/help - command list")
                print("/list - list messages")
                print("/send - sends a message (or type message without leading '/')")
                print("/exit - exit")
            elif cmd == "list":
                await websocket.send(json.dumps({"cmd": "list"}))
                response = await websocket.recv()
                data = json.loads(response)
                for msg in data.get("messages", []):
                    print(f"{msg['user']}: {msg['content']}")
            elif cmd == "send":
                content = (await ainput("  Content?> ")).strip()
                await websocket.send(json.dumps({"cmd": "send", "content": content, "session":session}))
                response = await websocket.recv()
                data = json.loads(response)
                for msg in data.get("messages", []):
                    print(f"{msg['user']}: {msg['content']}")
            elif cmd == "exit":
                print("Exiting...")
                running = False
            else:
                print("Unknown command. Type '/help'.")

if __name__ == "__main__":
    asyncio.run(main())
