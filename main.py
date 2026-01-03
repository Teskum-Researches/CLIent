#! /usr/bin/env python3
import asyncio
import websockets
import json
import ssl
from config import ip, port, is_secure, allow_self_signed


async def ainput(prompt: str = "") -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)

async def hello():
    uri = f"{'wss' if is_secure else 'ws'}://{ip}:{port}/ws"
    ssl_context = ssl.create_default_context()
    if allow_self_signed:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  
    if not is_secure:
        ssl_context = None
    async with websockets.connect(uri, ping_interval=20, ping_timeout=10, ssl=ssl_context) as websocket:
        print("Register/login[r,l]")
        operation = (await ainput("> ")).strip()
        print("Username")
        user = (await ainput("> ")).strip()
        print("Password")
        password = (await ainput("> ")).strip()
        
        if operation == "r":
            await websocket.send(json.dumps({"cmd": "register","username":user, "pass":password}))
            result_json = await websocket.recv()
            result = json.loads(result_json)
            if result["status"] == "ERROR":
                print("Error!")
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
            command = (await ainput("command> ")).strip()
            if command == "help":
                print("Teskum chat 1.0")
                print("help - command list")
                print("list - list messages")
                print("send - sends a message")
                print("exit - exit")
            elif command == "list":
                await websocket.send(json.dumps({"cmd": "list"}))
                response = await websocket.recv()
                data = json.loads(response)
                for msg in data.get("messages", []):
                    print(f"{msg['user']}: {msg['content']}")
            elif command == "send":
                content = (await ainput("  Content?> ")).strip()
                await websocket.send(json.dumps({"cmd": "send", "content": content, "session":session}))
                response = await websocket.recv()
                data = json.loads(response)
                for msg in data.get("messages", []):
                    print(f"{msg['user']}: {msg['content']}")
            elif command == "exit":
                print("Exiting...")
                running = False
            else:
                print("Unknown command. Type 'help'.")

if __name__ == "__main__":
    asyncio.run(hello())
