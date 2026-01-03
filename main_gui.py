import tkinter as tk
import threading
import websocket
import queue
from config import is_secure, ip, port, allow_self_signed
import json

pending_response = None      
response_callback = None     
session = None
can_work = False
messages = queue.Queue()
to_send = queue.Queue()
is_running = True

def on_closing():
    global is_running
    is_running = False
    root.destroy()

def send_command(cmd, callback):
    global pending_response, response_callback
    pending_response = "login"
    response_callback = callback
    
    to_send.put(cmd)
    log(">" + cmd)

def on_login():
    user = user_entry.get()
    password = password_entry.get()
    cmd = json.dumps({"cmd": "login", "username":user, "pass":password})
    send_command(cmd, handle_login_response)

def handle_login_response(msg):
    global session, can_work
    log("<" + msg)
    data = json.loads(msg)
    if data["status"] == "ERROR":
        log("Login error! Check login and password.")
        log("Error: " + data["error"])
    else:
        log("Login OK")
        session = data["session"]
        log("Session: " + session)
        can_work = True

def on_register():
    log("register button")

def on_send():
    message = message_entry.get()
    cmd = json.dumps({"cmd": "send", "content": message, "session":session})
    send_command(cmd, handle_send_response)

def handle_send_response(msg):
    log(msg)
    data = json.loads(msg)
    for i in data["messages"]:
        log(f"{i["user"]}: {i["content"]}")

def log(message):
    print(message)
    listbox.insert(tk.END, message) # tk.END добавляет в конец

# Создаем главное окно
root = tk.Tk()
root.title("Teskum chat")
root.geometry("410x480")

# Привязываем событие закрытия окна к нашей функции
root.protocol("WM_DELETE_WINDOW", on_closing)


user_label = tk.Label(root, text="Имя пользователя")
user_label.place(x=0, y=0)
user_entry = tk.Entry(root)
user_entry.place(x=120, y=0, width=200)

password_label = tk.Label(root, text="Пароль")
password_label.place(x=0, y=25)
password_entry = tk.Entry(root)
password_entry.place(x=120, y=25, width=200)

message_entry = tk.Entry(root)
message_entry.place(x=0, y=455, width=395-40)

send_button = tk.Button(root, text="send", command=on_send)
send_button.place(x=395-40,y=455,width=40)

login_button = tk.Button(root, text="login", command=on_login)
login_button.place(x=335, y=0)

register_button = tk.Button(root, text="register", command=on_register)
register_button.place(x=335, y=25)

scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = tk.Listbox(root, height=25, width=65)
listbox.place(y=25*2, x=0)

scrollbar.config(command=listbox.yview)

def check_messages():
    global pending_response, response_callback
    try:
        while not messages.empty():
            msg = messages.get()
            
            if pending_response is not None:
                if response_callback:
                    response_callback(msg)
                pending_response = None
                response_callback = None
            else:
                log(msg)
    except Exception as e:
        log("Error!")
        log(e)
    
    root.after(50, check_messages)

def ws_worker():
    ws = websocket.WebSocket()
    ws.connect(f"ws://{ip}:{port}")
    ws.settimeout(0.5) 
    while True:
        try:
            msg = ws.recv()
            messages.put(msg)
        except websocket.WebSocketTimeoutException:
            pass
        except:
            log("Error!")
            break

        try:
            msg_out = to_send.get_nowait()
            ws.send(msg_out)
        except queue.Empty:
            pass


check_messages() 

threading.Thread(target=ws_worker, daemon=True).start()

# Запуск главного цикла
while is_running:
    root.update()