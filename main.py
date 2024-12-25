import socket
import threading
import json
import time
from datetime import datetime

HOST = "0.0.0.0"
PORT = 2222
LOG_FILE = "ssh_honeypot_logs.json"
BANNED_IPS = {}
BANNED_DURATION = 600  # in seconds
MAX_LOGIN_ATTEMPTS = 5

FAKE_CREDENTIALS = {
    "root": "toor",
    "admin": "admin123",
    "user": "password"
}

COMMAND_RESPONSES = {
    "ls": "bin  boot  dev  etc  home  lib  usr  var",
    "pwd": "/root",
    "whoami": "root",
    "uname -a": "Linux ssh-honeypot 5.15.0-60-generic #66~20.04.1-Ubuntu SMP x86_64 GNU/Linux",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash"
}


def log_event(event_type, ip, details=None):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "ip": ip,
        "details": details or {}
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def is_ip_banned(ip):
    if ip in BANNED_IPS:
        if time.time() - BANNED_IPS[ip] > BANNED_DURATION:
            del BANNED_IPS[ip]
            return False
        return True
    return False


def ban_ip(ip):
    BANNED_IPS[ip] = time.time()
    log_event("ban", ip, {"reason": "too many failed login attempts"})


def handle_authentication(client_socket, ip):
    attempts = 0
    while attempts < MAX_LOGIN_ATTEMPTS:
        client_socket.send(b"login: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"password: ")
        password = client_socket.recv(1024).decode().strip()

        if username in FAKE_CREDENTIALS and FAKE_CREDENTIALS[username] == password:
            log_event("login_success", ip, {"username": username})
            client_socket.send(b"Welcome to the system!\n")
            return True

        attempts += 1
        log_event("login_failure", ip, {"username": username, "attempt": attempts})
        client_socket.send(b"Login incorrect.\n")

    ban_ip(ip)
    client_socket.send(b"Too many failed attempts. Connection closed.\n")
    return False


def handle_session(client_socket, ip):
    while True:
        client_socket.send(b"$ ")
        command = client_socket.recv(1024).decode().strip()

        if command in COMMAND_RESPONSES:
            client_socket.send(f"{COMMAND_RESPONSES[command]}\n".encode())
            log_event("command", ip, {"command": command, "response": COMMAND_RESPONSES[command]})
        elif command.lower() == "exit":
            log_event("session_end", ip)
            client_socket.send(b"Connection closed.\n")
            break
        else:
            client_socket.send(b"Command not found.\n")
            log_event("command_unknown", ip, {"command": command})


def handle_client(client_socket, ip):
    if is_ip_banned(ip):
        client_socket.send(b"Connection refused. Your IP is banned.\n")
        client_socket.close()
        return

    client_socket.send(b"SSH-2.0-OpenSSH_8.6p1 Ubuntu-6\n")
    log_event("connection_attempt", ip)

    if handle_authentication(client_socket, ip):
        handle_session(client_socket, ip)

    client_socket.close()


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Honeypot listening on {HOST}:{PORT}")
    log_event("honeypot_start", HOST)

    while True:
        client_socket, addr = server.accept()
        ip = addr[0]
        threading.Thread(target=handle_client, args=(client_socket, ip)).start()

if __name__ == "__main__":
    start_honeypot()
