# Advanced Modern SSH Honeypot

## Overview
This is a modern, modular SSH honeypot built with Python. It simulates a realistic SSH server and logs unauthorized login attempts and attacker behavior for analysis. It is perfect for educational, research, and monitoring purposes.

## Features
- Realistic SSH Banner: Simulates OpenSSH to appear authentic.
- Dynamic Session Handling: Supports multiple simultaneous connections using threading.
- Fake Authentication: Allows attackers to attempt logins with fake credentials.
- Command Emulation: Responds to common Linux commands such as `ls`, `pwd`, and `uname`.
- IP Banning: Automatically bans IP addresses after a specified number of failed login attempts.
- JSON Logging: Logs all events in JSON format for easy parsing and analysis.
- Extensible Design: Easily add more commands or customize honeypot behavior.

## Setup and Installation

### Requirements
- Python 3.x


# How To use


---

How to Use the Advanced Modern SSH Honeypot

1. Requirements:
   - Python 3.x

2. Clone the Repository:

3. Install Dependencies:
   pip install threading

4. Run the Honeypot:
   sudo python3 modern_ssh_honeypot.py

   Note: Run as root if binding to a privileged port (e.g., port 22). For a non-privileged port (e.g., 2222), you don’t need root access.

5. Customize Fake Credentials:
   - Modify FAKE_CREDENTIALS in the modern_ssh_honeypot.py file to change usernames and passwords:
     FAKE_CREDENTIALS = {
         "root": "toor",
         "admin": "admin123",
         "user": "password"
     }

6. Customize Command Responses:
   - Modify COMMAND_RESPONSES in the modern_ssh_honeypot.py file to change the output for commands:
     COMMAND_RESPONSES = {
         "ls": "bin  boot  dev  etc  home  lib  usr  var",
         "pwd": "/root",
         "whoami": "root",
         "uname -a": "Linux ssh-honeypot 5.15.0-60-generic #66~20.04.1-Ubuntu SMP x86_64 GNU/Linux"
     }

7. Configure IP Banning:
   - Set MAX_LOGIN_ATTEMPTS and BANNED_DURATION in the modern_ssh_honeypot.py file to control IP banning behavior:
     MAX_LOGIN_ATTEMPTS = 5
     BANNED_DURATION = 600  # in seconds

8. Connect to the Honeypot:
   Use an SSH client to connect to the honeypot on port 2222 (or another port if configured):
   ssh user@<honeypot_ip> -p 2222

9. Log Files:
   - All events are logged in ssh_honeypot_logs.json. Logs include:
     - Timestamps
     - Event types (e.g., login success/failure, command execution)
     - Attacker IP addresses
     - Details of events (e.g., commands executed)

10. Examine Logs:
    The log file ssh_honeypot_logs.json will store all the captured events in JSON format. You can analyze it manually or automate parsing for deeper insights into attacker behavior.

11. Advanced Customization:
    - Add more commands to COMMAND_RESPONSES.
    - Integrate IP geolocation or threat intelligence.
    - Analyze captured sessions for attack profiling.

12. Legal Disclaimer:
    - For research and educational purposes only. Misuse may violate applicable laws.
    - Use in isolated environments to avoid exposing sensitive systems.
