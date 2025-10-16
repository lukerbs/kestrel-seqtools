#!/usr/bin/env python3
"""
TCP Command Sender
This program listens for incoming connections and sends commands to execute.
"""

import socket
import sys

# Configuration
DEFAULT_HOST = "0.0.0.0"  # Listen on all interfaces
DEFAULT_PORT = 5555  # Port number
BUFFER_SIZE = 4096  # Socket buffer size
END_MARKER = "<<<END_OF_OUTPUT>>>"  # Command completion marker


def start_sender(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """
    Start the TCP command sender server.

    Args:
        host: The host address to bind to (0.0.0.0 means all available interfaces)
        port: The port number to listen on
    """
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow reuse of address to avoid "Address already in use" errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Bind the socket to the host and port
        server_socket.bind((host, port))

        # Listen for incoming connections (max 1 queued connection)
        server_socket.listen(1)

        print(f"Listening on {host}:{port}")
        print("Waiting for client to connect...\n")

        # Main server loop - accept multiple clients sequentially
        while True:
            # Accept a connection
            client_socket, client_address = server_socket.accept()
            print(f"Connected: {client_address[0]}:{client_address[1]}")
            print("Ready to send commands (Ctrl+C to exit)\n")

            # Continuously read user input and send commands
            try:
                while True:
                    try:
                        # Get command from user
                        command = input("command> ")

                        # Skip empty commands
                        if not command.strip():
                            continue

                        # Send the command
                        client_socket.sendall(command.encode("utf-8"))
                        print()

                        # Receive and display streaming output
                        while True:
                            try:
                                data = client_socket.recv(BUFFER_SIZE)
                                if not data:
                                    print("\nConnection lost")
                                    raise ConnectionResetError("Client disconnected")

                                chunk = data.decode("utf-8")

                                # Check for end marker
                                if END_MARKER in chunk:
                                    # Print only the part before the marker
                                    output = chunk.split(END_MARKER)[0]
                                    if output:
                                        sys.stdout.write(output)
                                        sys.stdout.flush()
                                    break

                                # Print output as it arrives (already line-by-line from receiver)
                                sys.stdout.write(chunk)
                                sys.stdout.flush()

                            except Exception as e:
                                print(f"\nError: {e}")
                                break

                    except KeyboardInterrupt:
                        print("\n\nExiting...")
                        raise  # Re-raise to exit server loop
                    except BrokenPipeError:
                        print("\nConnection closed by receiver")
                        break
                    except ConnectionResetError:
                        break
                    except Exception as e:
                        print(f"\nError: {e}")
                        break

            finally:
                # Clean up client connection
                client_socket.close()
                print("\nWaiting for next client to connect...\n")

    except KeyboardInterrupt:
        print("\n\nExiting...")
    except OSError as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        server_socket.close()


if __name__ == "__main__":
    print("\n[ TCP Command Sender ]\n")
    start_sender(DEFAULT_HOST, DEFAULT_PORT)
