import socket

def run_client():
    host = 'localhost'
    port = 12345

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((host, port))
    print('Connected to server:', host, port)

    while True:
        # Send data to the server
        message = input("Enter a message (or 'quit' to exit): ")
        client_socket.send(message.encode('utf-8'))

        if message == 'quit':
            break

    # Close the connection
    client_socket.close()

run_client()