import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(("127.0.0.1", 8080))
server.listen(5)

print("Test server running on port 8080...")

while True:
    client, address = server.accept()

    request = client.recv(1024)

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.58\r\n"
        b"Content-Length: 12\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"Hello World!"
    )

    client.sendall(response)
    client.close()