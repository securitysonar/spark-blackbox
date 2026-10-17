import socket
import ssl

def secure(sock: socket.socket):
    return ssl.wrap_socket(sock)
