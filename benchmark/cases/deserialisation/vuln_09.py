# CWE-502: Insecure Deserialisation — pickle.loads() from socket recv()
# Vulnerability: data arrives from a network socket and is immediately
# unpickled without any integrity check.

import pickle
import socket
import struct


def receive_object(conn):
    """
    Receive a pickled object from a TCP connection.
    VULNERABLE: data from the network is unpickled without validation.
    """
    # Read 4-byte length prefix
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]

    # Read the payload
    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(min(4096, msg_len - len(data)))
        if not chunk:
            break
        data += chunk

    # VULNERABLE: unpickling network data — any connected client can achieve RCE
    obj = pickle.loads(data)
    return obj


def run_server(host="0.0.0.0", port=9999):
    """Simple object server — receives and deserialises objects."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"Listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        try:
            obj = receive_object(conn)
            print(f"Received: {obj}")
        finally:
            conn.close()


if __name__ == "__main__":
    print("Insecure pickle server — do not deploy in production")
    # run_server()  # commented out to avoid starting an actual server
