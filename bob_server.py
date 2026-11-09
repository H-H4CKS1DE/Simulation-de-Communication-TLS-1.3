import socket
import ssl

HOST = "0.0.0.0"
PORT = 4433

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="bob.crt", keyfile="bob.key")
# Debug only: gives Wireshark the secrets needed to decrypt this lab session.
context.keylog_filename = "bob.keys"

with socket.create_server((HOST, PORT)) as server:
    print(f"Bob écoute sur {HOST}:{PORT}", flush=True)
    while True:
        raw_socket, address = server.accept()
        try:
            with context.wrap_socket(raw_socket, server_side=True) as tls_socket:
                print(
                    f"Client {address[0]} | {tls_socket.version()} | {tls_socket.cipher()}",
                    flush=True,
                )
                payload = tls_socket.recv(4096)
                tls_socket.sendall(b"Bob a recu : " + payload)
        except ssl.SSLError as exc:
            print(f"Échec TLS avec {address}: {exc}", flush=True)
