import os
import socket
import ssl

SERVER_IP = os.environ.get("TLS_SERVER_IP", "IP_BOB")
TLS_SERVER_NAME = os.environ.get("TLS_SERVER_NAME", "bob.lab")
CA_FILE = os.environ.get("TLS_CA_FILE", "ca.crt")
PORT = 4433

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
# Debug only: keep this file inside the lab; it decrypts this session in Wireshark.
context.keylog_filename = "alice.keys"

try:
    with socket.create_connection((SERVER_IP, PORT), timeout=5) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=TLS_SERVER_NAME) as tls_socket:
            print("Version :", tls_socket.version())
            print("Suite   :", tls_socket.cipher())
            tls_socket.sendall(b"Bonjour Alice")
            print("Réponse :", tls_socket.recv(4096).decode("utf-8", errors="replace"))
except ssl.SSLCertVerificationError as exc:
    print("ÉCHEC DE VÉRIFICATION :", exc.verify_message, f"(code {exc.verify_code})")
except (OSError, ssl.SSLError) as exc:
    print("ÉCHEC DE CONNEXION TLS :", exc)
