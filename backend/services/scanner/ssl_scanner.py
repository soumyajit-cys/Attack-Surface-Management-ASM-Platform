import ssl
import socket
from datetime import datetime


async def analyze_ssl(host):

    context = ssl.create_default_context()

    with socket.create_connection(
        (host, 443),
        timeout=5
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=host
        ) as secure_socket:

            cert = secure_socket.getpeercert()

            expiry = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            )

            tls_version = (
                secure_socket.version()
            )

            cipher = (
                secure_socket.cipher()[0]
            )

            issuer = cert["issuer"]

            return {
                "issuer": str(issuer),
                "cipher": cipher,
                "tls_version": tls_version,
                "expiry": expiry
            }
        


        