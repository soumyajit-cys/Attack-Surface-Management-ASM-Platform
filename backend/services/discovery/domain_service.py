import socket


async def resolve_domain(domain: str):

    ip = socket.gethostbyname(domain)

    return {
        "domain": domain,
        "ip": ip
    }