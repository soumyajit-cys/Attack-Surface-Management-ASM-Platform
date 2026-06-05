import asyncio
import socket

COMMON_PORTS = [
    22,
    80,
    443,
    8080,
    3306,
    5432,
    6379
]


async def check_port(host, port):

    try:
        conn = asyncio.open_connection(
            host,
            port
        )

        reader, writer = await asyncio.wait_for(
            conn,
            timeout=3
        )

        writer.close()

        await writer.wait_closed()

        return {
            "port": port,
            "status": "open"
        }

    except Exception:

        return {
            "port": port,
            "status": "closed"
        }


async def scan_ports(host):

    tasks = [
        check_port(host, p)
        for p in COMMON_PORTS
    ]

    return await asyncio.gather(*tasks)


