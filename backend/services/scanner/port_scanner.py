import asyncio
import json
import shutil

from utils.egress import (
    EgressBlocked,
    open_tcp_ip,
    resolve_validated_ips,
)
from utils.logger import logger

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    8080, 8443, 8888, 9000, 9200, 9300, 10000, 27017, 27018, 27019,
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "wsman", 5986: "wsman", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
}

BANNER_PORTS = frozenset({21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379})


async def _naabu_scan(ip: str) -> list[dict] | None:
    """naabu sweep of a validated IP literal (never a hostname)."""
    naabu_path = shutil.which("naabu")
    if not naabu_path:
        return None

    try:
        cmd = [
            naabu_path,
            "-host", ip,
            "-p", ",".join(str(p) for p in COMMON_PORTS),
            "-json",
            "-silent",
            "-rate", "1000",
            "-timeout", "3",
            "-retries", "1",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0 and stderr:
            logger.debug("naabu stderr: %s", stderr.decode().strip())

        results = []
        for line in stdout.decode().strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                port = data.get("port")
                if port:
                    results.append({
                        "port": port,
                        "status": "open",
                        "protocol": "tcp",
                        "service": SERVICE_MAP.get(port),
                    })
            except json.JSONDecodeError:
                continue
        return results
    except asyncio.TimeoutError:
        logger.warning("naabu scan timed out for %s", ip)
        return None
    except Exception as exc:
        logger.warning("naabu scan failed for %s: %s", ip, exc)
        return None


async def _socket_scan(ip: str) -> list[dict]:
    """TCP connect sweep of a validated IP literal (no resolution)."""

    async def check_port(port: int):
        try:
            _reader, writer = await open_tcp_ip(ip, port, timeout=2)
            writer.close()
            await writer.wait_closed()

            banner = None
            try:
                if port in BANNER_PORTS:
                    banner = await _grab_banner(ip, port)
            except Exception:
                pass

            return {
                "port": port,
                "status": "open",
                "protocol": "tcp",
                "service": SERVICE_MAP.get(port),
                "banner": banner,
            }
        except Exception:
            return {"port": port, "status": "closed", "protocol": "tcp"}

    tasks = [check_port(p) for p in COMMON_PORTS]
    return await asyncio.gather(*tasks)


async def _grab_banner(ip: str, port: int) -> str | None:
    try:
        reader, writer = await open_tcp_ip(ip, port, timeout=3)
        writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=2)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="ignore").strip()[:500]
    except Exception:
        return None


async def scan_ports(host: str) -> list[dict]:
    """Scan *host* after fail-closed resolution (raises ``EgressBlocked``).

    Every connection below goes to the validated IP: naabu receives the
    literal (no hostname for it to resolve) and the socket sweep connects
    per validated IP.
    """
    ips = resolve_validated_ips(host)
    ip = ips[0]
    naabu_results = await _naabu_scan(ip)
    if naabu_results is not None:
        return naabu_results
    return await _socket_scan(ip)
