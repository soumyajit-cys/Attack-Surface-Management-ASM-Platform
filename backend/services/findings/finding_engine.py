import asyncio
import json
import shutil
import subprocess

from utils.logger import logger


def generate_findings(
    open_ports: list,
    ssl_findings: list,
    header_findings: list,
) -> list:
    findings = []

    for port in open_ports:
        if port.get("status") == "open":
            severity = _port_severity(port.get("port"))
            findings.append({
                "title": f"Open Port {port.get('port')}",
                "severity": severity,
                "category": "network_exposure",
                "description": f"Port {port.get('port')} ({port.get('service', 'unknown')}) is open",
                "recommendation": "Ensure this port is intentionally exposed. Restrict access via firewall if not needed.",
            })

    for finding in ssl_findings:
        findings.append({
            "title": finding.get("title"),
            "severity": finding.get("severity", "medium"),
            "category": finding.get("category", "tls"),
            "description": finding.get("description"),
            "recommendation": finding.get("recommendation"),
        })

    for finding in header_findings:
        findings.append({
            "title": finding.get("title"),
            "severity": finding.get("severity", "medium"),
            "category": finding.get("category", "security_headers"),
            "description": finding.get("description"),
            "recommendation": finding.get("recommendation"),
        })

    return findings


def _port_severity(port: int) -> str:
    critical_ports = {21, 22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
    high_ports = {25, 53, 110, 111, 143, 465, 587, 993, 995, 1723, 5985, 5986, 8080, 8443, 9200, 9300}
    if port in critical_ports:
        return "critical"
    if port in high_ports:
        return "high"
    return "low"


async def run_nuclei_scan(target: str) -> list[dict]:
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        logger.debug("nuclei not found, skipping template-based scanning")
        return []

    try:
        cmd = [
            nuclei_path,
            "-target", target,
            "-json",
            "-silent",
            "-rate-limit", "50",
            "-timeout", "10",
            "-retries", "1",
            "-severity", "critical,high,medium,low,info",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        if proc.returncode != 0 and stderr:
            logger.debug("nuclei stderr: %s", stderr.decode().strip())

        findings = []
        for line in stdout.decode().strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(_map_nuclei_finding(data))
            except json.JSONDecodeError:
                continue
        return findings

    except asyncio.TimeoutError:
        logger.warning("nuclei scan timed out for %s", target)
        return []
    except Exception as exc:
        logger.warning("nuclei scan failed for %s: %s", target, exc)
        return []


def _map_nuclei_finding(data: dict) -> dict:
    info = data.get("info", {})
    severity = info.get("severity", "info").lower()
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return {
        "title": f"Nuclei: {info.get('name', 'Unknown')}",
        "severity": severity_map.get(severity, "info"),
        "category": "vulnerability",
        "description": info.get("description", data.get("matched-at", "")),
        "recommendation": info.get("remediation", "Review the finding and apply recommended fixes."),
        "nuclei_template": data.get("template-id"),
        "matched_at": data.get("matched-at"),
    }