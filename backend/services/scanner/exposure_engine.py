from services.scanner.port_scanner import (
    scan_ports
)

from services.scanner.ssl_scanner import (
    analyze_ssl
)

from services.scanner.ssl_risk import (
    evaluate_ssl
)

from services.scanner.header_scanner import (
    analyze_headers
)

from services.findings.finding_engine import (
    generate_findings
)


async def analyze(host):

    ports = await scan_ports(host)

    ssl_result = (
        await analyze_ssl(host)
    )

    ssl_risk = (
        evaluate_ssl(ssl_result)
    )

    headers = (
        await analyze_headers(
            f"https://{host}"
        )
    )

    findings = generate_findings(
        ports,
        ssl_risk,
        headers
    )

    return {
        "ports": ports,
        "ssl": ssl_result,
        "ssl_risk": ssl_risk,
        "findings": findings
    }