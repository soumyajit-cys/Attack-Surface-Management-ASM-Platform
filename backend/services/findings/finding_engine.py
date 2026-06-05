def generate_findings(
    open_ports,
    ssl_risk,
    header_findings
):

    findings = []

    if ssl_risk == "critical":

        findings.append({
            "title":
            "SSL Certificate Expiring Soon",
            "severity":
            "critical"
        })

    for finding in header_findings:

        findings.append({
            "title": finding,
            "severity": "medium"
        })

    for port in open_ports:

        if port["status"] == "open":

            findings.append({
                "title":
                f"Open Port {port['port']}",
                "severity":
                "low"
            })

    return findings


