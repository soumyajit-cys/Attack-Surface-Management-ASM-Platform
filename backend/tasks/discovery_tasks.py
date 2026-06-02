from services.discovery.domain_service import (
    resolve_domain
)

from services.discovery.dns_service import (
    enumerate_dns
)

from services.discovery.subdomain_service import (
    discover_subdomains
)

from services.discovery.whois_service import (
    get_whois
)


async def run_discovery(domain):

    resolved = await resolve_domain(domain)

    dns_records = await enumerate_dns(domain)

    subdomains = await discover_subdomains(domain)

    whois_data = await get_whois(domain)

    return {
        "resolved": resolved,
        "dns": dns_records,
        "subdomains": subdomains,
        "whois": whois_data
    }


