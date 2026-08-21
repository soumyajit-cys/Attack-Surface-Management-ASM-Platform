import asyncio
import socket
import requests

from utils.logger import logger

CRT_API = "https://crt.sh/?q=%25.{}&output=json"

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns1", "dns2", "dns3", "dns4", "mx1", "mx2", "mx3", "mx4",
    "test", "staging", "dev", "api", "admin", "app", "blog", "shop", "store",
    "support", "help", "docs", "wiki", "forum", "community", "status", "monitor",
    "vpn", "remote", "portal", "secure", "ssl", "cdn", "static", "assets", "media",
    "images", "img", "video", "stream", "live", "demo", "sandbox", "beta", "alpha",
    "prod", "production", "stage", "preprod", "uat", "qa", "ci", "jenkins", "gitlab",
    "github", "bitbucket", "jira", "confluence", "wiki", "redmine", "svn", "cvs",
    "backup", "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
    "kibana", "grafana", "prometheus", "alertmanager", "nginx", "apache", "iis",
    "tomcat", "jetty", "weblogic", "websphere", "jboss", "wildfly", "glassfish",
    "docker", "k8s", "kubernetes", "swarm", "mesos", "nomad", "consul", "vault",
    "registry", "harbor", "nexus", "artifactory", "jenkins", "gitlab-ci", "drone",
    "build", "deploy", "release", "artifact", "package", "npm", "maven", "gradle",
    "pip", "pypi", "composer", "nuget", "gem", "cargo", "go", "vendor", "third-party",
    "external", "internal", "private", "public", "dmz", "intranet", "extranet",
    "partner", "vendor", "client", "customer", "user", "member", "employee", "staff",
    "hr", "finance", "accounting", "legal", "marketing", "sales", "support", "engineering",
    "research", "development", "security", "compliance", "audit", "risk", "governance",
]


async def discover_subdomains(domain):
    subdomains = set()
    sources = {}

    crt_subs = await _crt_sh_discovery(domain)
    for sub in crt_subs:
        subdomains.add(sub)
        sources[sub] = "crt.sh"

    if len(subdomains) < 50:
        brute_subs = await _dns_brute_force(domain)
        for sub in brute_subs:
            if sub not in subdomains:
                sources[sub] = "dns_brute"
            subdomains.add(sub)

    result = []
    for sub in sorted(subdomains):
        result.append({
            "subdomain": sub,
            "source": sources.get(sub, "unknown"),
        })

    return result


async def _crt_sh_discovery(domain):
    try:
        response = requests.get(
            CRT_API.format(domain),
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.warning("crt.sh discovery failed for %s: %s", domain, exc)
        return []

    subdomains = set()
    for item in data:
        name = item.get("name_value")
        if name:
            for entry in name.split("\n"):
                entry = entry.strip().lower().rstrip(".")
                if entry and "*" not in entry:
                    subdomains.add(entry)
    return list(subdomains)


async def _dns_brute_force(domain):
    semaphore = asyncio.Semaphore(50)

    async def resolve_one(prefix):
        async with semaphore:
            fqdn = f"{prefix}.{domain}"
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                return fqdn
            except Exception:
                return None

    tasks = [resolve_one(prefix) for prefix in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def resolve_subdomain_ips(subdomain):
    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None)
        ips = set()
        for addr in addrs:
            ip = addr[4][0]
            if not ip.startswith("fe80") and not ip.startswith("127."):
                ips.add(ip)
        return list(ips)
    except Exception as exc:
        logger.warning("Failed to resolve IPs for %s: %s", subdomain, exc)
        return []