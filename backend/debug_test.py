import asyncio, sys
sys.path.insert(0, '.')
from scanner_modules.subdomain_takeover import subdomain_takeover_module
from app.scanning.context import ScanContext
from unittest.mock import patch

def fake_resolve(qname, rdtype, lifetime):
    qs = str(qname).rstrip('.').lower()
    if rdtype == 'CNAME':
        if qs == 'www.example.com':
            class A:
                def to_text(self): return 'github.io.'
                @property
                def target(self): return self
            return [A()]
    if qs == 'github.io' and rdtype == 'A':
        class A2:
            def to_text(self): return '1.2.3.4'
        return [A2()]
    raise dns.resolver.NoAnswer()

import dns.resolver
with patch('dns.resolver.resolve', side_effect=fake_resolve):
    import httpx
    def fake_get(self, url, headers=None, **kwargs):
        h = headers.get("Host", "") if headers else ""
        h = h.lower().rstrip(".")
        print(f"HTTP GET: {url}, Host: {h}")
        if h == 'github.io':
            class R:
                status_code = 200
                text = "There isn't a GitHub Pages site here"
            return R()
        class R2:
            status_code = 404
            text = "Not Found"
        return R2()
    with patch('httpx.Client.get', fake_get):
        def fake_resolve_validated_ips(host, port=80):
            return ["93.184.216.34"]
        import utils.egress
        with patch("utils.egress.resolve_validated_ips", fake_resolve_validated_ips):
            ctx = ScanContext(
                domain="www.example.com",
                pinned_ip="93.184.216.34",
                org_id=1,
                scan_id=1,
                db=None,
                scope="full",
                subdomains=["www.example.com"]
            )
            result = asyncio.run(subdomain_takeover_module(ctx))
            print("Findings:", result["findings"])
PYEOF
