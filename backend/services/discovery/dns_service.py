import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "TXT",
    "NS",
    "CNAME"
]


async def enumerate_dns(domain):

    results = []

    for record_type in RECORD_TYPES:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type
            )

            for answer in answers:

                results.append({
                    "type": record_type,
                    "value": str(answer)
                })

        except Exception:
            pass

    return results


