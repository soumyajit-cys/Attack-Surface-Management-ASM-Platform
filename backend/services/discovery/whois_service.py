import whois


async def get_whois(domain):

    data = whois.whois(domain)

    return {
        "registrar": data.registrar,
        "creation_date": str(data.creation_date)
    }

