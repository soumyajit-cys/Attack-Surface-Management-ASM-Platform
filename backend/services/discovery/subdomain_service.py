import requests


CRT_API = "https://crt.sh/?q=%25.{}&output=json"


async def discover_subdomains(domain):

    response = requests.get(
        CRT_API.format(domain),
        timeout=10
    )

    data = response.json()

    subdomains = set()

    for item in data:

        name = item.get("name_value")

        if name:

            subdomains.add(name)

    return list(subdomains)


