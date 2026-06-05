SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    8080: "http-alt",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis"
}


def identify(port):

    return SERVICE_MAP.get(
        port,
        "unknown"
    )


