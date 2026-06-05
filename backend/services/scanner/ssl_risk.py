from datetime import datetime


def evaluate_ssl(result):

    remaining = (
        result["expiry"] - datetime.utcnow()
    ).days

    if remaining < 7:
        return "critical"

    if remaining < 30:
        return "high"

    if remaining < 90:
        return "medium"

    return "low"



