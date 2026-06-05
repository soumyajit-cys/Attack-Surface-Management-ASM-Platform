def calculate_risk(
    exposure,
    severity,
    confidence
):

    score = (
        exposure *
        severity *
        confidence
    )

    score = min(score, 100)

    return score


