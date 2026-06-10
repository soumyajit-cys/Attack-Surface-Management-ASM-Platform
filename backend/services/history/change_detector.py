def detect_changes(
    previous,
    current
):

    changes = []

    previous_set = set(previous)
    current_set = set(current)

    added = current_set - previous_set
    removed = previous_set - current_set

    for item in added:
        changes.append({
            "type": "added",
            "value": item
        })

    for item in removed:
        changes.append({
            "type": "removed",
            "value": item
        })

    return changes


