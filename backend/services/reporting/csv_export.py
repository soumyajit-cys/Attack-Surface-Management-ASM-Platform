import csv


def export_csv(
    path,
    findings
):

    with open(
        path,
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "title",
            "severity"
        ])

        for item in findings:

            writer.writerow([
                item["title"],
                item["severity"]
            ])


            