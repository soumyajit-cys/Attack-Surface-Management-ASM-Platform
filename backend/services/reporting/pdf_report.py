from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)


def generate_pdf(
    path,
    findings
):

    doc = SimpleDocTemplate(path)

    content = []

    content.append(
        Paragraph(
            "SentinelASM Report"
        )
    )

    content.append(
        Spacer(1, 12)
    )

    for finding in findings:

        content.append(
            Paragraph(
                finding["title"]
            )
        )

    doc.build(content)