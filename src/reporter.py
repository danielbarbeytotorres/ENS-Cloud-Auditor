import csv
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path("templates")
HTML_OUTPUT_PATH = Path("output/audit_report.html")
CSV_OUTPUT_PATH = Path("output/audit_report.csv")


def generate_html_report(report):
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    template = env.get_template("report_template.html")
    html_content = template.render(report=report)

    HTML_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HTML_OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)

    return HTML_OUTPUT_PATH


def generate_csv_report(report):
    CSV_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "id", "status", "severity", "weight", "ens_code", "iso_27001",
        "aws_service", "title", "details", "affected_resources", "remediation_cli"
    ]

    with open(CSV_OUTPUT_PATH, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        for item in report["findings"]:
            writer.writerow({
                "id": item["id"],
                "status": item["status"],
                "severity": item["severity"],
                "weight": item["weight"],
                "ens_code": item["ens_code"],
                "iso_27001": item["iso_27001"],
                "aws_service": item["aws_service"],
                "title": item["title"],
                "details": item["details"],
                "affected_resources": ", ".join(item["affected_resources"]),
                "remediation_cli": item["remediation_cli"]
            })

    return CSV_OUTPUT_PATH


def generate_reports(report):
    html_path = generate_html_report(report)
    csv_path = generate_csv_report(report)
    return html_path, csv_path