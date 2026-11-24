from html import escape
from pathlib import Path
from src.engine import run_audit
from src.reporter import generate_reports


def test_mock_audit_scoring():
    """Verifica que el motor calcula correctamente la puntuación y conteos en modo mock."""
    report = run_audit(mock=True)
    summary = report["summary"]

    assert summary["total_controls"] == 8
    assert summary["passed"] == 5
    assert summary["failed"] == 3
    assert summary["errors"] == 0
    assert summary["compliance_score"] == 60.0


def test_html_report_generation_and_xss_autoescape():
    """Verifica que se genera el HTML y que Jinja2 escapa etiquetas como <AUDIT_BUCKET>."""
    report = run_audit(mock=True)
    html_path, _ = generate_reports(report)

    assert Path(html_path).exists()
    content = Path(html_path).read_text(encoding="utf-8")

    assert "Informe Ejecutivo de Cumplimiento ENS" in content
    assert escape("<AUDIT_BUCKET>") in content


def test_csv_report_generation():
    """Verifica que se genera el CSV con la cabecera esperada."""
    report = run_audit(mock=True)
    _, csv_path = generate_reports(report)

    assert Path(csv_path).exists()
    content = Path(csv_path).read_text(encoding="utf-8-sig")

    assert "id;status;severity;weight;ens_code;iso_27001" in content
    assert "ENS-S3-01" in content