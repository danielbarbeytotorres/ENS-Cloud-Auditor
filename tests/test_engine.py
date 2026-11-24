from html import escape
from pathlib import Path
from src.engine import run_audit
from src.reporter import generate_reports
from src.scanners.aws_scanner import _has_wildcard_admin


def test_mock_audit_scoring():
    """Verifica que el motor calcula correctamente la puntuación y conteos en modo mock."""
    report = run_audit(mock=True)
    summary = report["summary"]

    assert summary["total_controls"] == 8
    assert summary["passed"] == 5
    assert summary["failed"] == 3
    assert summary["errors"] == 0
    assert summary["compliance_score"] == 60.0


def test_domain_summary_breakdown():
    """Verifica que el motor desglosa correctamente el cumplimiento por dominio del ENS."""
    report = run_audit(mock=True)
    domains = {d["label"]: d for d in report["domain_summary"]}

    assert domains["Control de Acceso"]["score"] == 75.0
    assert domains["Protección de la Información"]["score"] == 100.0
    assert domains["Explotación"]["score"] == 0.0
    assert domains["Comunicaciones"]["score"] == 0.0


def test_html_report_generation_and_xss_autoescape():
    """Verifica que se genera el HTML con gráfica de dominios y autoescape activo frente a XSS."""
    report = run_audit(mock=True)
    html_path, _ = generate_reports(report)

    assert Path(html_path).exists()
    content = Path(html_path).read_text(encoding="utf-8")

    assert "Informe Ejecutivo de Cumplimiento ENS" in content
    assert "Cumplimiento por Dominio ENS" in content
    assert "domainChart" in content
    assert escape("<AUDIT_BUCKET>") in content


def test_csv_report_generation():
    """Verifica que se genera el CSV con la cabecera esperada."""
    report = run_audit(mock=True)
    _, csv_path = generate_reports(report)

    assert Path(csv_path).exists()
    content = Path(csv_path).read_text(encoding="utf-8-sig")

    assert "id;status;severity;weight;ens_code;iso_27001" in content
    assert "ENS-S3-01" in content


def test_wildcard_admin_detection():
    """Verifica la detección de políticas '*:*' en formato cadena, lista o dict único."""
    # Comodín como cadena simple
    assert _has_wildcard_admin({
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }) is True

    # Comodín dentro de listas
    assert _has_wildcard_admin({
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}]
    }) is True

    # Statement como diccionario único (no lista)
    assert _has_wildcard_admin({
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
    }) is True

    # Efecto Deny no debe disparar falso positivo
    assert _has_wildcard_admin({
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    }) is False

    # Política con mínimo privilegio
    assert _has_wildcard_admin({
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::mi-bucket/*"}]
    }) is False