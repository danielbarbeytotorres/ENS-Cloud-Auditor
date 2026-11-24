import json
from datetime import datetime, timezone
from pathlib import Path
from src.scanners.aws_scanner import run_aws_scan, run_mock_scan

CONFIG_PATH = Path("config/ens_controls.json")
OUTPUT_JSON_PATH = Path("output/audit_results.json")


def run_audit(mock=False, profile=None, region="eu-west-1"):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)

    scan_results = run_mock_scan() if mock else run_aws_scan(profile=profile, region=region)

    findings = []
    total_weight = 0
    earned_weight = 0
    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0}
    domain_stats = {}

    for control in config["controls"]:
        cid = control["id"]
        res = scan_results.get(cid, {
            "status": "ERROR",
            "details": "Control no evaluado por el escáner.",
            "affected_resources": []
        })

        status = res["status"]
        counts[status] = counts.get(status, 0) + 1

        weight = control["weight"]
        total_weight += weight
        if status == "PASS":
            earned_weight += weight

        domain = control.get("ens_domain", "Otros")
        if domain not in domain_stats:
            domain_stats[domain] = {
                "domain": domain,
                "label": domain.split(" - ")[-1].strip(),
                "total_weight": 0,
                "earned_weight": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "total": 0
            }

        d = domain_stats[domain]
        d["total"] += 1
        d["total_weight"] += weight
        if status == "PASS":
            d["passed"] += 1
            d["earned_weight"] += weight
        elif status == "FAIL":
            d["failed"] += 1
        else:
            d["errors"] += 1

        findings.append({
            **control,
            "status": status,
            "details": res["details"],
            "affected_resources": res["affected_resources"]
        })

    compliance_score = round((earned_weight / total_weight) * 100, 2) if total_weight > 0 else 0.0

    domain_summary = []
    for d in domain_stats.values():
        score = round((d["earned_weight"] / d["total_weight"]) * 100, 2) if d["total_weight"] > 0 else 0.0
        domain_summary.append({
            "domain": d["domain"],
            "label": d["label"],
            "score": score,
            "passed": d["passed"],
            "failed": d["failed"],
            "errors": d["errors"],
            "total": d["total"]
        })

    report = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mode": "MOCK (Simulación)" if mock else f"AWS LIVE ({region})",
        "metadata": config["metadata"],
        "summary": {
            "compliance_score": compliance_score,
            "total_controls": len(findings),
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "errors": counts["ERROR"]
        },
        "domain_summary": domain_summary,
        "findings": findings
    }

    OUTPUT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report