import argparse
import sys
from colorama import Fore, Style, init
from src.engine import run_audit

init(autoreset=True)


def print_banner():
    print(f"{Fore.CYAN}{Style.BRIGHT}" + "=" * 60)
    print("  ENS-Cloud-Auditor | Compliance-as-Code (RD 311/2022)")
    print("=" * 60 + f"{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Auditoría automatizada de AWS mapeada al ENS e ISO 27001.")
    parser.add_argument("--mock", action="store_true", help="Ejecuta en modo simulación sin credenciales AWS.")
    parser.add_argument("--profile", type=str, default=None, help="Perfil de AWS CLI a utilizar.")
    parser.add_argument("--region", type=str, default="eu-west-1", help="Región de AWS (por defecto eu-west-1).")
    parser.add_argument("--threshold", type=float, default=80.0, help="Umbral mínimo de cumplimiento (%%) para pasar.")
    args = parser.parse_args()

    print_banner()
    print(f"Modo: {Fore.YELLOW}{'MOCK' if args.mock else 'AWS LIVE'}{Style.RESET_ALL} | Región: {args.region}\n")

    report = run_audit(mock=args.mock, profile=args.profile, region=args.region)

    for f in report["findings"]:
        if f["status"] == "PASS":
            badge = f"{Fore.GREEN}[PASS]{Style.RESET_ALL}"
        elif f["status"] == "FAIL":
            badge = f"{Fore.RED}[FAIL]{Style.RESET_ALL}"
        else:
            badge = f"{Fore.YELLOW}[ERR ]{Style.RESET_ALL}"

        print(f"{badge} {f['id']} ({f['ens_code']}) - {f['title']}")
        if f["status"] != "PASS":
            print(f"       ↳ {Fore.LIGHTBLACK_EX}{f['details']}{Style.RESET_ALL}")

    s = report["summary"]
    score_color = Fore.GREEN if s["compliance_score"] >= args.threshold else Fore.RED

    print("\n" + "-" * 60)
    print(f"Puntuación de Cumplimiento ENS: {score_color}{Style.BRIGHT}{s['compliance_score']}%{Style.RESET_ALL} (Umbral: {args.threshold}%)")
    print(f"Controles: {Fore.GREEN}{s['passed']} PASS{Style.RESET_ALL} | {Fore.RED}{s['failed']} FAIL{Style.RESET_ALL} | {Fore.YELLOW}{s['errors']} ERROR{Style.RESET_ALL}")
    print(f"Resultados guardados en: {Fore.CYAN}output/audit_results.json{Style.RESET_ALL}")
    print("-" * 60)

    if s["compliance_score"] < args.threshold:
        print(f"\n{Fore.RED}[!] AUDITORÍA FALLIDA: El cumplimiento está por debajo del {args.threshold}%.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.GREEN}[✓] AUDITORÍA SUPERADA.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()