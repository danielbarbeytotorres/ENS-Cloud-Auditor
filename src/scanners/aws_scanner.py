import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def run_mock_scan():
    """Simula una auditoría sobre una cuenta AWS con algunos fallos realistas."""
    return {
        "ENS-S3-01": {
            "status": "FAIL",
            "details": "1 bucket sin Block Public Access completo.",
            "affected_resources": ["atlantico-cloud-public-assets"]
        },
        "ENS-S3-02": {
            "status": "PASS",
            "details": "Todos los buckets tienen cifrado por defecto habilitado.",
            "affected_resources": []
        },
        "ENS-IAM-01": {
            "status": "PASS",
            "details": "La cuenta Root dispone de MFA activo.",
            "affected_resources": []
        },
        "ENS-IAM-02": {
            "status": "PASS",
            "details": "Política de contraseñas cumple >= 14 caracteres y complejidad.",
            "affected_resources": []
        },
        "ENS-IAM-03": {
            "status": "PASS",
            "details": "No se detectaron políticas gestionadas con permisos '*:*'.",
            "affected_resources": []
        },
        "ENS-CT-01": {
            "status": "FAIL",
            "details": "No hay ningún Trail multirregión registrando eventos actualmente.",
            "affected_resources": ["Account-CloudTrail"]
        },
        "ENS-VPC-01": {
            "status": "FAIL",
            "details": "Puerto 22 (SSH) expuesto a 0.0.0.0/0 en un Security Group.",
            "affected_resources": ["sg-0a1b2c3d4e5f67890 (web-prod-sg)"]
        },
        "ENS-EBS-01": {
            "status": "PASS",
            "details": "Cifrado por defecto de volúmenes EBS habilitado en la región.",
            "affected_resources": []
        }
    }


def run_aws_scan(profile=None, region="eu-west-1"):
    """Ejecuta los checks reales contra AWS usando boto3."""
    session = boto3.Session(profile_name=profile, region_name=region)
    results = {}

    # 1. S3 Checks (ENS-S3-01 y ENS-S3-02)
    try:
        s3 = session.client("s3")
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        public_buckets = []
        unencrypted_buckets = []

        for bucket in buckets:
            # Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if not all(pab.values()):
                    public_buckets.append(bucket)
            except ClientError:
                public_buckets.append(bucket)

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket)
            except ClientError:
                unencrypted_buckets.append(bucket)

        results["ENS-S3-01"] = {
            "status": "FAIL" if public_buckets else "PASS",
            "details": f"{len(public_buckets)} bucket(s) sin bloqueo público completo." if public_buckets else "Todos los buckets bloquean acceso público.",
            "affected_resources": public_buckets
        }
        results["ENS-S3-02"] = {
            "status": "FAIL" if unencrypted_buckets else "PASS",
            "details": f"{len(unencrypted_buckets)} bucket(s) sin cifrado por defecto." if unencrypted_buckets else "Todos los buckets están cifrados.",
            "affected_resources": unencrypted_buckets
        }
    except (ClientError, NoCredentialsError) as e:
        for cid in ("ENS-S3-01", "ENS-S3-02"):
            results[cid] = {"status": "ERROR", "details": str(e), "affected_resources": []}

    # 2. IAM Checks (ENS-IAM-01, ENS-IAM-02, ENS-IAM-03)
    try:
        iam = session.client("iam")
        # Root MFA
        summary = iam.get_account_summary()["SummaryMap"]
        root_mfa = summary.get("AccountMFAEnabled", 0) == 1
        results["ENS-IAM-01"] = {
            "status": "PASS" if root_mfa else "FAIL",
            "details": "MFA activo en Root." if root_mfa else "La cuenta Root NO tiene MFA activado.",
            "affected_resources": [] if root_mfa else ["AWS-Root-Account"]
        }

        # Password Policy
        try:
            pol = iam.get_account_password_policy()["PasswordPolicy"]
            strong = (
                pol.get("MinimumPasswordLength", 0) >= 14
                and pol.get("RequireSymbols", False)
                and pol.get("RequireNumbers", False)
                and pol.get("RequireUppercaseCharacters", False)
                and pol.get("RequireLowercaseCharacters", False)
            )
            results["ENS-IAM-02"] = {
                "status": "PASS" if strong else "FAIL",
                "details": "Política de contraseñas robusta." if strong else "La política de contraseñas no cumple los requisitos mínimos del ENS.",
                "affected_resources": [] if strong else ["IAM-Password-Policy"]
            }
        except ClientError:
            results["ENS-IAM-02"] = {
                "status": "FAIL",
                "details": "No existe una política de contraseñas configurada.",
                "affected_resources": ["IAM-Password-Policy"]
            }

        # Overly permissive policies (*:*)
        risky_policies = []
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        for p in policies:
            ver = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
            stmts = ver["PolicyVersion"]["Document"].get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for s in stmts:
                if s.get("Effect") == "Allow" and s.get("Action") == "*" and s.get("Resource") == "*":
                    risky_policies.append(p["PolicyName"])
                    break

        results["ENS-IAM-03"] = {
            "status": "FAIL" if risky_policies else "PASS",
            "details": f"{len(risky_policies)} política(s) con permisos '*:*'." if risky_policies else "Sin políticas locales con permisos totales.",
            "affected_resources": risky_policies
        }
    except (ClientError, NoCredentialsError) as e:
        for cid in ("ENS-IAM-01", "ENS-IAM-02", "ENS-IAM-03"):
            results[cid] = {"status": "ERROR", "details": str(e), "affected_resources": []}

    # 3. CloudTrail Check (ENS-CT-01)
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        active_multi = False
        for t in trails:
            if t.get("IsMultiRegionTrail"):
                status = ct.get_trail_status(Name=t["TrailARN"])
                if status.get("IsLogging"):
                    active_multi = True
                    break
        results["ENS-CT-01"] = {
            "status": "PASS" if active_multi else "FAIL",
            "details": "Trail multirregión activo." if active_multi else "No hay ningún Trail multirregión registrando eventos.",
            "affected_resources": [] if active_multi else ["Account-CloudTrail"]
        }
    except (ClientError, NoCredentialsError) as e:
        results["ENS-CT-01"] = {"status": "ERROR", "details": str(e), "affected_resources": []}

    # 4. VPC Security Groups Check (ENS-VPC-01)
    try:
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed_sgs = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")
                if from_p is not None and to_p is not None:
                    if (from_p <= 22 <= to_p) or (from_p <= 3389 <= to_p):
                        cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                        cidrs_v6 = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                        if "0.0.0.0/0" in cidrs or "::/0" in cidrs_v6:
                            exposed_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                            break
        results["ENS-VPC-01"] = {
            "status": "FAIL" if exposed_sgs else "PASS",
            "details": f"{len(exposed_sgs)} Security Group(s) con SSH/RDP expuesto a Internet." if exposed_sgs else "Sin puertos críticos expuestos a Internet.",
            "affected_resources": exposed_sgs
        }

        # 5. EBS Default Encryption (ENS-EBS-01)
        ebs_enc = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
        results["ENS-EBS-01"] = {
            "status": "PASS" if ebs_enc else "FAIL",
            "details": "Cifrado EBS por defecto activo." if ebs_enc else "Cifrado EBS por defecto desactivado en la región.",
            "affected_resources": [] if ebs_enc else [f"EC2-Region-{region}"]
        }
    except (ClientError, NoCredentialsError) as e:
        for cid in ("ENS-VPC-01", "ENS-EBS-01"):
            results[cid] = {"status": "ERROR", "details": str(e), "affected_resources": []}

    return results