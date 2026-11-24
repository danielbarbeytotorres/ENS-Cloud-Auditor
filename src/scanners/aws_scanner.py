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
            "details": "Todos los buckets S3 utilizan cifrado con AWS KMS.",
            "affected_resources": []
        },
        "ENS-IAM-01": {
            "status": "PASS",
            "details": "MFA activado en la cuenta Root y en todos los usuarios IAM con acceso a consola.",
            "affected_resources": []
        },
        "ENS-IAM-02": {
            "status": "PASS",
            "details": "Política de contraseñas cumple >= 14 caracteres y complejidad.",
            "affected_resources": []
        },
        "ENS-IAM-03": {
            "status": "PASS",
            "details": "Sin políticas gestionadas ni inline con permisos totales '*:*'.",
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


def _has_wildcard_admin(policy_doc):
    """Devuelve True si una política IAM permite Action '*' sobre Resource '*'."""
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        actions = s.get("Action", [])
        resources = s.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if s.get("Effect") == "Allow" and "*" in actions and "*" in resources:
            return True
    return False


def run_aws_scan(profile=None, region="eu-west-1"):
    """Ejecuta los checks reales contra AWS usando boto3."""
    session = boto3.Session(profile_name=profile, region_name=region)
    results = {}

    # 1. S3 Checks (ENS-S3-01 y ENS-S3-02) con paginación
    try:
        s3 = session.client("s3")
        s3_paginator = s3.get_paginator("list_buckets")
        buckets = [
            b["Name"]
            for page in s3_paginator.paginate()
            for b in page.get("Buckets", [])
        ]
        public_buckets = []
        non_kms_buckets = []

        for bucket in buckets:
            # ENS-S3-01: Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if len(pab) < 4 or not all(pab.values()):
                    public_buckets.append(bucket)
            except ClientError:
                public_buckets.append(bucket)

            # ENS-S3-02: Cifrado gestionado con AWS KMS
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                uses_kms = any(
                    r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") in ("aws:kms", "aws:kms:dsse")
                    for r in rules
                )
                if not uses_kms:
                    non_kms_buckets.append(bucket)
            except ClientError:
                non_kms_buckets.append(bucket)

        results["ENS-S3-01"] = {
            "status": "FAIL" if public_buckets else "PASS",
            "details": (
                f"{len(public_buckets)} bucket(s) sin bloqueo público completo."
                if public_buckets
                else "Todos los buckets bloquean acceso público (o no hay buckets)."
            ),
            "affected_resources": public_buckets
        }
        results["ENS-S3-02"] = {
            "status": "FAIL" if non_kms_buckets else "PASS",
            "details": (
                f"{len(non_kms_buckets)} bucket(s) sin cifrado gestionado con AWS KMS."
                if non_kms_buckets
                else "Todos los buckets S3 utilizan cifrado con AWS KMS (o no hay buckets)."
            ),
            "affected_resources": non_kms_buckets
        }
    except (ClientError, NoCredentialsError) as e:
        for cid in ("ENS-S3-01", "ENS-S3-02"):
            results[cid] = {"status": "ERROR", "details": str(e), "affected_resources": []}

    # 2. IAM Checks (ENS-IAM-01, ENS-IAM-02, ENS-IAM-03)
    try:
        iam = session.client("iam")

        # ENS-IAM-01: MFA en Root y usuarios IAM con acceso a consola
        missing_mfa = []
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 0) != 1:
            missing_mfa.append("AWS-Root-Account")

        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                try:
                    iam.get_login_profile(UserName=username)
                    has_console_access = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console_access = False
                    else:
                        raise

                if has_console_access:
                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    if not mfa_devices:
                        missing_mfa.append(f"IAM-User: {username}")

        results["ENS-IAM-01"] = {
            "status": "FAIL" if missing_mfa else "PASS",
            "details": (
                f"{len(missing_mfa)} identidad(es) con acceso a consola sin MFA activo."
                if missing_mfa
                else "MFA activado en la cuenta Root y en todos los usuarios IAM con acceso a consola."
            ),
            "affected_resources": missing_mfa
        }

        # ENS-IAM-02: Política de contraseñas
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

        # ENS-IAM-03: Políticas '*:*' (locales gestionadas + inline en usuarios, grupos y roles)
        risky_policies = []

        # Políticas gestionadas locales
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for p in page.get("Policies", []):
                ver = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
                if _has_wildcard_admin(ver["PolicyVersion"]["Document"]):
                    risky_policies.append(f"ManagedPolicy: {p['PolicyName']}")

        # Políticas inline en usuarios
        for page in iam.get_paginator("list_users").paginate():
            for u in page.get("Users", []):
                uname = u["UserName"]
                for p_page in iam.get_paginator("list_user_policies").paginate(UserName=uname):
                    for pname in p_page.get("PolicyNames", []):
                        doc = iam.get_user_policy(UserName=uname, PolicyName=pname)["PolicyDocument"]
                        if _has_wildcard_admin(doc):
                            risky_policies.append(f"UserInline: {uname}/{pname}")

        # Políticas inline en grupos
        for page in iam.get_paginator("list_groups").paginate():
            for g in page.get("Groups", []):
                gname = g["GroupName"]
                for p_page in iam.get_paginator("list_group_policies").paginate(GroupName=gname):
                    for pname in p_page.get("PolicyNames", []):
                        doc = iam.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"]
                        if _has_wildcard_admin(doc):
                            risky_policies.append(f"GroupInline: {gname}/{pname}")

        # Políticas inline en roles (excluyendo roles gestionados por AWS)
        for page in iam.get_paginator("list_roles").paginate():
            for r in page.get("Roles", []):
                if r.get("Path", "").startswith("/aws-service-role/"):
                    continue
                rname = r["RoleName"]
                for p_page in iam.get_paginator("list_role_policies").paginate(RoleName=rname):
                    for pname in p_page.get("PolicyNames", []):
                        doc = iam.get_role_policy(RoleName=rname, PolicyName=pname)["PolicyDocument"]
                        if _has_wildcard_admin(doc):
                            risky_policies.append(f"RoleInline: {rname}/{pname}")

        results["ENS-IAM-03"] = {
            "status": "FAIL" if risky_policies else "PASS",
            "details": (
                f"{len(risky_policies)} política(s) gestionada(s) o inline con permisos '*:*'."
                if risky_policies
                else "Sin políticas gestionadas ni inline con permisos totales '*:*'."
            ),
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

    # 4. VPC Security Groups Check (ENS-VPC-01) con paginación y protocolo "-1"
    try:
        ec2 = session.client("ec2")
        exposed_sgs = []
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                for perm in sg.get("IpPermissions", []):
                    proto = perm.get("IpProtocol")
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    is_risky_port = (
                        proto == "-1"
                        or (from_p is not None and to_p is not None and ((from_p <= 22 <= to_p) or (from_p <= 3389 <= to_p)))
                    )
                    if is_risky_port:
                        cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                        cidrs_v6 = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                        if "0.0.0.0/0" in cidrs or "::/0" in cidrs_v6:
                            exposed_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                            break
        results["ENS-VPC-01"] = {
            "status": "FAIL" if exposed_sgs else "PASS",
            "details": f"{len(exposed_sgs)} Security Group(s) con SSH/RDP o todo el tráfico expuesto a Internet." if exposed_sgs else "Sin puertos críticos expuestos a Internet.",
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