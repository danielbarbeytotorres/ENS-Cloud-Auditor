# Declaración de Aplicabilidad (SoA)
**Organización:** Atlántico Cloud Solutions S.L. (Escenario de referencia)  
**Sistema:** Plataforma SaaS en AWS – Categoría ENS: MEDIA  
**Referencia:** Anexo II del Real Decreto 311/2022 (ENS) y Anexo A de ISO/IEC 27001:2022  

| ID Interno | Medida ENS | Equivalencia ISO 27001 | Descripción del Control | ¿Aplica? | Justificación / Salvaguarda Técnica | Simulación (`--mock`, 60%) | AWS Live Inicial (70%) | AWS Live Post-Remediación (85%) |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **ENS-S3-01** | `op.acc.2` / `mp.info.1` | A.5.15 / A.8.3 | Bloqueo de acceso público en S3 | **SÍ** | Evitar fugas de datos de clientes/ciudadanos mediante *Block Public Access*. | ❌ No Conforme | ✅ Conforme | ✅ Conforme |
| **ENS-S3-02** | `mp.info.3` | A.8.24 | Cifrado en reposo con AWS KMS en S3 | **SÍ** | Protección criptográfica gestionada (SSE-KMS) para información almacenada. | ✅ Conforme | ✅ Conforme | ✅ Conforme |
| **ENS-IAM-01** | `op.acc.5` | A.8.5 | MFA en Root y usuarios IAM con consola | **SÍ** | Prevención de compromiso de cuentas administrativas y acceso a consola AWS. | ✅ Conforme | ✅ Conforme | ✅ Conforme |
| **ENS-IAM-02** | `op.acc.5` | A.5.17 | Política de contraseñas robusta | **SÍ** | Longitud ≥ 14 caracteres y complejidad obligatoria en IAM. | ✅ Conforme | ❌ No Conforme | ✅ Conforme *(Remediado)* |
| **ENS-IAM-03** | `op.acc.4` | A.8.2 | Principio de mínimo privilegio | **SÍ** | Prohibición de políticas gestionadas locales e *inline* con permisos `*:*`. | ✅ Conforme | ✅ Conforme | ✅ Conforme |
| **ENS-CT-01** | `op.exp.8` | A.8.15 | Registro de actividad (CloudTrail) | **SÍ** | Trazabilidad forense continua de acciones en AWS en modo multirregión. | ❌ No Conforme | ❌ No Conforme | ❌ Pendiente *(Plan de acción)* |
| **ENS-VPC-01** | `mp.com.1` | A.8.20 | Cierre de puertos críticos (22/3389) y tráfico `-1` | **SÍ** | Reducción de superficie de ataque perimetral en Security Groups (`0.0.0.0/0` y `::/0`). | ❌ No Conforme | ✅ Conforme | ✅ Conforme |
| **ENS-EBS-01** | `mp.info.3` | A.8.24 | Cifrado por defecto en volúmenes EBS | **SÍ** | Confidencialidad de discos de instancias EC2 a nivel de región. | ✅ Conforme | ❌ No Conforme | ✅ Conforme *(Remediado)* |
| **ENS-PHY-01** | `mp.if.1` | A.7.1 | Seguridad física de centros de datos | **NO (Heredado)** | Control heredado del proveedor cloud (AWS) bajo modelo de responsabilidad compartida (certificación ENS Alta de AWS). | ⚪ Heredado | ⚪ Heredado | ⚪ Heredado |

> **Nota de trazabilidad:** El modo `--mock` reproduce un entorno vulnerable controlado para validación CI/CD y demostración (60,0%). Las columnas **AWS Live** reflejan la auditoría real ejecutada en la región `eu-west-1` antes (70,0%) y después (85,0%) de aplicar las remediaciones automatizadas de IAM y EBS. El control `ENS-CT-01` (CloudTrail multirregión) permanece documentado como acción pendiente en la cuenta de laboratorio para evitar costes recurrentes de almacenamiento S3.