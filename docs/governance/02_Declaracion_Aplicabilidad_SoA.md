# Declaración de Aplicabilidad (SoA)
**Sistema:** Plataforma SaaS en AWS – Categoría ENS: MEDIA  
**Referencia:** Anexo II del Real Decreto 311/2022 (ENS) y Anexo A de ISO/IEC 27001:2022  

| ID Interno | Medida ENS | Equivalencia ISO 27001 | Descripción del Control | ¿Aplica? | Justificación / Salvaguarda Técnica | Estado Actual (Mock) |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: |
| **ENS-S3-01** | `op.acc.2` / `mp.info.1` | A.5.15 / A.8.3 | Bloqueo de acceso público en S3 | **SÍ** | Evitar fugas de datos de ciudadanos/clientes. Verificado con *ENS-Cloud-Auditor*. | ❌ No Conforme |
| **ENS-S3-02** | `mp.info.3` | A.8.24 | Cifrado en reposo en buckets S3 | **SÍ** | Protección criptográfica de datos almacenados (SSE-S3 / KMS). | ✅ Conforme |
| **ENS-IAM-01** | `op.acc.5` | A.8.5 | MFA en cuenta Root de AWS | **SÍ** | Prevención de compromiso total de la cuenta cloud. | ✅ Conforme |
| **ENS-IAM-02** | `op.acc.5` | A.5.17 | Política de contraseñas robusta | **SÍ** | Longitud >= 14 caracteres y complejidad obligatoria en IAM. | ✅ Conforme |
| **ENS-IAM-03** | `op.acc.4` | A.8.2 | Principio de mínimo privilegio | **SÍ** | Evitar escalada de privilegios por políticas `*:*`. | ✅ Conforme |
| **ENS-CT-01** | `op.exp.8` | A.8.15 | Registro de actividad (CloudTrail) | **SÍ** | Trazabilidad forense de acciones en AWS (multirregión). | ❌ No Conforme |
| **ENS-VPC-01** | `mp.com.1` | A.8.20 | Cierre de puertos críticos (22/3389) | **SÍ** | Reducción de superficie de ataque perimetral en VPC. | ❌ No Conforme |
| **ENS-EBS-01** | `mp.info.3` | A.8.24 | Cifrado por defecto en volúmenes EBS | **SÍ** | Confidencialidad de discos de instancias EC2. | ✅ Conforme |
| **ENS-PHY-01** | `mp.if.1` | A.7.1 | Seguridad física de centros de datos | **NO (Heredado)** | Control heredado del proveedor cloud (AWS) bajo modelo de responsabilidad compartida (certificación ENS Alta de AWS). | ⚪ Heredado |