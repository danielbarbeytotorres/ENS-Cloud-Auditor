# Análisis y Gestión de Riesgos (Metodología MAGERIT v3)
**Organización:** Atlántico Cloud Solutions S.L. – Infraestructura SaaS en AWS (Categoría ENS: MEDIA)  
**Escala de valoración:** Probabilidad (1-5) × Impacto (1-5) = Riesgo (1-25)  
* **Bajo:** 1–6 | **Medio:** 7–12 | **Alto:** 13–19 | **Crítico:** 20–25  

| ID Riesgo | Activo (MAGERIT) | Amenaza | Prob. | Imp. | Riesgo Intrínseco | Salvaguarda / Control ENS | Riesgo Residual | Tratamiento |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: | :--- |
| **R-01** | `[D] Datos en S3` | `[A.11]` Acceso no autorizado / Fuga de información por bucket público | 4 | 5 | **20 (Crítico)** | `op.acc.2` / `mp.info.1` (Block Public Access) + Auditoría CI/CD | **4 (Bajo)** | Mitigar (Verificado en AWS Live) |
| **R-02** | `[S] Cuenta Root e Identidades IAM` | `[A.5]` Suplantación de identidad y escalada de privilegios | 3 | 5 | **15 (Alto)** | `op.acc.5` (MFA en Root y usuarios de consola + contraseñas ≥ 14) y `op.acc.4` (sin políticas `*:*`) | **3 (Bajo)** | Mitigar (Implantado y remediado en AWS Live) |
| **R-03** | `[SW] Instancias EC2 / VPC` | `[A.24]` Denegación o intrusión vía SSH/RDP o tráfico `-1` expuesto a Internet | 5 | 4 | **20 (Crítico)** | `mp.com.1` (Restricción Security Groups en IPv4/IPv6 + VPN/Bastion) | **4 (Bajo)** | Mitigar (Verificado en AWS Live) |
| **R-04** | `[L] Logs de Auditoría` | `[E.2]` Falta de trazabilidad ante incidente de seguridad | 4 | 4 | **16 (Alto)** | `op.exp.8` (CloudTrail multirregión activo) | **3 (Bajo)** | Mitigar (Plan de acción prioritario) |
| **R-05** | `[D] Volúmenes EBS / Buckets S3` | `[A.19]` Divulgación de información por acceso a almacenamiento sin cifrado gestionado | 2 | 4 | **8 (Medio)** | `mp.info.3` (Cifrado con AWS KMS en S3 y cifrado por defecto en EBS) | **2 (Bajo)** | Mitigar (Implantado y remediado en AWS Live) |