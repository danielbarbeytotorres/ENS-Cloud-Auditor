# Análisis y Gestión de Riesgos (Metodología MAGERIT v3)
**Escala de valoración:** Probabilidad (1-5) × Impacto (1-5) = Riesgo (1-25)  
* **Bajo:** 1–6 | **Medio:** 7–12 | **Alto:** 13–19 | **Crítico:** 20–25  

| ID Riesgo | Activo (MAGERIT) | Amenaza | Prob. | Imp. | Riesgo Intrínseco | Salvaguarda / Control ENS | Riesgo Residual | Tratamiento |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: | :--- |
| **R-01** | `[D] Datos en S3` | `[A.11]` Acceso no autorizado / Fuga de información por bucket público | 4 | 5 | **20 (Crítico)** | `op.acc.1` (Block Public Access) + Auditoría CI/CD | **4 (Bajo)** | Mitigar (Plan de acción inmediato) |
| **R-02** | `[S] Cuenta AWS Root` | `[A.5]` Suplantación de identidad de usuario privilegiado | 3 | 5 | **15 (Alto)** | `op.acc.5` (MFA Hardware/Virtual en Root) | **3 (Bajo)** | Mitigar (Implantado) |
| **R-03** | `[SW] Instancias EC2 / VPC` | `[A.24]` Denegación o intrusión vía SSH/RDP expuesto a Internet | 5 | 4 | **20 (Crítico)** | `mp.com.1` (Restricción Security Groups + VPN/Bastion) | **4 (Bajo)** | Mitigar (Plan de acción inmediato) |
| **R-04** | `[L] Logs de Auditoría` | `[E.2]` Falta de trazabilidad ante incidente de seguridad | 4 | 4 | **16 (Alto)** | `op.exp.8` (CloudTrail multirregión + validación logs) | **3 (Bajo)** | Mitigar (Plan de acción inmediato) |
| **R-05** | `[D] Volúmenes EBS / S3` | `[A.19]` Divulgación de información por acceso a soporte sin cifrar | 2 | 4 | **8 (Medio)** | `mp.info.3` (Cifrado en reposo AES-256 / KMS) | **2 (Bajo)** | Mitigar (Implantado) |