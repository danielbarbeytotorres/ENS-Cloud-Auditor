# Política de Seguridad de la Información (PSI)
**Organización:** Atlántico Cloud Solutions S.L. (A Coruña, España)  
**Alcance:** Infraestructura Cloud en AWS para prestación de servicios SaaS a la Administración Pública  
**Marco Normativo:** Esquema Nacional de Seguridad (RD 311/2022) e ISO/IEC 27001:2022  
**Categoría del Sistema (ENS):** MEDIA  

---

## 1. Objetivo
Establecer el marco de gobierno, gestión de riesgos y cumplimiento para proteger la confidencialidad, integridad, disponibilidad, autenticidad y trazabilidad de la información alojada en la infraestructura AWS de Atlántico Cloud Solutions S.L.

## 2. Principios Básicos (Art. 5 RD 311/2022)
* **Seguridad integral:** La seguridad abarca personas, procesos y tecnología cloud.
* **Gestión basada en riesgos:** Toda decisión técnica se justifica mediante análisis de riesgos (metodología MAGERIT).
* **Prevención, detección, respuesta y conservación:** Monitorización continua y auditoría automatizada (*Compliance-as-Code*).
* **Líneas de defensa:** Separación de entornos, mínimo privilegio en IAM y cifrado por defecto.

## 3. Roles y Responsabilidades (ENS `org.1`)
| Rol ENS | Responsable en la Organización | Funciones Principales |
| :--- | :--- | :--- |
| **Responsable de la Información** | Dirección de Producto / Cliente AAPP | Determinar los niveles de seguridad de los datos tratados. |
| **Responsable del Servicio** | Dirección de Operaciones (COO) | Determinar los requisitos de disponibilidad y continuidad del SaaS. |
| **Responsable de Seguridad (CISO)** | Área de Ciberseguridad & GRC | Supervisar el cumplimiento del ENS, auditorías y gestión de incidentes. |
| **Responsable del Sistema** | Ingeniería Cloud / DevSecOps | Operar la infraestructura AWS y aplicar las medidas técnicas y remediaciones. |

## 4. Normas Obligatorias en Entorno AWS
1. **Control de Acceso (`op.acc`):** Uso obligatorio de MFA en la cuenta Root y en todos los usuarios IAM con acceso a consola, política de contraseñas robusta (≥ 14 caracteres y complejidad) y prohibición estricta de políticas IAM —tanto gestionadas locales como *inline*— con permisos totales (`*:*`).
2. **Protección de Datos (`mp.info`):** Todo almacenamiento debe estar cifrado en reposo (claves gestionadas con AWS KMS en buckets S3 y cifrado por defecto habilitado en volúmenes EBS) y sin exposición pública salvo excepción formalmente aprobada.
3. **Comunicaciones (`mp.com`):** Prohibida la exposición de puertos de administración (SSH 22, RDP 3389) o reglas de tráfico irrestricto (`-1`) a Internet (`0.0.0.0/0` o `::/0`).
4. **Trazabilidad (`op.exp.8`):** AWS CloudTrail debe permanecer activo en modo multirregión con registro continuo de eventos.

## 5. Cumplimiento Continuo y Revisión
El cumplimiento técnico de esta política se verifica de forma automatizada mediante **ENS-Cloud-Auditor** en los pipelines de CI/CD, estableciendo un **umbral mínimo obligatorio del 80%**. Esta política se revisará anualmente o ante cambios normativos relevantes.