# Security Policy - TrustVault

## 1. Security Philosophy & Standards

TrustVault is designed to secure sensitive enterprise documents against unauthorized access, privilege escalation, data leakage, and insider tampering.

Our core security architecture is governed by five mandatory pillars:
1. **Zero-Trust Access Control**: No client-side claims (roles, permissions, IDs) are ever trusted. Authorization is evaluated against current database state on every request.
2. **Confidentiality & Least Privilege**: Platform Administrators maintain operational oversight and audit review, but **never possess automatic access to confidential document contents**.
3. **Immediate Revocation**: Session invalidation and permission revocations take effect on subsequent requests with zero cache window.
4. **Audit Immutability**: All security actions and unauthorized attempts are logged to an append-only, trigger-protected database table secured with SHA-256-linked audit hash chaining.
5. **Database Privilege Separation**: The runtime application user (`trustvault_app`) is blocked from executing DDL migrations, altering triggers, or updating/deleting audit records.

---

## 2. Supported Versions

| Version | Supported | Status |
| :--- | :---: | :--- |
| 1.0.x (Current) | ✅ | Active Development & Security Updates |

---

## 3. Reporting a Vulnerability

If you discover a potential security flaw in TrustVault, please practice coordinated vulnerability disclosure:

1. **Email**: A monitored security contact has not yet been configured. `security@trustvault.local` is a development placeholder, not a verified public reporting address. Replace it before any public release..
2. **Details to Include**:
   - Attack vector description and STRIDE classification.
   - Proof-of-concept (PoC) script or HTTP request sequence.
   - Affected endpoints and impact assessment.
3. **Response Timeline**:
   - Initial acknowledgement within 24 hours.
   - Severity triage and mitigation plan within 72 hours.
   - Coordinated release following verification and regression testing.

---

## 4. Architectural Limitations & External Anchoring

- **Database Superuser Privileges**: Database-level immutability triggers prevent application-level tampering (e.g. SQL injection). However, a database superuser (`postgres`) or host OS administrator has the capability to bypass triggers or modify raw filesystem blocks.
- **Production Guidance**: In enterprise deployments, audit logs must be replicated continuously to an external Write-Once-Read-Many (WORM) storage destination (such as AWS CloudWatch with retention lock, Azure Immutable Blob Storage, or a dedicated SIEM) to ensure non-repudiation even against compromised host administrators.
