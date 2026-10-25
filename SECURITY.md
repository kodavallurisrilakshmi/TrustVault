# Security Policy (—) TrustVault

## 1. Security Philosophy and Standards

TrustVault is designed to protect sensitive documents against unauthorized access, privilege escalation, data leakage, and audit-record tampering.

The security architecture is based on five principles:

1. **Zero-Trust Access Control:** Client-supplied roles, permissions, and document identifiers are not trusted as authorization evidence. Protected operations must validate authorization using current server-side state.
2. **Confidentiality and Least Privilege:** Administrators can perform authorized operational and audit functions, but administrator status alone does not grant permission to read or download confidential document contents.
3. **Revocation:** Session invalidation and document permission revocation are intended to take effect on subsequent protected requests, provided current session and permission state is checked on every request.
4. **Audit Integrity:** Audit records use a trigger-protected append-only database design and SHA-256-linked hash chaining. These mechanisms support tamper resistance and detection but do not protect against every privileged database or host-level attack.
5. **Database Privilege Separation:** The runtime application role (`trustvault_app`) is separated from the schema-management role. Its production privileges are restricted, including restrictions on audit-record updates and deletions.

## 2. Supported Versions

| Version | Supported | Status |
|---|---|---|
| 1.0.x | Yes | Active development and security updates |

## 3. Reporting a Vulnerability

A monitored public security contact has not yet been configured. The address `security@trustvault.local` is a development placeholder and must not be treated as a verified reporting address. Configure a monitored contact before public release.

When reporting a vulnerability, include:

- The attack vector and relevant STRIDE category.
- A proof-of-concept script or HTTP request sequence, where safe.
- The affected endpoints and potential impact.

The following are proposed response targets, not a currently verified service-level commitment:

- Initial acknowledgement within 24 hours.
- Initial severity assessment and mitigation plan within 72 hours.
- Coordinated disclosure after mitigation and regression testing.

## 4. Architectural Limitations and External Audit Anchoring

### Database and host administrators

Database immutability triggers and application-level authorization do not prevent every attack. A sufficiently privileged database administrator or host operating-system administrator may bypass database controls, alter stored data, or modify application files.

### Production recommendations

For deployments requiring stronger audit assurances:

- Continuously export security events to a separately administered, access-controlled destination.
- Consider immutable or retention-locked storage, such as an appropriately configured WORM service, alongside a security information and event management (SIEM) system.
- Monitor failures in audit writes, verification checks, and log forwarding.
- Test backup, recovery, access-control, and incident-response procedures.

A valid hash chain demonstrates consistency of the records being checked; by itself, it does not prove that every security-relevant action was logged or that a privileged administrator could not rewrite the entire chain.

## 5. Verification Status

Latest local verification checkpoint: 2026-10-24.

- **Backend tests:** 99 passed, 0 failed, in 5.56 seconds (latest rerun on 2026-10-24).
- **Configuration and health tests:** 21 passed, 0 failed in the latest focused rerun.
- **Frontend production build:** Successful using Vite 5.4.21; 33 modules transformed.
- **Audit integrity tests:** 10 passed, 0 failed in the latest focused rerun.
- **Live audit-chain integrity:** HTTP 200; `is_valid=true`; 152 records verified on 2026-10-24, with no broken record reported.
- **Database migration:** Current and head revisions both equal `ed28e992c911` on 2026-10-24.
- **Production database protections:** Read-only checks on 2026-10-24 confirmed trustvault_app has SELECT and INSERT, but not UPDATE, DELETE, or TRUNCATE on public.audit_logs; trustvault_admin owns the table; the app role is not an owner-role member; and trg_audit_logs_immutable is enabled. These are manual checks, not automated production-role integration tests.
- **Repository hygiene:** Environment-file ignore rules and secret scans passed at earlier local checkpoints. Repeat these checks before publication.

These results are a local verification snapshot, not a security certification. Passing tests and building the frontend do not establish that production infrastructure is configured securely or that every security threat has been mitigated.

Outstanding work includes production hosting and persistent storage configuration, production secret and CORS verification, audit-failure monitoring, external immutable audit-log anchoring, and verification of the remaining items in `THREATS.md`.

Repeat relevant checks after subsequent code or configuration changes. Do not describe unverified controls as implemented or proven.
