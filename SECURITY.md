# Security Policy — TrustVault

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

Latest reported local verification:

- **Backend tests:** 84 passed, 0 failed in 10.07 seconds.
- **Frontend production build:** Successful with Vite 5.4.21; 33 modules transformed.
- **Pydantic configuration:** Deprecated class-based schema configuration replaced with `ConfigDict`.
- **Upload-size boundaries:** Previously reported tests confirmed that an upload exactly at the configured 25 MiB limit succeeds and an upload one byte over the limit is rejected with HTTP 413.
- **Database privilege separation:** Production PostgreSQL privileges were manually verified on 2026-10-23. These checks are not automated integration tests against the production roles.

Latest verification checkpoint: backend test suite and frontend production build passed after commit `0ba5d92` (`Restore complete security policy documentation`).

These results are a verification snapshot, not a security certification. Consult `THREATS.md` for outstanding tests, known limitations, and production recommendations. Repeat relevant checks after subsequent code or configuration changes.
