# TrustVault - AI Interaction Log (PROMPTS.md)

This log records interactions with the AI assistant during the development of TrustVault, in accordance with project audit rules. Each entry captures the date, a prompt summary, actual output, specific errors/discrepancies discovered, corrections applied, and Git commit references where applicable.

---

### Entry 001: Architecture, Threat Model, and Implementation Roadmap
- **Date**: 2026-10-18
- **Prompt / Summary**:
  The user requested the initial architectural blueprint, database schema, permission matrix, authentication & immediate revocation design, private storage design, audit-integrity design, STRIDE-aligned threat model, automated testing strategy, and phased implementation plan for TrustVault. Explicit constraints: do not implement the entire application in one step; follow least-privilege for administrators (no automatic content access); validate all file uploads; enforce server-side authorization on every request; record append-only audit events; establish isolated pytest suite.
- **Actual Output**:
  Comprehensive architectural specification, data model, permission matrix, security mechanisms, threat model, testing matrix, and phased implementation roadmap. Identified security trade-offs (e.g., 404 vs 403 enumeration prevention, break-glass vs owner-only access, database privilege separation for audit integrity).
- **Specific Errors / Discrepancies Discovered**:
  None at planning phase. Clarified potential risk of metadata/ID enumeration if returning 403 instead of 404 for unpermitted resources, and highlighted DBA superuser limitations regarding local audit log immutability.
- **Correction / Mitigation**:
  Adopted "404 Not Found or Forbidden" response pattern for unauthorized document queries at the API layer, while persisting exact `DENIED` status and actor details in the internal append-only audit log. SHA-256-linked audit hash chain and PostgreSQL role privilege separation for audit log defense.
- **Git Commit**: Pending initial repository commit.

---

### Entry 002: Phase 1 Environment, Database & Security Foundation
- **Date**: 2026-10-18
- **Prompt / Summary**:
  User approved architecture with conditions: (1) consistent HTTP 404 responses for nonexistent and unauthorized documents; (2) administrative document ownership transfer under explicit policy without granting content access; (3) database privilege separation for `trustvault_app` vs `trustvault_admin` with automated negative privilege tests; (4) server-side authorization and `token_version` checks on every request; (5) documentation of in-progress download behavior during immediate revocation; (6) concurrency-safe audit hash chaining and tamper detection testing; (7) real isolated database tests. Prompted to execute Phase 1 only.
- **Actual Output**:
  Implemented project directory structure, `.gitignore`, `.env.example`, Pydantic Settings with production secret validation, SQLAlchemy 2.0 ORM models (`User`, `Document`, `DocumentPermission`, `AuditLog`), Alembic migrations with PostgreSQL immutability trigger, database privilege scripts (`init_db_roles.sql`), Argon2id password hashing and JWT issuance with `token_version` invalidation, `AuditService` with advisory transaction lock serialization and autonomous logging, FastAPI health checks, comprehensive integration tests (`test_config_health.py`, `test_auth_foundation.py`, `test_audit_integrity.py`, `test_db_privilege_separation.py`), `docs/ARCHITECTURE.md`, `SECURITY.md`, `THREATS.md`, `README.md`, and `docs/API.md`.
- **Specific Errors / Discrepancies Discovered**:
  1. Pip backtracking: When pydantic and pydantic-settings version constraints were left open with Python 3.13, pip resolver backtracked across multiple pydantic releases.
  2. Slow PyPI downloads for large binary wheels on the local Windows network caused socket timeouts in pip.
- **Correction / Mitigation**:
  1. Configured virtual environment `pyvenv.cfg` to enable `include-system-site-packages = true`, directly inheriting pre-verified wheels (`fastapi`, `pydantic`, `uvicorn`, `PyJWT`, `bcrypt`) without redundant network downloads.
  2. Pinned dependency requirements and isolated package installations.
  3. Formulated explicit test fixtures with automated negative privilege testing for database least privilege and audit log immutability triggers.
- **Git Commit**: Initial Git repository initialized (`.git`), pending Phase 1 commit.

### Entry 003: Upload Validation, Authorization Regression Tests, and Security Verification

- **Date**: 2026-10-22
- **Prompt / Summary**: Strengthen upload validation and verify authentication expiration, administrator document isolation, audit immutability, and database privilege separation.
- **Actual Output**:
  - Added uploaded-file content validation for supported file types, including PDF signatures, PNG/JPG signatures, DOCX/XLSX ZIP structure, and UTF-8 text/CSV checks.
  - Added upload tests for valid text uploads, empty files, oversized uploads, disallowed extensions, filename path-component stripping, and invalid PDF content.
  - Added regression tests for expired JWT rejection and administrator download denial without document permission.
  - Verified the full backend test suite: 45 passed, 1 skipped, 4 warnings.
  - Verified the frontend production build had succeeded in the preceding development checkpoint.
  - Inspected the production `trustvault` database: Alembic revision `ed28e992c911` is at head; the audit immutability trigger is enabled; the `trustvault_app` role can read and insert audit records but cannot directly update or delete them; it cannot create objects in `public` and is not a member of `trustvault_admin`.
- **Specific Errors / Discrepancies Discovered**:
  - The test database `trustvault_test` is cleaned up by the test fixture, so it should not be used to infer the presence of application tables after a test run.
  - Windows symlink-escape testing remains skipped because the environment lacks the required privilege.
  - Automated DDL privilege tests, broader file-format validation tests, and additional audit coverage remain outstanding.
- **Correction / Mitigation**:
  - Updated the threat-model verification status to reflect the new passing tests and preserve the remaining gaps.
  - Continued read-only verification of production database configuration; no production schema or privilege changes were made during these checks.
- **Git Commit**: Pending.
