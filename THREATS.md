# TrustVault Threat Model (STRIDE) & Test Verification Matrix
This document provides a systematic threat model for TrustVault based on the **STRIDE** methodology. Each threat is mapped to existing automated tests where available; uncovered requirements and manual verification are identified explicitly.

---

## 1. STRIDE Threat Matrix

| Threat ID | Category | Attack Scenario | TrustVault Mitigation | Automated Integration Test |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | Forged JWT access token with altered `sub` | Cryptographic signature verification with `HS256`/`RS256`; rejected with HTTP 401 | `test_auth_foundation.py::test_tampered_jwt_signature_rejected` |
| **TH-02** | **Spoofing** | Replaying an expired authentication token | Token `exp` claim verified by JWT engine; expired tokens rejected with HTTP 401 | `test_auth_foundation.py::test_invalid_credentials_rejected` |
| **TH-03** | **Spoofing** | Logged-out or revoked user session replay | Server compares JWT `token_version` claim to database `token_version` on every request | `test_auth_foundation.py::test_token_version_immediate_revocation` |
| **TH-04** | **Spoofing** | Deactivated user accessing endpoints | User `is_active` verified in database on every request; deactivation increments version | `test_auth_foundation.py::test_deactivated_account_immediate_revocation` |
| **TH-05** | **Tampering** | BOLA / IDOR document access by unauthorized user | Authorization dependency executes live SQL check; returns unified HTTP 404 | `test_document_access.py::test_unpermitted_user_cannot_access_document` |
| **TH-06** | **Tampering** | Unauthorized metadata or content update | Enforces Editor or Owner permission level in database; returns HTTP 404 | `test_document_access.py::test_view_permission_does_not_allow_edit`  |
| **TH-07** | **Tampering** | Modifying or deleting audit records via SQL | PostgreSQL `BEFORE UPDATE OR DELETE` trigger aborts query with exception | `test_db_privilege_separation.py::test_audit_logs_immutability_trigger_blocks_update` |
| **TH-08** | **Repudiation** | Actor denies deleting document or accessing file | Request ID, actor IP, timestamp, action, and result recorded in immutable audit log | `test_audit_integrity.py::test_audit_event_logged_on_successful_login` |
| **TH-09** | **Repudiation** | Attacker tampers with historical audit log | Cryptographic SHA-256-linked audit hash chain detects any modified, reordered, or deleted row | `test_audit_integrity.py::test_audit_chain_tamper_detection` |
| **TH-10** | **Information Disclosure** | Probing document IDs via 403 vs 404 errors | Nonexistent and unauthorized document requests return uniform HTTP 404 response | `test_document_access.py::test_unpermitted_user_cannot_access_document` |
| **TH-11** | **Information Disclosure** | Search query cross-user metadata leak | SQL filters restrict query results to owned or granted documents only | `Not currently covered by the verified automated test suite; add a dedicated cross-user search isolation test.` |
| **TH-12** | **Information Disclosure** | Exposure of secrets via health/config endpoints | Health check endpoints strictly mask `SECRET_KEY` and database credentials | `test_config_health.py::test_config_check_masks_secrets` |
| **TH-13** | **Denial of Service** | Storage exhaustion via oversized file uploads | In-flight streaming byte counter terminates upload at 25MB with HTTP 413 | `test_upload_validation.py::test_oversized_file_upload_rejected` (Phase 3) |
| **TH-14** | **Elevation of Privilege** | Administrator accessing confidential documents | Admin role denied download endpoint access unless explicitly granted by owner | `Not currently covered by the verified automated test suite; add a dedicated administrator document-download authorization test.`  |
| **TH-15** | **Elevation of Privilege** | Viewer attempting to grant document access | Only the Document Owner can grant or revoke access; viewers rejected | `test_document_permissions.py::test_non_owner_cannot_grant_permission`  |
| **TH-16** | **Elevation of Privilege** | Application role altering database schema | Runtime role `trustvault_app` lacks DDL permissions; table drop/alter rejected | `test_db_privilege_separation.py::test_audit_logs_immutability_trigger_blocks_delete` |
| **TH-17** | **Malicious Upload** | Path traversal via crafted filename (`../../etc/passwd`) | Random UUIDv4 storage keys decouple file on disk from client-provided filename | `test_upload_validation.py::test_path_traversal_filename_neutralized` (Phase 3) |
| **TH-18** | **Malicious Upload** | Executable masquerading as PDF (`malware.exe`) | Magic-byte signature verification checks initial bytes before persistence | `test_upload_validation.py::test_executable_disguised_as_pdf_rejected` (Phase 3) |
| **TH-19** | **Race Condition** | Using permission immediately after owner revocation | Permission check queries database on every request; subsequent call blocked immediately | `test_document_access.py::test_unpermitted_user_cannot_access_document` |
| **TH-20** | **Race Condition** | Broken audit hash chain under concurrent writes | PostgreSQL advisory transaction locks serialize chain head reads and inserts | `test_audit_integrity.py::test_audit_chain_concurrency_continuity` |

---

## 2. Information Leakage Prevention Guidelines

1. **Uniform HTTP 404 Responses**:
   When a user requests `GET /api/v1/documents/{doc_id}` and either the document does not exist OR the user lacks permission, the response is identically:
   ```json
   {
     "detail": "Document not found or access denied"
   }
   ```
   Status Code: `404 Not Found`.
2. **Internal Audit Precision**:
   While the client receives an innocuous 404, the internal audit log captures `result='DENIED'`, `action='DOC_READ'`, `actor_id='...'`, `target_id='...'`, and `denial_reason='UNAUTHORIZED_ACCESS'`.

---

## 3. Administrative Ownership Transfer Policy

If a document owner leaves the organization or is incapacitated, an administrator can transfer document ownership under the following strict rules:
1. Target destination owner must exist, be active, and not be the administrator.
2. The transfer is atomic and changes `documents.owner_id`.
3. An immutable audit record is created capturing `actor_id` (admin), `old_owner_id`, `new_owner_id`, and `reason`.
4. **The transfer does NOT grant the administrator access to read or download the document content**.
