# TrustVault Threat Model (STRIDE) & Test Verification Matrix

This document describes TrustVault's threat model using the **STRIDE** methodology. Each threat is mapped to its mitigation and known automated test coverage. Test references must be verified against the current codebase before being considered passing evidence.

## 1. STRIDE Threat Matrix

| Threat ID | Category | Attack Scenario | TrustVault Mitigation | Automated Test / Verification Status |
|---|---|---|---|---|
| TH-01 | Spoofing | Forged JWT with altered `sub` claim | JWT signature verification; invalid tokens return HTTP 401 | `test_auth_foundation.py::test_tampered_jwt_signature_rejected` |
| TH-02 | Spoofing | Replaying an expired authentication token | JWT expiration (`exp`) validation | `test_auth_foundation.py::test_expired_jwt_is_rejected` — passed in the full suite |
| TH-03 | Spoofing | Replaying a logged-out or revoked session | Compare the JWT `token_version` with the current database value on authenticated requests | `test_auth_foundation.py::test_token_version_immediate_revocation` |
| TH-04 | Spoofing | Deactivated user accessing endpoints | Check account activation status during authentication | `test_auth_foundation.py::test_deactivated_account_immediate_revocation` |
| TH-05 | Tampering | BOLA / IDOR document access | Enforce server-side document authorization and return a non-disclosing HTTP 404 | `test_document_access.py::test_unpermitted_user_cannot_access_document` |
| TH-06 | Tampering | Unauthorized metadata or content modification | Enforce the required owner/editor permission before allowing modifications | `test_document_access.py::test_view_permission_does_not_allow_edit` |
| TH-07 | Tampering | Modifying or deleting audit records through SQL | PostgreSQL triggers prevent audit-record updates and deletions | `test_db_privilege_separation.py::test_audit_logs_immutability_trigger_blocks_update` |
| TH-08 | Repudiation | Actor denies performing an operation | Record available request, actor, timestamp, action, and outcome information in the audit log | `test_audit_integrity.py::test_audit_event_logged_on_successful_login`; document-specific audit coverage requires separate verification |
| TH-09 | Repudiation | Tampering with historical audit records | Verify the SHA-256-linked audit hash chain | `test_audit_integrity.py::test_audit_chain_tamper_detection` |
| TH-10 | Information Disclosure | Probing document IDs using different error responses | Return a uniform HTTP 404 for nonexistent or unauthorized documents | `test_document_access.py::test_unpermitted_user_cannot_access_document`; compare responses for both cases in a dedicated test |
| TH-11 | Information Disclosure | Cross-user document listing exposes private document metadata | Restrict document-list results to documents the requester owns or is authorized to access | `test_document_permissions.py::test_document_list_is_isolated_between_users` — passed; a separate search-isolation test remains outstanding if search is implemented |
| TH-12 | Information Disclosure | Secrets exposed by health or configuration endpoints | Mask secrets and sensitive configuration values in diagnostic responses | `test_config_health.py::test_config_check_masks_secrets` |
| TH-13 | Denial of Service | Storage exhaustion through oversized uploads | Enforce the configured upload-size limit while streaming and reject oversized requests | `tests/test_document_upload.py::test_oversized_upload_is_rejected` — passed; test uses an 8-byte limit to exercise the rejection path |
| TH-14 | Elevation of Privilege | Administrator downloads confidential documents without permission | Require explicit document authorization; administrative privileges must not automatically grant content access | `test_document_permissions.py::test_admin_cannot_download_private_document_without_permission` — passed in the full suite |
| TH-15 | Elevation of Privilege | Viewer grants or revokes document access | Restrict permission management to the document owner or another explicitly authorized role | `test_document_permissions.py::test_non_owner_cannot_grant_permission` |
| TH-16 | Elevation of Privilege | Application database role modifies the schema | Restrict runtime database privileges and separate application access from schema-management privileges | Existing audit-trigger tests cover audit immutability, **not** general DDL privilege separation; add a dedicated privilege test |
| TH-17 | Malicious Upload | Path traversal through a crafted filename | Generate server-controlled storage keys and prevent client filenames from determining filesystem paths | `tests/test_document_upload.py::test_path_components_are_removed_from_uploaded_filename` — passed; storage containment is also enforced by `LocalStorageService` |
| TH-18 | Malicious Upload | File content does not match its declared extension | Check supported file-format signatures or structure and reject mismatched content | `tests/test_document_upload.py::test_pdf_with_non_pdf_contents_is_rejected` — passed; other format-validation paths need dedicated tests |
| TH-19 | Race Condition | Access continues after permission revocation | Recheck current permissions on each protected request | `test_document_permissions.py::test_revoked_viewer_loses_document_list_access` and `test_document_permissions.py::test_revoked_viewer_cannot_download_document` — passed; download authorization is tested with the storage read mocked |
| TH-20 | Race Condition | Concurrent audit writes break hash-chain continuity | Serialize audit-chain head reads and inserts using PostgreSQL transaction-level advisory locking | `test_audit_integrity.py::test_audit_chain_concurrency_continuity` |

**Verification rule:** A test reference is not proof that a test exists or passes. Confirm the test file, test implementation, and execution result before marking a threat as covered. Tests that are skipped must be recorded as skipped, not passed.

## 2. Information Leakage Prevention Guidelines

### 2.1 Uniform HTTP 404 responses

When a user requests a document that either does not exist or is not accessible to them, the API should return the same status and public error message.

Example response:

```json
{
  "detail": "Document not found or access denied"
}
```

Status code: `404 Not Found`.

Verify this behavior separately for document metadata, download, and any other protected document endpoint. Error-message consistency alone does not guarantee that timing or other response details cannot leak information.

### 2.2 Internal audit precision

Where supported by the endpoint and audit implementation, denied-access events should record the actor, action, target, timestamp, request identifier, and denial reason.

Example event fields:

- `result`: `DENIED`
- `action`: the relevant document operation, such as `DOC_READ`
- `actor_id`: authenticated user's identifier, if available
- `target_id`: requested document identifier, if available
- `denial_reason`: a specific internal authorization reason

Do not expose sensitive internal denial details to the client. Verify that audit logging is reliable and that failures are monitored rather than silently ignored.

## 3. Administrative Ownership Transfer Policy

If a document owner leaves the organization or becomes unable to manage their documents, an administrator may transfer ownership only through an explicitly authorized and audited workflow.

1. The destination owner must exist, be active, and be different from the administrator performing the transfer.
2. The ownership change must be atomic.
3. An immutable audit event must identify the administrator, previous owner, new owner, affected document, timestamp, and transfer reason, subject to the available audit schema.
4. **Ownership transfer must not automatically grant the administrator permission to read or download the document content.**
5. The new owner's access must follow the application's documented authorization policy.
6. The transfer operation must fail safely if the database update or required audit operation cannot be completed.

**Implementation status:** Treat this policy as a requirement until the corresponding endpoint, authorization checks, audit behavior, and automated tests have been verified. Do not imply that an ownership-transfer feature already exists unless confirmed in the codebase.

## 4. Verification Limitations and Outstanding Work

The following areas require additional verification or dedicated tests:

- Cross-user document search isolation, if search is implemented.
- Upload-size enforcement: the rejection path is tested with a reduced limit; the configured production limit has not been tested with a full-size upload.
- Filename path-component stripping is tested; Windows-compatible storage symlink-escape testing remains skipped because the current environment lacks the required privilege.
- PDF content-signature rejection is tested; dedicated tests for PNG, JPG, DOCX, XLSX, TXT, and CSV validation remain outstanding.
- Equivalent public responses for nonexistent and unauthorized documents across all protected endpoints.
- Automated tests proving runtime database-role restrictions beyond audit-table immutability, including DDL restrictions.
- Audit logging failure monitoring and document-specific audit coverage.
- Production audit-chain resilience against privileged database or host administrators; external immutable log anchoring is recommended for production.
- Administrative ownership-transfer workflow, if required, until its implementation and authorization tests are verified.

The expired-JWT rejection and administrator-without-permission download tests have been added and passed in the full backend test suite.

Update this matrix whenever tests are added, changed, skipped, or fail. Record actual results and avoid describing unverified security controls as proven.
