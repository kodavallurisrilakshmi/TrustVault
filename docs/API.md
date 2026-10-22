# TrustVault REST API Specification (V1)

## 1. Global Conventions & Headers

### Base URL
`http://localhost:8000/api/v1`

### Mandatory Request Headers
| Header | Description | Required |
| :--- | :--- | :---: |
| `Authorization` | `Bearer <access_token>` | For all protected routes |
| `X-Request-ID` | Unique UUID correlation identifier (generated if omitted) | Optional (Recommended) |
| `Content-Type` | `application/json` or `multipart/form-data` | Required for POST/PATCH |

### Security Response Headers
- `X-Request-ID`: Returns the request correlation ID for audit tracing.
- `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing.

### Uniform Error Response Format
All client errors follow RFC 7807 structured format:
```json
{
  "detail": "Description of the error condition"
}
```

> [!IMPORTANT]
> **Anti-Enumeration 404 Policy**: Nonexistent and unauthorized document requests return uniform `HTTP 404 Not Found` with message: `"Document not found or access denied"`.

---

## 2. Health & Diagnostic Endpoints

### `GET /health`
- **Description**: Basic liveness probe.
- **Auth**: None.
- **Response**: `200 OK`
```json
{
  "status": "ok",
  "service": "TrustVault"
}
```

### `GET /health/ready`
- **Description**: Readiness probe checking PostgreSQL connectivity and local storage vault directory.
- **Auth**: None.
- **Response**: `200 OK` / `503 Service Unavailable`
```json
{
  "status": "ready",
  "database": "ok",
  "vault": "ok"
}
```

### `GET /health/config`
- **Description**: Deployment configuration verification with all secrets masked.
- **Auth**: None.
- **Response**: `200 OK`

---

## 3. Authentication Endpoints

### `POST /api/v1/auth/register`
- **Description**: Register a new user account with Argon2id password hashing.
- **Auth**: None.
- **Request Body**:
```json
{
  "email": "alice@example.com",
  "password": "SecurePassword123!",
  "full_name": "Alice Document Owner"
}
```
- **Response**: `201 Created`

### `POST /api/v1/auth/login`
- **Description**: Authenticate credentials and receive short-lived JWT access and refresh tokens.
- **Auth**: None.
- **Request Body**:
```json
{
  "email": "alice@example.com",
  "password": "SecurePassword123!"
}
```
- **Response**: `200 OK`
```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "bearer"
}
```

### `POST /api/v1/auth/refresh`
- **Description**: Exchange refresh token for fresh token pair.
- **Auth**: None.
- **Request Body**:
```json
{
  "refresh_token": "eyJhbGciOi..."
}
```
- **Response**: `200 OK`

### `POST /api/v1/auth/logout`
- **Description**: Invalidate current user session immediately across all devices by incrementing `users.token_version`.
- **Auth**: Bearer.
- **Response**: `200 OK`
```json
{
  "message": "Successfully logged out. All active sessions invalidated."
}
```

### `GET /api/v1/auth/me`
- **Description**: Return profile of currently authenticated user.
- **Auth**: Bearer.
- **Response**: `200 OK`

---

## 4. User Management Endpoints (Admin Only)

### `GET /api/v1/users`
- **Description**: List all registered users.
- **Auth**: Bearer (Role: `admin`).
- **Response**: `200 OK`

### `PATCH /api/v1/users/{user_id}/status`
- **Description**: Activate or deactivate user account. Deactivating increments `token_version` to immediately revoke all active sessions.
- **Auth**: Bearer (Role: `admin`).
- **Request Body**:
```json
{
  "is_active": false
}
```
- **Response**: `200 OK`

### `PATCH /api/v1/users/{user_id}/role`
- **Description**: Update user system role (`admin` or `user`).
- **Auth**: Bearer (Role: `admin`).
- **Request Body**:
```json
{
  "role": "admin"
}
```
- **Response**: `200 OK`

---

## 5. Audit Endpoints (Admin Only)

### `GET /api/v1/audit/logs`
- **Description**: Search immutable audit logs with multi-attribute filtering.
- **Auth**: Bearer (Role: `admin`).
- **Query Parameters**:
  - `actor_id` (UUID): Filter by actor user ID
  - `action` (string): Filter by action code (`AUTH_LOGIN`, `DOC_DOWNLOAD`, etc.)
  - `target_type` (string): `user`, `document`, `permission`
  - `target_id` (string): ID of target resource
  - `result` (string): `SUCCESS`, `DENIED`, `ERROR`
  - `from_date`, `to_date` (ISO-8601): Time range
  - `limit` (integer, max 500), `offset` (integer)
- **Response**: `200 OK`

### `GET /api/v1/audit/verify`
- **Description**: Cryptographically verify the sequential SHA-256 Merkle hash chain from genesis.
- **Auth**: Bearer (Role: `admin`).
- **Response**: `200 OK`
```json
{
  "is_valid": true,
  "total_records": 128,
  "broken_record_id": null,
  "expected_hash": null,
  "actual_hash": null,
  "message": "Cryptographic audit chain fully verified (128 records)."
}
```

---

## 6. Document & Permission Endpoints (Planned for Phases 3-4)

- `POST /api/v1/documents/upload`: Streaming upload with size & magic bytes validation.
- `GET /api/v1/documents`: Search & list documents (enforcing owner/viewer DAC boundary).
- `GET /api/v1/documents/{id}`: Document metadata (unified 404 on unshared docs).
- `GET /api/v1/documents/{id}/download`: Authenticated streaming download.
- `DELETE /api/v1/documents/{id}`: Soft/hard delete (Owner only).
- `POST /api/v1/documents/{id}/transfer-ownership`: Atomic administrative ownership transfer.
- `POST /api/v1/documents/{id}/permissions`: Grant `view` or `edit` permission (Owner only).
- `DELETE /api/v1/documents/{id}/permissions/{user_id}`: Immediate permission revocation (Owner only).
