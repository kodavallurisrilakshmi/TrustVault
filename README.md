# TrustVault - Enterprise Secure Document-Sharing Platform

TrustVault is a zero-trust enterprise document-sharing platform engineered with Python FastAPI, PostgreSQL, and React + Vite. It provides discretionary access control (DAC), strict administrative separation of duties, streaming upload verification, and an append-only, tamper-evident audit log with SHA-256 Merkle hash chaining.

---

## 1. Core Security Features

- **Least-Privilege Administrators**: Administrators manage platform users and audit logs, but **cannot read or download confidential document contents** without explicit document owner grants.
- **Immediate Revocation**: Session invalidations (`token_version`) and permission revocations take effect on subsequent requests with zero cache window.
- **Private Local Storage Vault**: Files reside outside the web root, named by high-entropy UUIDs (`storage_vault/ab/cd/<uuid>.bin`). Path traversal (`../../etc/passwd`) is neutralized.
- **Append-Only Immutable Audit Log**: Secured by a PostgreSQL trigger blocking `UPDATE` and `DELETE`, plus a continuous cryptographic SHA-256 Merkle hash chain.
- **Database Privilege Separation**: Application runtime role (`trustvault_app`) lacks DDL and schema alteration rights and is denied `UPDATE`/`DELETE` on `audit_logs`.

---

## 2. Technology Stack

- **Backend**: Python 3.11+ / 3.13, FastAPI (ASGI)
- **Database & ORM**: PostgreSQL with async SQLAlchemy 2.0 (`asyncpg`) and Alembic
- **Testing**: `pytest`, `pytest-asyncio`, `httpx` (AsyncClient)
- **Security**: Argon2id password hashing, PyJWT, streaming SHA-256 digests
- **Frontend**: React 18/19, Vite, modular Vanilla CSS design system

---

## 3. Directory Layout

```
TrustVault/
├── backend/
│   ├── alembic/              # Database schema migrations
│   ├── app/
│   │   ├── api/              # V1 API routes (auth, users, documents, permissions, audit)
│   │   ├── core/             # Config, security (Argon2id/JWT), database engines
│   │   ├── models/           # SQLAlchemy models (User, Document, Permission, AuditLog)
│   │   ├── schemas/          # Pydantic v2 schemas
│   │   ├── services/         # AuditService, DocumentService, StorageService
│   │   └── main.py           # Application entrypoint & health checks
│   ├── tests/                # Automated security integration tests
│   └── requirements.txt      # Pinned backend dependencies
├── frontend/                 # React + Vite application
├── storage_vault/            # Private local storage vault
├── docs/
│   ├── ARCHITECTURE.md       # Full architecture specification
│   └── API.md                # REST API documentation
├── THREATS.md                # STRIDE threat model & test matrix
├── SECURITY.md               # Security policy & disclosure guidelines
├── PROMPTS.md                # Verifiable AI interaction log
└── README.md                 # Setup and execution guide
```

---

## 4. Setup & Installation

### Prerequisites
- Python 3.11+ or 3.13
- PostgreSQL 14+ (or Docker)
- Node.js 18+ and npm

### Backend Setup
1. **Navigate to the backend directory and activate the virtual environment**:
   ```bash
   cd backend
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your PostgreSQL credentials and strong SECRET_KEY
   ```

4. **Initialize Database Roles & Permissions**:
   Connect as PostgreSQL superuser (`postgres`) and execute:
   ```bash
   psql -U postgres -d postgres -f scripts/init_db_roles.sql
   ```

5. **Run Database Migrations**:
   ```bash
   alembic upgrade head
   ```

6. **Start the FastAPI Development Server**:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

### Frontend Setup
1. **Navigate to the frontend directory**:
   ```bash
   cd frontend
   npm install
   ```

2. **Start the Vite Development Server**:
   ```bash
   npm run dev
   ```

---

## 5. Verification & Running Tests

Execute the automated test suite using `pytest`:
```bash
cd backend
pytest tests/ -v
```

Tests cover:
- Health check endpoints and configuration secret masking
- Argon2id password hashing and JWT token verification
- Immediate session revocation via `token_version`
- Tampered JWT signature rejection
- Autonomous audit logging for denied operations
- Cryptographic hash-chain continuity and tamper detection
- Database privilege separation and immutability trigger validation
