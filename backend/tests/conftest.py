import os
import uuid
import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Ensure environment uses test configurations
os.environ["APP_ENV"] = "testing"
os.environ["SECRET_KEY"] = "trustvault-test-secret-key-32-bytes-minimum-length!"

from app.core.config import settings
from app.core.database import get_db
import app.services.audit_service as audit_service
from app.models.base import Base
from app.models.user import User
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit_log import AuditLog
from app.core.security import hash_password, create_access_token
from app.main import app

# Check whether PostgreSQL test database is reachable; if not, use SQLite for isolated tests
_postgres_test_url = settings.TEST_DATABASE_URL
# Fallback SQLite test URL
_sqlite_test_url = "sqlite+aiosqlite:///:memory:"

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", _postgres_test_url)

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    future=True
)

test_async_session = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)
# Keep autonomous audit writes isolated in the test database.
audit_service.async_session_factory = test_async_session

@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_test_db():
    """Initialize database tables before tests and tear down after session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

        if "postgresql" in str(test_engine.url):
            await conn.execute(text("""
                CREATE OR REPLACE FUNCTION
                trg_prevent_audit_log_modification()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION
                    'Audit logs are immutable. UPDATE and DELETE are prohibited.';
                END;
                $$ LANGUAGE plpgsql;
            """))

            await conn.execute(text("""
                DROP TRIGGER IF EXISTS trg_audit_logs_immutable
                ON public.audit_logs;
            """))

            await conn.execute(text("""
                CREATE TRIGGER trg_audit_logs_immutable
                BEFORE UPDATE OR DELETE ON public.audit_logs
                FOR EACH ROW
                EXECUTE FUNCTION
                trg_prevent_audit_log_modification();
            """))

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

        if "postgresql" in str(test_engine.url):
            await conn.execute(text("""
                DROP FUNCTION IF EXISTS
                trg_prevent_audit_log_modification();
            """))


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """Provide a clean transactional async session for tests."""
    async with test_async_session() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession):
    """Provide an HTTPX AsyncClient with database dependency overridden."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_admin_user(db_session: AsyncSession) -> User:
    """Create and return a seeded test administrator user."""
    admin = User(
        id=uuid.uuid4(),
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("AdminSecurePassword123!"),
        full_name="Platform Administrator",
        role="admin",
        token_version=1,
        is_active=True
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    return admin


@pytest_asyncio.fixture
async def test_user_a(db_session: AsyncSession) -> User:
    """Create and return seeded User A (Document Owner)."""
    user = User(
        id=uuid.uuid4(),
        email=f"user_a_{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("UserASecurePassword123!"),
        full_name="Alice Owner",
        role="user",
        token_version=1,
        is_active=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_user_b(db_session: AsyncSession) -> User:
    """Create and return seeded User B (Another User)."""
    user = User(
        id=uuid.uuid4(),
        email=f"user_b_{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("UserBSecurePassword123!"),
        full_name="Bob Viewer",
        role="user",
        token_version=1,
        is_active=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def admin_headers(test_admin_user: User) -> dict:
    """Return Authorization headers for test administrator."""
    token = create_access_token(
        user_id=str(test_admin_user.id),
        role=test_admin_user.role,
        token_version=test_admin_user.token_version
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_a_headers(test_user_a: User) -> dict:
    """Return Authorization headers for User A."""
    token = create_access_token(
        user_id=str(test_user_a.id),
        role=test_user_a.role,
        token_version=test_user_a.token_version
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_b_headers(test_user_b: User) -> dict:
    """Return Authorization headers for User B."""
    token = create_access_token(
        user_id=str(test_user_b.id),
        role=test_user_b.role,
        token_version=test_user_b.token_version
    )
    return {"Authorization": f"Bearer {token}"}
