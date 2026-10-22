from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)
from app.core.config import settings

# Runtime engine used by application endpoints (least-privilege trustvault_app)
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_APP_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

# Admin engine used for schema migrations, administrative setup, and maintenance
admin_engine: AsyncEngine = create_async_engine(
    settings.DATABASE_ADMIN_URL,
    echo=False,
    future=True,
    pool_pre_ping=True
)

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

admin_session_factory = async_sessionmaker(
    bind=admin_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency providing an active async database session for the request."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
