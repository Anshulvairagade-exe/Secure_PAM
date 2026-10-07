"""
Database session management — async SQLAlchemy engine and session factory.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

# Create async engine with connection pooling.
# echo is intentionally always False: SQLAlchemy's echo=True attaches its
# own raw StreamHandler directly to the "sqlalchemy.engine" logger, which
# then duplicates every line through our structlog-formatted root handler
# too. SQL statement logging is controlled via that logger's level instead
# (see app/core/logging.py — enabled at INFO when settings.DEBUG is true).
#
# Under pytest, each test may run on its own asyncio event loop, but a
# pooled asyncpg connection is bound to the loop it was created on — reusing
# it from a different loop raises "Event loop is closed" / "attached to a
# different loop". NullPool opens a fresh connection per checkout and
# closes it on checkin, so no connection ever survives across a loop
# boundary. Production/dev keep real pooling.
_pool_kwargs = (
    {"poolclass": NullPool}
    if settings.ENVIRONMENT == "test"
    else {"pool_size": 20, "max_overflow": 10, "pool_recycle": 300}
)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    **_pool_kwargs,
)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """
    Dependency that yields an async database session.
    Ensures proper cleanup on completion or error.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Verify database connectivity on startup."""
    async with engine.begin() as conn:
        # Just verify we can connect
        await conn.execute(text("SELECT 1"))


async def close_db() -> None:
    """Close the database engine on shutdown."""
    await engine.dispose()


from sqlalchemy import text
