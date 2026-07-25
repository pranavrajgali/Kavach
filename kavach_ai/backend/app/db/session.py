import os
from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from kavach_ai.backend.app.db import models  # noqa: F401 - registers SQLModel tables


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SQLITE_URL = f"sqlite+aiosqlite:///{(PROJECT_ROOT / 'kavach_dev.db').as_posix()}"


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return url


DATABASE_URL = _normalize_database_url(os.getenv("KAVACH_DATABASE_URL", DEFAULT_SQLITE_URL))

engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("KAVACH_SQL_ECHO", "false").lower() == "true",
    future=True,
)


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSession(engine) as session:
        yield session
