from contextlib import asynccontextmanager

from decouple import config

from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine

from sqlmodel import create_engine, SQLModel, Session
from sqlmodel.ext.asyncio.session import AsyncSession


def get_engine(db_url: str = None, echo: bool = False) -> AsyncEngine:
    if db_url is None:
        db_url = config("TXWTF_API_DATABASE_URL", default="sqlite+aiosqlite://")
    return create_async_engine(db_url, echo=echo)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


@asynccontextmanager
async def get_session(engine):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
