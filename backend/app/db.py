"""DB Security Lab — асинхронные движки SQLAlchemy 2.x под роли наименьших привилегий.

Три отдельных пула подключений:
  * admin_engine    (app_admin)    — инициализация/миграции, health-check;
  * readonly_engine (app_readonly) — демо-запросы (включая УЯЗВИМЫЕ эндпоинты);
  * logger_engine   (app_logger)   — запись audit_logs/incidents, чтение для дашборда.
"""
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.engine import URL

from .config import get_settings


def _make_url(username: str, password: str) -> URL:
    s = get_settings()
    return URL.create(
        "postgresql+asyncpg",
        username=username,
        password=password,
        host=s.db_host,
        port=s.db_port,
        database=s.db_name,
    )


def _make_engine(username: str, password: str, app_name: str):
    return create_async_engine(
        _make_url(username, password),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        connect_args={"server_settings": {"application_name": app_name}},
    )


admin_engine = _make_engine(get_settings().db_admin_user, get_settings().db_admin_password, "lab-admin")
readonly_engine = _make_engine(get_settings().db_readonly_user, get_settings().db_readonly_password, "lab-readonly")
logger_engine = _make_engine(get_settings().db_logger_user, get_settings().db_logger_password, "lab-logger")

AdminSessionLocal = async_sessionmaker(admin_engine, class_=AsyncSession, expire_on_commit=False)
ReadonlySessionLocal = async_sessionmaker(readonly_engine, class_=AsyncSession, expire_on_commit=False)
LoggerSessionLocal = async_sessionmaker(logger_engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def admin_session():
    async with AdminSessionLocal() as session:
        yield session


@asynccontextmanager
async def readonly_session():
    async with ReadonlySessionLocal() as session:
        yield session


@asynccontextmanager
async def logger_session():
    async with LoggerSessionLocal() as session:
        yield session


async def check_db() -> bool:
    """Быстрая проверка доступности БД (под демо-ролью readonly)."""
    try:
        async with readonly_session() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def dispose_all() -> None:
    for engine in (admin_engine, readonly_engine, logger_engine):
        await engine.dispose()
