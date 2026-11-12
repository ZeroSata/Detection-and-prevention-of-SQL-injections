"""DB Security Lab — FastAPI-приложение.

ДЕМО-СТЕНД ДЛЯ ОБУЧЕНИЯ. Содержит намеренно уязвимые эндпоинты
(app/routers/insecure.py). Не выставлять в публичную сеть.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from .config import get_settings
from .db import check_db, dispose_all
from .logging_setup import setup_logging
from .middleware import WafAuditMiddleware
from .routers import dashboard, insecure, secure

logger = logging.getLogger("lab.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    setup_logging(s.log_level)
    logger.info(
        "application startup",
        extra={"event": "startup", "detail": (
            f"db={s.db_host}:{s.db_port}/{s.db_name}; "
            f"roles: admin={s.db_admin_user}, readonly={s.db_readonly_user}, logger={s.db_logger_user}; "
            f"waf_default={s.waf_default_enabled}"
        )},
    )
    yield
    await dispose_all()
    logger.info("application shutdown", extra={"event": "shutdown"})


app = FastAPI(
    title="DB Security Lab API",
    description=(
        "Учебный прототип подсистемы аудита, мониторинга и защиты БД: "
        "SQLi Playground (insecure/secure + WAF), журнал аудита, инциденты, корреляция. "
        "Содержит НАМЕРЕННО УЯЗВИМЫЕ эндпоинты — только для изолированного стенда."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# Порядок: WafAudit добавлен первым -> он ВНУТРИ CORS-обёртки,
# поэтому на 403-ответы WAF тоже навешиваются CORS-заголовки.
app.add_middleware(WafAuditMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(insecure.router)
app.include_router(secure.router)
app.include_router(dashboard.router)
app.include_router(dashboard.meta)


@app.get("/api/health", tags=["meta"], summary="Health-check (приложение + БД)")
async def health():
    db_ok = await check_db()
    if not db_ok:
        return JSONResponse(status_code=503, content={"status": "down", "db": "unavailable"})
    return {
        "status": "ok",
        "db": "up",
        "waf_default_enabled": get_settings().waf_default_enabled,
    }
