"""DB Security Lab — защищённые эндпоинты: параметризованные запросы SQLAlchemy.

Ввод НИКОГДА не подставляется в текст SQL: передаётся отдельно как параметр
(:name). СУБД компилирует шаблон и данные раздельно — изменение структуры
запроса через ввод невозможно.
"""
from fastapi import APIRouter, Query, Request
from sqlalchemy import text

from ..context import set_generated_sql
from ..db import readonly_session
from ..schemas import LoginRequest
from ..security import verify_password
from ..utils import jsonable

router = APIRouter(prefix="/api/secure", tags=["secure (parameterized)"])


@router.get("/search", summary="Поиск товаров — ЗАЩИЩЁННЫЙ (параметризованный запрос)")
async def secure_search(request: Request, q: str = Query(min_length=1, max_length=256)):
    template = (
        "SELECT id, name, category, price FROM products "
        "WHERE name ILIKE :term OR category ILIKE :term ORDER BY id LIMIT 50"
    )
    params = {"term": f"%{q}%"}
    set_generated_sql(request, f"{template}  -- параметры: {params}")

    async with readonly_session() as session:
        rows = (await session.execute(text(template), params)).mappings().all()

    return {
        "mode": "secure",
        "sql": template,
        "params": params,
        "rows": [jsonable(r) for r in rows],
        "rows_count": len(rows),
        "note": ("Ввод передан отдельным параметром (:term). Кавычки и ключевые слова "
                 "во вводе интерпретируются как ДАННЫЕ, а не как SQL."),
    }


@router.post("/login", summary="Вход — ЗАЩИЩЁННЫЙ (параметризованный запрос + bcrypt)")
async def secure_login(request: Request, body: LoginRequest):
    template = (
        "SELECT id, username, full_name, role, password_hash, is_active FROM users "
        "WHERE username = :username LIMIT 1"
    )
    params = {"username": body.username}
    set_generated_sql(request, f"{template}  -- параметры: username=***")

    async with readonly_session() as session:
        row = (await session.execute(text(template), params)).mappings().first()

    if row is None:
        reason = "user_not_found"
    elif not row["is_active"]:
        reason = "inactive"
    elif not verify_password(body.password, row["password_hash"]):
        reason = "bad_password"
    else:
        reason = "ok"

    user = None
    if reason == "ok":
        user = jsonable(row)
        user.pop("password_hash", None)

    return {
        "mode": "secure",
        "sql": template,
        "params": {"username": body.username, "password": "*** (проверка bcrypt вне SQL)"},
        "authenticated": reason == "ok",
        "reason": reason,
        "user": user,
        "note": ("Пользователь ищется параметризованным запросом, пароль проверяется "
                 "bcrypt-сравнением с хэшем. Инъекция во вводе невозможна."),
    }
