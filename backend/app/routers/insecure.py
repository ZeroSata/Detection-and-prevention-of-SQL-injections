"""
================================================================================
 ВНИМАНИЕ: INTENTIONALLY VULNERABLE — НАМЕРЕННО УЯЗВИМЫЙ УЧЕБНЫЙ КОД
================================================================================
 Эндпоинты этого модуля собирают SQL КОНКАТЕНАЦИЕЙ СТРОК и уязвимы к
 SQL-инъекциям. Это демонстрация анти-паттерна для учебного стенда
 "DB Security Lab". 

 Ограничения безопасности, снижающие риск стенда:
   * работают ТОЛЬКО с демо-данными (users/products, без PII);
   * выполняются под ролью БД app_readonly (только SELECT) — DROP/UPDATE/DELETE
     отклоняются СУБД даже при успешной инъекции;
   * каждый запрос логируется в audit_logs с полным сгенерированным SQL.
 НИ ПРИ КАКИХ УСЛОВИЯХ НЕ КОПИРУЙТЕ ЭТОТ КОД В РЕАЛЬНЫЕ ПРОЕКТЫ.
================================================================================
"""
from fastapi import APIRouter, Query, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ..context import set_generated_sql, set_result_status
from ..db import readonly_session
from ..schemas import LoginRequest
from ..utils import jsonable

router = APIRouter(prefix="/api/insecure", tags=["insecure (INTENTIONALLY VULNERABLE)"])

WARNING = ("Уязвимый эндпоинт: SQL собран конкатенацией строк. "
           "Только для демонстрации SQL-инъекций на демо-данных.")


@router.get("/search", summary="Поиск товаров — УЯЗВИМЫЙ (конкатенация строк)")
async def insecure_search(request: Request, q: str = Query(min_length=1, max_length=256)):
    """Демонстрация SQL-инъекции через параметр поиска.

    SQL формируется подстановкой ввода прямо в шаблон — символ кавычки
    позволяет изменить структуру запроса (UNION, OR-тавтология и т.д.).
    Возвращает сгенерированный SQL и результат СУБД (или текст ошибки).
    """
    sql = (
        "SELECT id, name, category, price FROM products "
        f"WHERE name ILIKE '%{q}%' OR category ILIKE '%{q}%' ORDER BY id LIMIT 50"
    )
    set_generated_sql(request, sql)
    try:
        async with readonly_session() as session:
            rows = (await session.execute(text(sql))).mappings().all()
    except SQLAlchemyError as exc:
        set_result_status(request, "error")
        return {
            "mode": "insecure",
            "sql": sql,
            "params": None,
            "rows": [],
            "rows_count": 0,
            "db_error": str(exc)[:400],
            "warning": WARNING,
        }
    return {
        "mode": "insecure",
        "sql": sql,
        "params": None,
        "rows": [jsonable(r) for r in rows],
        "rows_count": len(rows),
        "warning": WARNING,
    }


@router.post("/login", summary="Вход — УЯЗВИМЫЙ (конкатенация строк)")
async def insecure_login(request: Request, body: LoginRequest):
    """Демонстрация обхода аутентификации через SQL-инъекцию.

    Пароль сравнивается СРАЗУ в SQL: если инъекция в username добавляет
    OR-тавтологию и усекает хвост комментарием, проверка пароля обходится
    (аутентификация = наличие строк в результате).
    """
    sql = (
        "SELECT id, username, full_name, role, password_hash FROM users "
        f"WHERE username = '{body.username}' AND password_hash = '{body.password}'"
    )
    set_generated_sql(request, sql)
    try:
        async with readonly_session() as session:
            rows = (await session.execute(text(sql))).mappings().all()
    except SQLAlchemyError as exc:
        set_result_status(request, "error")
        return {
            "mode": "insecure",
            "sql": sql,
            "authenticated": False,
            "user": None,
            "matched_rows": 0,
            "db_error": str(exc)[:400],
            "warning": WARNING,
        }
    user = jsonable(rows[0]) if rows else None
    if user is not None:
        # Не отдаём хэш пароля в ответе (демонстрируется UNION-экфильтрацией в search).
        user.pop("password_hash", None)
    return {
        "mode": "insecure",
        "sql": sql,
        "authenticated": bool(rows),
        "user": user,
        "matched_rows": len(rows),
        "warning": WARNING,
    }
