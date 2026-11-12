#!/usr/bin/env python3
"""
DB Security Lab — локальная инициализация БД БЕЗ Docker.

Выполняет те же SQL-скрипты, что и docker-entrypoint-initdb.d в контейнере:
  1) db/init/01_schema.sql  — схема
  2) db/init/roles.sql.tpl  — роли наименьших привилегий (пароли из окружения)
  3) db/init/03_seed.sql    — демо-данные (bcrypt-хэши)

Использование:
  python scripts/local_init.py --dsn postgresql://postgres:postgres@127.0.0.1:55432/postgres

Пароли ролей берутся из переменных окружения APP_READONLY_PASSWORD /
APP_LOGGER_PASSWORD / POSTGRES_ADMIN_USER / POSTGRES_ADMIN_PASSWORD
(значения по умолчанию — только для локального учебного стенда).
"""
import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

import asyncpg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INIT_DIR = PROJECT_ROOT / "db" / "init"


def split_sql_statements(sql: str) -> list[str]:
    """Разбиение SQL на стейтменты с учётом '', $$..$$, -- и /* */ комментариев."""
    stmts: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    in_q = in_line = in_block = False
    dollar: str | None = None
    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if in_line:
            buf.append(c)
            if c == "\n":
                in_line = False
            i += 1
            continue
        if in_block:
            buf.append(c)
            if c == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block = False
                continue
            i += 1
            continue
        if dollar:
            if sql.startswith(dollar, i):
                buf.append(dollar)
                i += len(dollar)
                dollar = None
                continue
            buf.append(c)
            i += 1
            continue
        if in_q:
            buf.append(c)
            if c == "'":
                if nxt == "'":
                    buf.append(nxt)
                    i += 2
                    continue
                in_q = False
            i += 1
            continue
        if c == "-" and nxt == "-":
            in_line = True
            buf.append(c)
            i += 1
            continue
        if c == "/" and nxt == "*":
            in_block = True
            buf.append(c)
            i += 1
            continue
        if c == "'":
            in_q = True
            buf.append(c)
            i += 1
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                dollar = m.group(0)
                buf.append(dollar)
                i += len(dollar)
                continue
        if c == ";":
            s = "".join(buf).strip()
            if s:
                stmts.append(s)
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
    return [s for s in stmts if not all(line.lstrip().startswith("--") or not line.strip() for line in s.splitlines())]


def dsn_with_db(dsn: str, dbname: str) -> str:
    m = re.match(r"^(postgres(ql)?://[^/]+)/[^/]*(\?.*)?$", dsn)
    if not m:
        raise ValueError(f"Не удалось разобрать DSN: {dsn}")
    return f"{m.group(1)}/{dbname}"


async def run_file(conn: asyncpg.Connection, path: Path) -> int:
    sql = path.read_text(encoding="utf-8")
    stmts = split_sql_statements(sql)
    for idx, stmt in enumerate(stmts, 1):
        head = stmt.strip().splitlines()[0][:80]
        try:
            await conn.execute(stmt)
        except Exception as e:
            print(f"[local_init] ОШИБКА в {path.name}, стейтмент #{idx} ({head}...): {e}", file=sys.stderr)
            raise
    print(f"[local_init] {path.name}: выполнено {len(stmts)} стейтментов")
    return len(stmts)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True, help="DSN суперпользователя (например postgresql://postgres:postgres@127.0.0.1:5432/postgres)")
    ap.add_argument("--db", default=os.environ.get("POSTGRES_DB", "securedemo"))
    args = ap.parse_args()

    ro_pwd = os.environ.get("APP_READONLY_PASSWORD", "readonly_change_me")
    lg_pwd = os.environ.get("APP_LOGGER_PASSWORD", "logger_change_me")
    admin_user = os.environ.get("POSTGRES_ADMIN_USER", "app_admin")
    admin_pwd = os.environ.get("POSTGRES_ADMIN_PASSWORD", "admin_change_me")

    # 0) база данных
    conn = await asyncpg.connect(args.dsn)
    exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", args.db)
    if not exists:
        await conn.execute(f'CREATE DATABASE "{args.db}"')
        print(f"[local_init] база {args.db} создана")
    await conn.close()

    conn = await asyncpg.connect(dsn_with_db(args.dsn, args.db))

    # 1) схема
    await run_file(conn, INIT_DIR / "01_schema.sql")

    # 2) роли (шаблон -> подстановка паролей из окружения)
    tpl = (INIT_DIR / "roles.sql.tpl").read_text(encoding="utf-8")
    tpl = tpl.replace("__READONLY_PWD__", ro_pwd).replace("__LOGGER_PWD__", lg_pwd)
    for stmt in split_sql_statements(tpl):
        await conn.execute(stmt)
    print("[local_init] роли app_readonly / app_logger созданы, права выданы")

    # роль администрирования (локально — владелец объектов, не суперпользователь)
    arow = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", admin_user)
    if not arow:
        await conn.execute(f"CREATE ROLE {admin_user} LOGIN PASSWORD '{admin_pwd}'")
    else:
        await conn.execute(f"ALTER ROLE {admin_user} PASSWORD '{admin_pwd}'")

    # 3) seed
    await run_file(conn, INIT_DIR / "03_seed.sql")

    # владелец объектов — роль администрирования (не суперпользователь)
    for t in ("users", "products", "audit_logs", "incidents"):
        await conn.execute(f"ALTER TABLE {t} OWNER TO {admin_user}")
        await conn.execute(f"ALTER SEQUENCE IF EXISTS {t}_id_seq OWNER TO {admin_user}")
    print(f"[local_init] владелец объектов: {admin_user}")

    # контроль
    users_n = await conn.fetchval("SELECT count(*) FROM users")
    prods_n = await conn.fetchval("SELECT count(*) FROM products")
    print(f"[local_init] готово: users={users_n}, products={prods_n}, db={args.db}")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
