"""DB Security Lab — общая инфраструктура pytest: клиент, классификация результатов, матрица."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

# Окружение тестов. Значения по умолчанию соответствуют docker compose
# (проброс порта 5432). В песочнице экспортируется DB_PORT=55432.
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "securedemo")
os.environ.setdefault("DB_ADMIN_USER", "app_admin")
os.environ.setdefault("DB_ADMIN_PASSWORD", "admin_change_me")
os.environ.setdefault("DB_READONLY_USER", "app_readonly")
os.environ.setdefault("DB_READONLY_PASSWORD", "readonly_change_me")
os.environ.setdefault("DB_LOGGER_USER", "app_logger")
os.environ.setdefault("DB_LOGGER_PASSWORD", "logger_change_me")
os.environ.setdefault("WAF_DEFAULT_ENABLED", "true")

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.main import app  # noqa: E402

RESULTS_DIR = BACKEND_DIR / "test_results"
MATRIX_ROWS: list[dict] = []


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="session")
def ensure_db():
    """Проверяет, что БД инициализирована (инструкция — см. README)."""
    import asyncio

    import asyncpg

    async def _check():
        conn = await asyncpg.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ["DB_PORT"]),
            user=os.environ["DB_ADMIN_USER"],
            password=os.environ["DB_ADMIN_PASSWORD"],
            database=os.environ["DB_NAME"],
        )
        try:
            n = await conn.fetchval("SELECT count(*) FROM users")
        finally:
            await conn.close()
        return n

    try:
        n = asyncio.run(_check())
    except Exception as exc:  # pragma: no cover
        pytest.exit(
            f"\n[conftest] БД недоступна или схема не создана ({exc}).\n"
            "Инициализируйте БД: 'docker compose up postgres' (авто-инициализация)\n"
            "или 'python scripts/local_init.py --dsn postgresql://<superuser>@127.0.0.1:5432/postgres'\n",
            returncode=3,
        )
    if not n:
        pytest.exit("[conftest] Таблица users пуста — выполните seed (scripts/local_init.py)", returncode=3)


@pytest.fixture
async def client(ensure_db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


# ------------------------------------------------------------------ helpers
def _hdr(waf: bool) -> dict:
    return {"X-WAF-Enabled": "true" if waf else "false"}


async def do_search(client: AsyncClient, mode: str, q: str, waf: bool):
    """Поиск. % в пейлоаде сохраняется (safe='%') — контроль кодирования за тестом."""
    url = f"/api/{mode}/search?q={quote(q, safe='%')}"
    t0 = time.perf_counter()
    resp = await client.get(url, headers=_hdr(waf))
    ms = int((time.perf_counter() - t0) * 1000)
    return resp, ms


async def do_login(client: AsyncClient, mode: str, username: str, password: str, waf: bool):
    t0 = time.perf_counter()
    resp = await client.post(
        f"/api/{mode}/login",
        json={"username": username, "password": password},
        headers=_hdr(waf),
    )
    ms = int((time.perf_counter() - t0) * 1000)
    return resp, ms


class R:
    BLOCKED = "BLOCKED"      # 403 от WAF
    EXPLOIT = "EXPLOIT"      # инъекция дала видимый эффект (данные/вход/задержка)
    ERROR = "ERROR"          # ошибка СУБД, всплывшая наружу
    EMPTY = "EMPTY"          # штатный пустой результат
    ROWS = "ROWS"            # штатный результат со строками
    AUTH_OK = "AUTH_OK"      # легитимный вход
    AUTH_FAIL = "AUTH_FAIL"  # отказ во входе


TIME_EXPLOIT_THRESHOLD_MS = 1500  # pg_sleep(2): EMPTY + задержка => EXPLOIT


def classify_search(resp, ms: int, *, time_based: bool = False) -> str:
    if resp.status_code == 403:
        return R.BLOCKED
    d = resp.json()
    if d.get("db_error"):
        return R.ERROR
    rows = d.get("rows_count", 0)
    if rows > 0:
        return R.EXPLOIT
    if time_based and ms >= TIME_EXPLOIT_THRESHOLD_MS:
        return R.EXPLOIT
    return R.EMPTY


def classify_login(resp) -> str:
    if resp.status_code == 403:
        return R.BLOCKED
    d = resp.json()
    if d.get("db_error"):
        return R.ERROR
    if d.get("authenticated"):
        return R.EXPLOIT  # для malicious: вход через инъекцию = успех эксплуатации
    return R.AUTH_FAIL


def record_matrix(row: dict) -> None:
    MATRIX_ROWS.append(row)


def pytest_sessionfinish(session, exitstatus):
    """По завершении сессии пишет матрицу payload x режим и метрики."""
    if not MATRIX_ROWS:
        return
    RESULTS_DIR.mkdir(exist_ok=True)

    import json

    malicious = [r for r in MATRIX_ROWS if r["kind"] == "malicious"]
    legit = [r for r in MATRIX_ROWS if r["kind"] == "legit"]

    det_total = len(malicious)
    det_blocked = sum(1 for r in malicious if r["insecure_waf_on"] == R.BLOCKED)
    fp_total = len(legit)
    fp_blocked = sum(1 for r in legit if r["waf_on_blocked"])
    secure_exploits = sum(1 for r in malicious if r["secure_waf_off"] in (R.EXPLOIT, R.ERROR))

    metrics = {
        "malicious_total": det_total,
        "waf_detection_rate": round(det_blocked / det_total, 4) if det_total else None,
        "waf_detected": det_blocked,
        "legit_total": fp_total,
        "false_positive_rate": round(fp_blocked / fp_total, 4) if fp_total else None,
        "false_positives": [r["id"] for r in legit if r["waf_on_blocked"]],
        "secure_mode_exploits_or_errors": secure_exploits,
        "secure_mode_safe": secure_exploits == 0,
    }

    (RESULTS_DIR / "matrix.json").write_text(
        json.dumps({"rows": MATRIX_ROWS, "metrics": metrics}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "# DB Security Lab — матрица «пейлоад × режим → результат»",
        "",
        f"Дата: {time.strftime('%Y-%m-%d %H:%M:%S')} · генерируется автоматически (tests/conftest.py)",
        "",
        "Обозначения: BLOCKED — 403 от WAF; EXPLOIT — видимый эффект инъекции (данные/вход/задержка);",
        "ERROR — ошибка СУБД всплыла наружу; EMPTY/AUTH_FAIL — штатная безопасная обработка.",
        "",
        "## Вредоносные пейлоады",
        "",
        "| id | категория | цель | пейлоад | Insecure+WAF OFF | Insecure+WAF ON | Secure+WAF OFF | Secure+WAF ON |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in malicious:
        p = r["payload"].replace("|", "\\|")
        lines.append(
            f"| {r['id']} | {r['category']} | {r['target']} | `{p}` "
            f"| {r['insecure_waf_off']} | {r['insecure_waf_on']} | {r['secure_waf_off']} | {r['secure_waf_on']} |"
        )
    lines += [
        "",
        "## Легитимные запросы (проверка ложных срабатываний)",
        "",
        "| id | цель | ввод | WAF ON | WAF OFF | ложное срабатывание |",
        "|---|---|---|---|---|---|",
    ]
    for r in legit:
        v = r["payload"].replace("|", "\\|")
        lines.append(
            f"| {r['id']} | {r['target']} | `{v}` "
            f"| {'BLOCKED' if r['waf_on_blocked'] else 'PASS'} | {'BLOCKED' if r['waf_off_blocked'] else 'PASS'} | "
            f"{'ДА' if r['waf_on_blocked'] else 'нет'} |"
        )
    lines += [
        "",
        "## Метрики",
        "",
        f"- Malicious пейлоадов: **{metrics['malicious_total']}**",
        f"- WAF detection rate (Insecure+WAF ON, доля заблокированных): **{metrics['waf_detection_rate']}**",
        f"- Легитимных запросов: **{metrics['legit_total']}**, ложных срабатываний: "
        f"**{len(metrics['false_positives'])}** ({metrics['false_positives']})",
        f"- False positive rate: **{metrics['false_positive_rate']}**",
        f"- Эксплуатаций/ошибок в Secure-режиме (WAF OFF): **{metrics['secure_mode_exploits_or_errors']}** "
        f"(параметризация безопасна: {metrics['secure_mode_safe']})",
        "",
    ]
    (RESULTS_DIR / "matrix.md").write_text("\n".join(lines), encoding="utf-8")
