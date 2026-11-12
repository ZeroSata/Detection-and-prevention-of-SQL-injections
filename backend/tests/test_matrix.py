"""DB Security Lab — итоговая матрица: payload x режим -> результат.

Для каждого вредоносного пейлоада прогоняются 4 комбинации:
  1. Insecure + WAF OFF  — ожидание из payloads.expected (эксплуатация/ошибка/none)
  2. Insecure + WAF ON   — обязан быть BLOCKED (detection rate)
  3. Secure + WAF OFF    — обязан быть безопасным (параметризация)
  4. Secure + WAF ON     — BLOCKED или безопасно

Для легитимных запросов считается false positive rate (WAF ON).
Матрица и метрики пишутся в backend/test_results/ (см. pytest_sessionfinish).
"""
import pytest

from .conftest import (R, classify_login, classify_search, do_login, do_search,
                       record_matrix, TIME_EXPLOIT_THRESHOLD_MS)
from .payloads import EXPECTED_FALSE_POSITIVES, LEGIT, MALICIOUS

OK_FOR_SECURE = {R.EMPTY, R.ROWS, R.AUTH_FAIL, R.AUTH_OK, R.BLOCKED}


@pytest.mark.parametrize("p", MALICIOUS, ids=[p["id"] for p in MALICIOUS])
async def test_malicious_matrix(client, p):
    target = p["target"]
    time_based = p["category"] == "time_based"

    # 1) Insecure + WAF OFF
    if target == "search":
        resp, ms = await do_search(client, "insecure", p["payload"], waf=False)
        r1 = classify_search(resp, ms, time_based=time_based)
    else:
        resp, ms = await do_login(client, "insecure", p["payload"], p.get("password", "guess"), waf=False)
        r1 = classify_login(resp)

    # 2) Insecure + WAF ON
    if target == "search":
        resp2, _ = await do_search(client, "insecure", p["payload"], waf=True)
        r2 = classify_search(resp2, 0)
    else:
        resp2, _ = await do_login(client, "insecure", p["payload"], p.get("password", "guess"), waf=True)
        r2 = classify_login(resp2)

    # 3) Secure + WAF OFF
    if target == "search":
        resp3, ms3 = await do_search(client, "secure", p["payload"], waf=False)
        r3 = classify_search(resp3, ms3, time_based=time_based)
        body3 = resp3.json()
        assert "$2b$" not in str(body3), "хэши паролей не должны эксфильтроваться в secure-режиме"
    else:
        resp3, _ = await do_login(client, "secure", p["payload"], p.get("password", "guess"), waf=False)
        r3 = classify_login(resp3)

    # 4) Secure + WAF ON
    if target == "search":
        resp4, ms4 = await do_search(client, "secure", p["payload"], waf=True)
        r4 = classify_search(resp4, ms4, time_based=time_based)
    else:
        resp4, _ = await do_login(client, "secure", p["payload"], p.get("password", "guess"), waf=True)
        r4 = classify_login(resp4)

    record_matrix({
        "kind": "malicious", "id": p["id"], "category": p["category"], "target": target,
        "payload": p["payload"], "expected": p["expected"],
        "insecure_waf_off": r1, "insecure_waf_on": r2, "secure_waf_off": r3, "secure_waf_on": r4,
    })

    # --- жёсткие требования ТЗ ---
    assert r2 == R.BLOCKED, f"[{p['id']}] WAF не заблокировал пейлоад (insecure+waf on): {r2}"
    assert r3 in OK_FOR_SECURE, f"[{p['id']}] secure+waf off небезопасен: {r3}"
    assert r4 in OK_FOR_SECURE, f"[{p['id']}] secure+waf on небезопасен: {r4}"

    # ожидаемый эффект в уязвимом режиме
    if p["expected"] == "exploit":
        assert r1 == R.EXPLOIT, (
            f"[{p['id']}] ожидалась эксплуатация, получено {r1}. {p.get('note','')}"
        )
    elif p["expected"] == "error":
        assert r1 == R.ERROR, f"[{p['id']}] ожидалась ошибка СУБД, получено {r1}"
    else:  # none: без ошибок и без эффекта
        assert r1 in (R.EMPTY, R.ROWS), f"[{p['id']}] ожидался штатный приём, получено {r1}"


@pytest.mark.parametrize("p", LEGIT, ids=[p["id"] for p in LEGIT])
async def test_legit_matrix(client, p):
    # WAF ON
    if p["target"] == "search":
        resp_on, _ = await do_search(client, "secure", p["value"], waf=True)
        blocked_on = resp_on.status_code == 403
        rows_on = resp_on.json().get("rows_count") if resp_on.status_code == 200 else None
    else:
        resp_on, _ = await do_login(client, "secure", p["value"], p["password"], waf=True)
        blocked_on = resp_on.status_code == 403
        rows_on = None

    # WAF OFF (легитимный сценарий обязан работать)
    if p["target"] == "search":
        resp_off, _ = await do_search(client, "secure", p["value"], waf=False)
        blocked_off = resp_off.status_code == 403
        assert resp_off.status_code == 200, f"[{p['id']}] легитимный поиск сломан"
        assert (resp_off.json()["rows_count"] or 0) >= p["min_rows"]
    else:
        resp_off, _ = await do_login(client, "secure", p["value"], p["password"], waf=False)
        blocked_off = resp_off.status_code == 403
        assert resp_off.json()["authenticated"] is p["expect_auth"], (
            f"[{p['id']}] легитимный вход сломан"
        )

    record_matrix({
        "kind": "legit", "id": p["id"], "category": "legit", "target": p["target"],
        "payload": p["value"],
        "waf_on_blocked": blocked_on, "waf_off_blocked": blocked_off, "rows": rows_on,
    })

    is_expected_fp = p["id"] in EXPECTED_FALSE_POSITIVES
    if not is_expected_fp:
        assert not blocked_on, f"[{p['id']}] неожиданное ложное срабатывание WAF на легитимном запросе"
    else:
        # известный FP фиксируем, но требуем, чтобы это был именно осознанный low-риск
        assert blocked_on, f"[{p['id']}] ожидали задокументированный FP (см. payloads.py), его нет"
