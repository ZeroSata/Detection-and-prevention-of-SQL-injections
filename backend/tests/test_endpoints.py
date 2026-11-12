"""DB Security Lab — функциональные тесты эндпоинтов, аудита, корреляции и дашборда."""
import pytest

from .conftest import do_login, do_search
from .payloads import LEGIT


async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok" and body["db"] == "up"


async def test_insecure_search_returns_generated_sql(client):
    resp, ms = await do_search(client, "insecure", "ноутбук", waf=False)
    assert resp.status_code == 200
    d = resp.json()
    assert d["mode"] == "insecure" and d["params"] is None
    assert "ноутбук" in d["sql"] and "ILIKE" in d["sql"].upper()
    assert d["rows_count"] >= 1
    assert ms < 1500


async def test_secure_search_parameterized(client):
    resp, _ = await do_search(client, "secure", "ноутбук", waf=False)
    d = resp.json()
    assert d["params"]["term"] == "%ноутбук%"
    assert ":term" in d["sql"]
    assert d["rows_count"] >= 1


async def test_secure_search_injection_is_data(client):
    """Параметризация: та же тавтология в secure-режиме не возвращает данных."""
    resp, _ = await do_search(client, "secure", "' OR '1'='1", waf=False)
    d = resp.json()
    assert resp.status_code == 200
    assert d["rows_count"] == 0
    assert not d.get("db_error")


async def test_insecure_login_bypass(client):
    resp, _ = await do_login(client, "insecure", "admin'--", "any", waf=False)
    d = resp.json()
    assert d["authenticated"] is True
    assert d["user"]["username"] == "admin"
    assert "password_hash" not in d["user"]  # хэш не отдаётся в ответе


async def test_secure_login_legit_and_wrong_password(client):
    ok, _ = await do_login(client, "secure", "admin", "admin123", waf=False)
    assert ok.json()["authenticated"] is True
    assert ok.json()["reason"] == "ok"

    bad, _ = await do_login(client, "secure", "admin", "wrong-password", waf=False)
    assert bad.json()["authenticated"] is False
    assert bad.json()["reason"] == "bad_password"

    nope, _ = await do_login(client, "secure", "no_such_user", "x", waf=False)
    assert nope.json()["reason"] == "user_not_found"


async def test_stacked_queries_do_not_execute(client):
    """Двойная защита stacked-атак: asyncpg не исполняет несколько операторов,
    а роль app_readonly не имеет прав на изменение данных."""
    resp, _ = await do_search(client, "insecure", "zz'; DROP TABLE products--", waf=False)
    d = resp.json()
    assert d.get("db_error")  # ошибка всплыла (это демо!), но...
    # таблица на месте и доступна
    check, _ = await do_search(client, "secure", "ноутбук", waf=False)
    assert check.json()["rows_count"] >= 1


async def test_waf_block_response_and_incident_created(client):
    payload = "zz%' UNION SELECT 1,2,3,4--"
    resp, _ = await do_search(client, "insecure", payload, waf=True)
    assert resp.status_code == 403
    d = resp.json()
    assert d["blocked"] is True
    assert d["matched_rule"] == "SQLI-UNION-SELECT"
    assert d["attack_type"] == "union"
    assert d["risk_level"] in ("medium", "high", "critical")
    assert isinstance(d["incident_id"], int)

    # инцидент доступен через дашборд, связан с записью аудита blocked
    det = await client.get(f"/api/dashboard/incidents/{d['incident_id']}")
    assert det.status_code == 200
    body = det.json()
    assert body["incident"]["payload"] == payload
    assert body["audit_log"]["result_status"] == "blocked"


async def test_waf_toggle_off_disables_block(client):
    resp, _ = await do_search(client, "insecure", "zz';", waf=False)
    assert resp.status_code == 200  # без WAF доходит до СУБД (и даёт ошибку SQL в теле)


async def test_waf_toggle_via_query_param(client):
    resp = await client.get("/api/insecure/search", params={"q": "zz'--", "waf": "false"})
    assert resp.status_code == 200
    resp = await client.get("/api/insecure/search", params={"q": "zz'--", "waf": "true"})
    assert resp.status_code == 403


async def test_incident_status_change_flow(client):
    # создаём инцидент
    resp, _ = await do_search(client, "insecure", "zz%' OR 1=1--", waf=True)
    incident_id = resp.json()["incident_id"]

    for status in ("investigating", "closed", "new"):
        r = await client.patch(f"/api/dashboard/incidents/{incident_id}/status", json={"status": status})
        assert r.status_code == 200
        assert r.json()["status"] == status

    # некорректный статус -> 422 (Pydantic)
    r = await client.patch(f"/api/dashboard/incidents/{incident_id}/status", json={"status": "hacked"})
    assert r.status_code == 422

    # несуществующий инцидент -> 404
    r = await client.patch("/api/dashboard/incidents/999999/status", json={"status": "closed"})
    assert r.status_code == 404


async def test_correlation_escalates_risk(client):
    """4 блокировки low-рискового правила (кавычка) с одного IP за короткое окно
    -> корреляция обязана поднять риск до high."""
    ip = "10.255.255.7"
    incident_id = None
    for _ in range(4):
        resp = await client.get(
            "/api/insecure/search",
            params={"q": 'zzzz"'},
            headers={"X-Forwarded-For": ip, "X-WAF-Enabled": "true"},
        )
        assert resp.status_code == 403
        incident_id = resp.json()["incident_id"]

    det = await client.get(f"/api/dashboard/incidents/{incident_id}")
    inc = det.json()["incident"]
    assert inc["risk_level"] in ("high", "critical")
    assert inc["escalated"] is True


async def test_dashboard_stats_shape(client):
    resp = await client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    s = resp.json()
    for key in ("incidents_total", "by_risk", "by_type", "timeline", "top_ips",
                "requests_total", "blocked_total", "avg_response_ms"):
        assert key in s
    assert set(s["by_risk"]) == {"low", "medium", "high", "critical"}
    assert len(s["timeline"]) == 60


async def test_audit_logs_written(client):
    resp, _ = await do_search(client, "insecure", "ноутбук", waf=False)
    logs = (await client.get("/api/dashboard/audit-logs", params={"mode": "insecure", "page_size": 20})).json()
    assert logs["total"] >= 1
    item = logs["items"][0]
    for key in ("ts", "source_ip", "endpoint", "mode", "waf_enabled", "raw_input",
                "generated_sql", "result_status", "response_time_ms"):
        assert key in item
    # среди последних insecure-запросов находим выполненный (не заблокированный) — с SQL
    executed = [i for i in logs["items"] if i["generated_sql"].startswith("SELECT")]
    assert executed, "нет записей с сгенерированным SQL"
    assert "ноутбук" in executed[0]["generated_sql"]


async def test_validation_errors_422(client):
    r = await client.get("/api/insecure/search", params={"q": ""})
    assert r.status_code == 422
    r = await client.post("/api/insecure/login", json={"username": "x"})
    assert r.status_code == 422
    r = await client.get("/api/secure/search", params={"q": "x" * 300})
    assert r.status_code == 422


async def test_meta_waf_rules(client):
    r = await client.get("/api/meta/waf-rules")
    rules = r.json()["rules"]
    assert len(rules) >= 10
    ids = {x["rule_id"] for x in rules}
    assert "SQLI-TAUTOLOGY" in ids and "SQLI-TIME-BASED" in ids
