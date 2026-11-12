"""DB Security Lab — WAF-middleware + аудит-логирование (единый конвейер).

Логика обработки каждого /api-запроса:
  1. WAF вкл/выкл: заголовок X-WAF-Enabled или query-параметр `waf`
     (по умолчанию — WAF_DEFAULT_ENABLED из окружения).
  2. Сбор проверяемых значений: query-параметры, строковые значения тела JSON,
     избранные заголовки (User-Agent, Referer, X-Forwarded-For, X-*).
  3. Проверка по сигнатурам (raw + нормализованная копия, см. app/waf.py).
  4. При срабатывании: HTTP 403 + запись в audit_logs (result_status=blocked)
     + регистрация инцидента через движок корреляции.
  5. При пропуске: после ответа эндпоинта — запись в audit_logs
     (ok/error) с generated_sql из contextvar и временем ответа.

ОШИБКИ ЗАПИСИ АУДИТА не ломают основной ответ (фиксируются в журнале приложения).
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from sqlalchemy import insert
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import waf
from .config import get_settings
from .context import get_generated_sql, get_result_status
from .correlation import register_incident
from .db import logger_session
from .models import AuditLog

logger = logging.getLogger("lab.waf")
audit_logger = logging.getLogger("lab.audit")

TRUTHY = {"true", "1", "on", "yes"}
FALSY = {"false", "0", "off", "no"}

CHECKED_HEADERS = ("user-agent", "referer", "x-forwarded-for", "x-requested-with")
DOCS_PREFIXES = ("/api/docs", "/api/openapi.json", "/api/redoc")


def derive_mode(path: str) -> str:
    if "/api/insecure" in path:
        return "insecure"
    if "/api/secure" in path:
        return "secure"
    if "/api/dashboard" in path or "/api/meta" in path:
        return "dashboard"
    return "other"


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def resolve_waf_enabled(request: Request, default: bool) -> bool:
    header = request.headers.get("x-waf-enabled")
    if header is not None:
        v = header.strip().lower()
        if v in TRUTHY:
            return True
        if v in FALSY:
            return False
    q = request.query_params.get("waf")
    if q is not None:
        v = q.strip().lower()
        if v in TRUTHY:
            return True
        if v in FALSY:
            return False
    return default


def _walk_strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_walk_strings(v))
        return out
    if isinstance(obj, (list, tuple)):
        out = []
        for v in obj:
            out.extend(_walk_strings(v))
        return out
    return []


def extract_body_strings(body: bytes) -> tuple[list[str], str]:
    if not body:
        return [], ""
    text = body.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
        return _walk_strings(data), text
    except json.JSONDecodeError:
        return [text], text


def summarize_raw(query_string: str, body_text: str, max_len: int) -> str:
    parts = []
    if query_string:
        parts.append(f"query: {query_string}")
    if body_text:
        parts.append(f"body: {body_text}")
    summary = " | ".join(parts) if parts else "(без параметров)"
    return summary[:max_len]


def _find_full_value(values: list[str], rule_id: str) -> str:
    """Полное значение ввода, на котором сработало правило (для инцидента)."""
    for value in values:
        for m in waf.inspect_value(value):
            if m.rule.rule_id == rule_id:
                return value
    return ""


class WafAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path

        if request.method == "OPTIONS" or not path.startswith("/api"):
            return await call_next(request)
        if any(path.startswith(p) for p in DOCS_PREFIXES):
            return await call_next(request)

        waf_enabled = resolve_waf_enabled(request, settings.waf_default_enabled)
        request.state.waf_enabled = waf_enabled
        mode = derive_mode(path)
        ip = client_ip(request)

        body_strings, body_text = extract_body_strings(await request.body())
        query_pairs = request.query_params.multi_items()
        raw_input = summarize_raw(request.url.query, body_text, settings.raw_input_max_len)

        checked_values: list[str] = [v for _, v in query_pairs] + body_strings
        # Заголовки проверяются только по правилам >= medium: легитимные User-Agent
        # содержат "; " и кавычки (низкорисковые правила дают 100% FP на браузеры).
        header_values = [h for h in (request.headers.get(k) for k in CHECKED_HEADERS) if h]
        header_values.extend(
            v for k, v in request.headers.items()
            if k.startswith("x-") and k != "x-waf-enabled" and k not in CHECKED_HEADERS
        )

        # ---------- Фаза 1: WAF ----------
        if waf_enabled:
            matches = waf.inspect(checked_values) + waf.inspect(header_values, include_low_risk=False)
            if matches:
                top = waf.pick_top(matches)
                full_value = _find_full_value(checked_values, top.rule.rule_id)[:2000]

                incident_id = None
                incident_risk = top.rule.risk
                try:
                    async with logger_session() as session:
                        res = await session.execute(
                            insert(AuditLog)
                            .values(
                                source_ip=ip,
                                endpoint=path,
                                mode=mode,
                                waf_enabled=True,
                                raw_input=raw_input,
                                generated_sql="",
                                result_status="blocked",
                                status_code=403,
                                response_time_ms=0,
                                error_detail=f"{top.rule.rule_id}: {top.rule.description}",
                            )
                            .returning(AuditLog.id)
                        )
                        audit_id = res.scalar_one()
                        incident = await register_incident(
                            session,
                            source_ip=ip,
                            attack_type=top.rule.attack_type,
                            payload=full_value,
                            matched_rule=top.rule.rule_id,
                            base_risk=top.rule.risk,
                            audit_log_id=audit_id,
                        )
                        await session.commit()
                        incident_id = incident.id
                        incident_risk = incident.risk_level
                except Exception:  # аудит не должен ломать ответ
                    audit_logger.exception("audit write failed (blocked request)",
                                           extra={"event": "audit_write_failed", "ip": ip, "path": path})

                logger.warning(
                    "WAF blocked request",
                    extra={"event": "waf_blocked", "ip": ip, "path": path, "method": request.method,
                           "rule": top.rule.rule_id, "attack_type": top.rule.attack_type,
                           "risk": incident_risk, "incident_id": incident_id},
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "blocked": True,
                        "matched_rule": top.rule.rule_id,
                        "attack_type": top.rule.attack_type,
                        "risk_level": incident_risk,
                        "incident_id": incident_id,
                        "matched_value": full_value[:200],
                        "detail": f"WAF: запрос заблокирован. Правило {top.rule.rule_id} — {top.rule.description}",
                    },
                )

        # ---------- Фаза 2: пропуск запроса + аудит ----------
        request.state.generated_sql = ""
        request.state.result_status = ""
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            await self._write_audit(ip, path, mode, waf_enabled, raw_input, "", "error", 500,
                                    elapsed_ms, f"unhandled: {type(exc).__name__}: {exc}"[:300])
            raise

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        status = get_result_status(request) or ("error" if response.status_code >= 400 else "ok")
        await self._write_audit(
            ip, path, mode, waf_enabled, raw_input,
            get_generated_sql(request)[:2000], status, response.status_code, elapsed_ms,
            f"HTTP {response.status_code}" if status == "error" else "",
        )
        return response

    @staticmethod
    async def _write_audit(ip: str, path: str, mode: str, waf_enabled: bool, raw_input: str,
                           generated_sql: str, status: str, status_code: int,
                           elapsed_ms: int, error_detail: str) -> None:
        try:
            async with logger_session() as session:
                await session.execute(
                    insert(AuditLog).values(
                        source_ip=ip,
                        endpoint=path,
                        mode=mode,
                        waf_enabled=waf_enabled,
                        raw_input=raw_input,
                        generated_sql=generated_sql,
                        result_status=status,
                        status_code=status_code,
                        response_time_ms=elapsed_ms,
                        error_detail=error_detail,
                    )
                )
                await session.commit()
        except Exception:
            audit_logger.exception("audit write failed", extra={"event": "audit_write_failed", "ip": ip, "path": path})
