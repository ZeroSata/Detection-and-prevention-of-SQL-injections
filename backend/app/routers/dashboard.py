"""DB Security Lab — API для дашборда ИБ-аналитика (статистика, инциденты, журнал аудита).

Все запросы выполняются под ролью app_logger (SELECT audit_logs/incidents,
UPDATE incidents.status). Смена статуса инцидента — демо-операция без
авторизации (в продакшене здесь нужна RBAC + JWT-сессия аналитика).
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import delete, func, select, text, update

from ..config import get_settings
from ..db import logger_session
from ..models import AuditLog, Incident
from ..schemas import AuditMode, AuditStatus, IncidentStatus, IncidentStatusUpdate, RiskLevel
from ..utils import jsonable
from ..waf import RISK_ORDER, rules_report

router = APIRouter(prefix="/api/dashboard", tags=["dashboard (SOC)"])
meta = APIRouter(prefix="/api/meta", tags=["meta"])


@meta.get("/waf-rules", summary="Список сигнатур WAF")
async def get_waf_rules():
    return {"rules": rules_report()}


@meta.get("/correlation", summary="Параметры движка корреляции")
async def get_correlation_config():
    s = get_settings()
    return {
        "window_minutes": s.corr_window_minutes,
        "high_threshold": s.corr_high_threshold,
        "critical_threshold": s.corr_critical_threshold,
        "incident_group_minutes": s.incident_group_minutes,
        "rules": [
            f">= {s.corr_high_threshold} блокировок от IP за {s.corr_window_minutes} мин -> риск минимум HIGH",
            f">= {s.corr_critical_threshold} блокировок от IP за {s.corr_window_minutes} мин -> риск CRITICAL",
            f"повторы (ip + тип + payload) в пределах {s.incident_group_minutes} мин -> группируются в один инцидент (repeat_count)",
        ],
    }


@router.get("/stats", summary="Агрегированная статистика для карточек и графиков")
async def stats():
    async with logger_session() as session:
        incidents_total = (await session.execute(select(func.count()).select_from(Incident))).scalar_one()
        unique_attackers = (
            await session.execute(select(func.count(func.distinct(Incident.source_ip))))
        ).scalar_one()

        by_risk_rows = (
            await session.execute(
                select(Incident.risk_level, func.count()).group_by(Incident.risk_level)
            )
        ).all()
        by_risk = {r: 0 for r in ("low", "medium", "high", "critical")}
        for risk, cnt in by_risk_rows:
            by_risk[risk] = cnt

        by_status_rows = (
            await session.execute(select(Incident.status, func.count()).group_by(Incident.status))
        ).all()
        by_status = {r: 0 for r in ("new", "investigating", "closed")}
        for st, cnt in by_status_rows:
            by_status[st] = cnt

        by_type_rows = (
            await session.execute(
                select(Incident.attack_type, func.count().label("cnt"))
                .group_by(Incident.attack_type)
                .order_by(text("cnt DESC"))
                .limit(12)
            )
        ).all()

        timeline_rows = (
            await session.execute(text(
                """
                WITH m AS (
                  SELECT generate_series(
                    date_trunc('minute', now()) - interval '59 minutes',
                    date_trunc('minute', now()),
                    interval '1 minute'
                  ) AS minute
                ),
                a AS (
                  SELECT date_trunc('minute', ts) AS minute, count(*) AS attacks
                  FROM audit_logs
                  WHERE result_status = 'blocked' AND ts >= now() - interval '60 minutes'
                  GROUP BY 1
                ),
                i AS (
                  SELECT date_trunc('minute', ts) AS minute, count(*) AS incidents
                  FROM incidents
                  WHERE ts >= now() - interval '60 minutes'
                  GROUP BY 1
                )
                SELECT to_char(m.minute, 'HH24:MI') AS minute,
                       COALESCE(a.attacks, 0) AS attacks,
                       COALESCE(i.incidents, 0) AS incidents
                FROM m
                LEFT JOIN a ON a.minute = m.minute
                LEFT JOIN i ON i.minute = m.minute
                ORDER BY m.minute
                """
            ))
        ).mappings().all()

        top_ip_rows = (
            await session.execute(text(
                """
                SELECT source_ip, count(*) AS cnt, array_agg(DISTINCT risk_level) AS risks
                FROM incidents
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT 5
                """
            ))
        ).all()

        requests_total = (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
        blocked_total = (
            await session.execute(
                select(func.count()).select_from(AuditLog).where(AuditLog.result_status == "blocked")
            )
        ).scalar_one()
        error_total = (
            await session.execute(
                select(func.count()).select_from(AuditLog).where(AuditLog.result_status == "error")
            )
        ).scalar_one()
        avg_ms = (
            await session.execute(
                select(func.avg(AuditLog.response_time_ms)).where(AuditLog.mode.in_(("insecure", "secure")))
            )
        ).scalar_one()

    return {
        "incidents_total": incidents_total,
        "incidents_open": by_status["new"] + by_status["investigating"],
        "unique_attackers": unique_attackers,
        "by_risk": by_risk,
        "by_status": by_status,
        "by_type": [{"attack_type": t, "count": c} for t, c in by_type_rows],
        "timeline": [
            {"minute": r["minute"], "attacks": r["attacks"], "incidents": r["incidents"]}
            for r in timeline_rows
        ],
        "top_ips": [
            {
                "ip": ip,
                "count": cnt,
                "max_risk": max(risks, key=lambda x: RISK_ORDER.get(x, -1)) if risks else "low",
            }
            for ip, cnt, risks in top_ip_rows
        ],
        "requests_total": requests_total,
        "blocked_total": blocked_total,
        "error_total": error_total,
        "avg_response_ms": round(float(avg_ms), 1) if avg_ms is not None else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/incidents", summary="Список инцидентов (фильтры, пагинация)")
async def incidents(
    risk: RiskLevel | None = Query(default=None),
    status: IncidentStatus | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    ip: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    filters = []
    if risk:
        filters.append(Incident.risk_level == risk)
    if status:
        filters.append(Incident.status == status)
    if attack_type:
        filters.append(Incident.attack_type == attack_type)
    if ip:
        filters.append(Incident.source_ip.ilike(f"%{ip}%"))

    async with logger_session() as session:
        total = (
            await session.execute(select(func.count()).select_from(Incident).where(*filters))
        ).scalar_one()
        rows = (
            await session.execute(
                select(Incident)
                .where(*filters)
                .order_by(Incident.ts.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

    return {
        "items": [jsonable(i.__dict__) for i in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, math.ceil(total / page_size)),
    }


@router.get("/incidents/{incident_id}", summary="Детали инцидента + связанная запись аудита")
async def incident_detail(incident_id: int):
    async with logger_session() as session:
        incident = await session.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Инцидент не найден")
        audit = None
        if incident.audit_log_id:
            arow = await session.get(AuditLog, incident.audit_log_id)
            if arow is not None:
                audit = jsonable(arow.__dict__)
    return {"incident": jsonable(incident.__dict__), "audit_log": audit}


@router.patch("/incidents/{incident_id}/status", summary="Смена статуса инцидента")
async def change_incident_status(incident_id: int, body: IncidentStatusUpdate):
    async with logger_session() as session:
        incident = await session.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Инцидент не найден")
        incident.status = body.status
        await session.commit()
        return {"id": incident.id, "status": incident.status}


@router.get("/audit-logs", summary="Журнал аудита (фильтры, пагинация)")
async def audit_logs(
    mode: AuditMode | None = Query(default=None),
    status: AuditStatus | None = Query(default=None),
    endpoint: str | None = Query(default=None, max_length=200),
    ip: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    filters = []
    if mode:
        filters.append(AuditLog.mode == mode)
    if status:
        filters.append(AuditLog.result_status == status)
    if endpoint:
        filters.append(AuditLog.endpoint.ilike(f"%{endpoint}%"))
    if ip:
        filters.append(AuditLog.source_ip.ilike(f"%{ip}%"))

    async with logger_session() as session:
        total = (
            await session.execute(select(func.count()).select_from(AuditLog).where(*filters))
        ).scalar_one()
        rows = (
            await session.execute(
                select(AuditLog)
                .where(*filters)
                .order_by(AuditLog.ts.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

    return {
        "items": [jsonable(a.__dict__) for a in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, math.ceil(total / page_size)),
    }
