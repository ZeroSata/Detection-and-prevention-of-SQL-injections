"""DB Security Lab — простой движок корреляции событий аудита.

Правила:
  1. Группировка повторов: тот же (source_ip, attack_type, payload) в пределах
     incident_group_minutes -> инцидент НЕ создаётся заново, увеличивается
     repeat_count и обновляется last_seen_at.
  2. Эскалация риска: число блокировок WAF от source_ip за последние
     corr_window_minutes:
        >= corr_critical_threshold -> risk = critical
        >= corr_high_threshold     -> risk = max(base_risk, high)
Пороги настраиваются через переменные окружения (CORR_*).
"""
from __future__ import annotations

import logging

from sqlalchemy import func, select, update

from .config import get_settings
from .models import AuditLog, Incident
from .waf import RISK_ORDER

logger = logging.getLogger("lab.correlation")

VALID_RISKS = ("low", "medium", "high", "critical")


async def register_incident(
    session,
    *,
    source_ip: str,
    attack_type: str,
    payload: str,
    matched_rule: str,
    base_risk: str,
    audit_log_id: int | None,
) -> Incident:
    s = get_settings()

    # --- 1) Группировка повторов -------------------------------------------
    group_cutoff = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, s.incident_group_minutes * 60)
    existing = (
        await session.execute(
            select(Incident)
            .where(
                Incident.source_ip == source_ip,
                Incident.attack_type == attack_type,
                Incident.payload == payload,
                Incident.last_seen_at >= group_cutoff,
            )
            .order_by(Incident.last_seen_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # --- 2) Скользящее окно по IP (число блокировок за окно) -----------------
    window_cutoff = func.now() - func.make_interval(0, 0, 0, 0, 0, 0, s.corr_window_minutes * 60)
    recent_blocked = (
        await session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.source_ip == source_ip,
                AuditLog.result_status == "blocked",
                AuditLog.ts >= window_cutoff,
            )
        )
    ).scalar_one()

    risk = base_risk if base_risk in VALID_RISKS else "medium"
    escalated = False
    if recent_blocked >= s.corr_critical_threshold:
        risk = "critical"
        escalated = risk != base_risk
    elif recent_blocked >= s.corr_high_threshold:
        risk = "high" if RISK_ORDER["high"] > RISK_ORDER.get(risk, 0) else risk
        escalated = risk != base_risk

    if existing is not None:
        await session.execute(
            update(Incident)
            .where(Incident.id == existing.id)
            .values(
                last_seen_at=func.now(),
                repeat_count=Incident.repeat_count + 1,
                matched_rule=matched_rule,
                risk_level=risk,
                escalated=escalated,
                audit_log_id=audit_log_id,
            )
        )
        await session.flush()
        incident = await session.get(Incident, existing.id)
        logger.info(
            "incident repeated",
            extra={"event": "incident_repeated", "incident_id": incident.id, "ip": source_ip,
                   "attack_type": attack_type, "risk": risk, "detail": f"repeat_count={incident.repeat_count}"},
        )
        return incident

    incident = Incident(
        source_ip=source_ip,
        attack_type=attack_type,
        payload=payload,
        matched_rule=matched_rule,
        risk_level=risk,
        status="new",
        repeat_count=1,
        escalated=escalated,
        audit_log_id=audit_log_id,
    )
    session.add(incident)
    await session.flush()
    logger.info(
        "incident created",
        extra={"event": "incident_created", "incident_id": incident.id, "ip": source_ip,
               "attack_type": attack_type, "risk": risk, "rule": matched_rule},
    )
    return incident
