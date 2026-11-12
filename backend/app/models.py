"""DB Security Lab — SQLAlchemy 2.0 модели (отображение на схему из db/init/01_schema.sql)."""
from decimal import Decimal
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, Numeric, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    username: Mapped[str] = mapped_column(String(64))
    password_hash: Mapped[str] = mapped_column(Text)
    full_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(64))
    price: Mapped[Decimal] = mapped_column(Numeric(10, 2))
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    source_ip: Mapped[str] = mapped_column(String(64))
    endpoint: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(16))
    waf_enabled: Mapped[bool] = mapped_column(Boolean)
    raw_input: Mapped[str] = mapped_column(Text)
    generated_sql: Mapped[str] = mapped_column(Text)
    result_status: Mapped[str] = mapped_column(String(16))
    status_code: Mapped[int] = mapped_column(Integer)
    response_time_ms: Mapped[int] = mapped_column(Integer)
    error_detail: Mapped[str] = mapped_column(Text)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    source_ip: Mapped[str] = mapped_column(String(64))
    attack_type: Mapped[str] = mapped_column(String(48))
    payload: Mapped[str] = mapped_column(Text)
    matched_rule: Mapped[str] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    repeat_count: Mapped[int] = mapped_column(Integer)
    escalated: Mapped[bool] = mapped_column(Boolean)
    audit_log_id: Mapped[int | None] = mapped_column(BigInteger)
