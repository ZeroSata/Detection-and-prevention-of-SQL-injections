"""DB Security Lab — Pydantic-схемы (валидация входных данных API)."""
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128, examples=["admin"])
    password: str = Field(min_length=1, max_length=128, examples=["admin123"])


class SearchRequest(BaseModel):
    q: str = Field(min_length=1, max_length=256, examples=["ноутбук"])


class IncidentStatusUpdate(BaseModel):
    status: Literal["new", "investigating", "closed"]


RiskLevel = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["new", "investigating", "closed"]
AuditMode = Literal["insecure", "secure", "dashboard", "other"]
AuditStatus = Literal["ok", "error", "blocked"]
