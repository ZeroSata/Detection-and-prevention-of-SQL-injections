"""DB Security Lab — конфигурация приложения (pydantic-settings).

Все секреты приходят из окружения (.env / docker compose). Значения по
умолчанию — только для локального учебного стенда.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "DB Security Lab API"

    # --- Подключения к PostgreSQL (три роли наименьших привилегий) ---
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "securedemo"
    db_admin_user: str = "app_admin"          # миграции/инициализация схемы
    db_admin_password: str = "admin_change_me"
    db_readonly_user: str = "app_readonly"    # демо-запросы (в т.ч. уязвимые эндпоинты)
    db_readonly_password: str = "readonly_change_me"
    db_logger_user: str = "app_logger"        # аудит, инциденты, дашборд
    db_logger_password: str = "logger_change_me"

    # --- WAF ---
    waf_default_enabled: bool = True

    # --- Прочее ---
    cors_origins: str = "http://localhost:8080,http://localhost:5173"
    log_level: str = "INFO"
    raw_input_max_len: int = 500

    # --- Пороги корреляции инцидентов ---
    corr_window_minutes: int = 5      # окно скользящей статистики по IP
    corr_high_threshold: int = 3      # >=3 блокировок от IP за окно -> риск минимум high
    corr_critical_threshold: int = 10 # >=10 блокировок от IP за окно -> риск critical
    incident_group_minutes: int = 10  # группировка повторов (ip+тип+payload)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
