#!/bin/bash
# =============================================================================
# DB Security Lab — создание ролей с наименьшими привилегиями.
# Запускается официальным entrypoint образа postgres (docker-entrypoint-initdb.d)
# от имени POSTGRES_USER. Пароли берутся из окружения контейнера, в код не пишутся.
# =============================================================================
set -euo pipefail

RO_PWD="${APP_READONLY_PASSWORD:-readonly_change_me}"
LG_PWD="${APP_LOGGER_PASSWORD:-logger_change_me}"

sed -e "s|__READONLY_PWD__|${RO_PWD}|g" -e "s|__LOGGER_PWD__|${LG_PWD}|g" \
    /docker-entrypoint-initdb.d/roles.sql.tpl \
  | psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"

echo "[db-init] roles app_readonly / app_logger created, least-privilege grants applied"
