-- =============================================================================
-- DB Security Lab — роли и права по принципу наименьших привилегий.
-- Файл-ШАБЛОН: пароли подставляются из окружения (docker: 02_roles.sh,
-- локальный запуск: scripts/local_init.py). Пароли никогда не хранятся в коде.
-- =============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_readonly') THEN
    CREATE ROLE app_readonly LOGIN PASSWORD '__READONLY_PWD__';
  ELSE
    ALTER ROLE app_readonly PASSWORD '__READONLY_PWD__';
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_logger') THEN
    CREATE ROLE app_logger LOGIN PASSWORD '__LOGGER_PWD__';
  ELSE
    ALTER ROLE app_logger PASSWORD '__LOGGER_PWD__';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO app_readonly, app_logger;

-- app_readonly: ТОЛЬКО SELECT на демо-таблицы (под этой ролью работают и
-- уязвимые эндпоинты — при инъекции злоумышленник получает права только чтения)
GRANT SELECT ON users, products TO app_readonly;

-- app_logger: INSERT в журнал аудита и инциденты + SELECT для дашборда и
-- корреляции. Отдельное осознанное расширение: UPDATE incidents (смена статуса
-- аналитиком). audit_logs — append-only: UPDATE/DELETE не выданы никому.
GRANT INSERT ON audit_logs, incidents TO app_logger;
GRANT SELECT ON audit_logs, incidents TO app_logger;
GRANT UPDATE ON incidents TO app_logger;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq, incidents_id_seq TO app_logger;

COMMENT ON ROLE app_readonly IS 'Demo: SELECT only on users/products (also used by intentionally vulnerable endpoints)';
COMMENT ON ROLE app_logger  IS 'Demo: INSERT audit_logs/incidents, SELECT for dashboard/correlation, UPDATE incidents.status';
