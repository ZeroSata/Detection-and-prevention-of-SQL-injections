#!/bin/bash
# Запуск встроенного PostgreSQL стенда в песочнице БЕЗ Docker (для проверки).
# Идемпотентен: если сервер уже слушает порт 55432 — ничего не делает.
set -e
PGBIN=$(python3 -c "import pgserver._commands as c; print(c.POSTGRES_BIN_PATH)")
PGDATA=/home/z/my-project/.runtime/pgdata
RT=/home/z/my-project/.runtime
LOG=$RT/pg.log

mkdir -p "$RT"

if python3 - <<'EOF'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 55432), timeout=2)
    s.close(); sys.exit(0)
except OSError:
    sys.exit(1)
EOF
then
  echo "[sandbox_pg] postgres уже запущен на 127.0.0.1:55432"
else
  # настройки журналирования из канонического примера (идемпотентно)
  if ! grep -q "db-security-lab" "$PGDATA/postgresql.conf" 2>/dev/null; then
    {
      echo ""
      echo "# --- db-security-lab: расширенное журналирование (см. db/postgresql.conf.example) ---"
      sed -e "s/^listen_addresses = .*/listen_addresses = '127.0.0.1'/" \
          -e "s/^port = .*/port = 55432/" \
          -e "s|^log_line_prefix = .*|log_line_prefix = '%m [%p] db=%d,user=%u,app=%a,client=%h '|" \
          "$HOME/my-project/db-security-lab/db/postgresql.conf.example" | grep -v '^#' | grep -v '^$'
    } >> "$PGDATA/postgresql.conf"
  fi
  "$PGBIN/pg_ctl" -D "$PGDATA" -w -l "$LOG" \
    -o "-h 127.0.0.1 -p 55432 -k $RT" start >/dev/null
  echo "[sandbox_pg] postgres запущен: 127.0.0.1:55432 (лог: $LOG)"
fi
