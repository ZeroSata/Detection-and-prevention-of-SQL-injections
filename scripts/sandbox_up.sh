#!/bin/bash
# Идемпотентный подъём стенда в песочнице (БЕЗ Docker): PG + backend (+ frontend опция).
# Использование: bash scripts/sandbox_up.sh [with_frontend]
set -e
ROOT=/home/z/my-project/db-security-lab
RT=/home/z/my-project/.runtime
mkdir -p "$RT"

# --- PostgreSQL ---
bash "$ROOT/scripts/sandbox_pg.sh"

pg_up() { python3 - <<'EOF'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 55432), timeout=2); s.close(); sys.exit(0)
except OSError: sys.exit(1)
EOF
}

# --- Backend ---
if curl -s -m 2 http://127.0.0.1:8000/api/health > /dev/null 2>&1; then
  echo "[up] backend уже работает"
else
  cd "$ROOT/backend"
  DB_HOST=127.0.0.1 DB_PORT=55432 DB_NAME=securedemo \
    setsid nohup python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 \
    > "$RT/backend.log" 2>&1 < /dev/null &
  for i in $(seq 1 40); do
    sleep 0.5
    curl -s -m 2 http://127.0.0.1:8000/api/health > /dev/null 2>&1 && break
  done
  echo "[up] backend запущен (лог: $RT/backend.log)"
fi

# --- Frontend (dev server Vite) ---
if [ "${1:-}" = "with_frontend" ]; then
  if curl -s -m 2 http://127.0.0.1:5173/ > /dev/null 2>&1; then
    echo "[up] frontend уже работает"
  else
    cd "$ROOT/frontend"
    [ -d node_modules ] || npm install --no-audit --no-fund --loglevel=error
    setsid nohup npm run dev -- --host 127.0.0.1 --port 5173 \
      > "$RT/frontend.log" 2>&1 < /dev/null &
    for i in $(seq 1 60); do
      sleep 0.5
      curl -s -m 2 http://127.0.0.1:5173/ > /dev/null 2>&1 && break
    done
    echo "[up] frontend запущен (лог: $RT/frontend.log)"
  fi
fi

echo "[up] готово"
