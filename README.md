# DB Security Lab

**Учебный стенд**: подсистема аудита, мониторинга и защиты базы данных (PostgreSQL) с веб-интерфейсом
для демонстрации обнаружения и предотвращения SQL-инъекций и анализа инцидентов ИБ.

> ## ⚠️ ВНИМАНИЕ
> Стенд содержит **намеренно уязвимый код** (`backend/app/routers/insecure.py`) и предназначен
> **исключительно для обучения** на изолированной тестовой среде.
> **НЕ выставляйте его в публичную сеть.** Все данные — демонстрационные, пароли — демо.

## Что демонстрирует стенд

1. **Разница между уязвимым и защищённым кодом**: эндпоинты `/api/insecure/*` собирают SQL
   конкатенацией строк (уязвимы к SQLi), `/api/secure/*` используют параметризованные запросы
   SQLAlchemy — один и тот же ввод даёт разные результаты.
2. **WAF-middleware**: 12 сигнатур (UNION, тавтологии, комментарии, stacked queries, pg_sleep,
   error-based, разведка и т.д.) + нормализация ввода (URL-decode ×2, регистр, inline-комментарии).
   Включается/выключается на лету (заголовок `X-WAF-Enabled` или `?waf=`). Блокировка → `403`,
   запись в журнал аудита и создание инцидента.
3. **Аудит и корреляция**: каждый API-запрос логируется в `audit_logs` (ввод, сгенерированный SQL,
   статус, время); движок корреляции группирует повторы и повышает уровень риска инцидентов;
   дашборд ИБ-аналитика с графиками обновляется в реальном времени (polling 4 с).

## Стек

| Слой | Технологии |
|---|---|
| БД | PostgreSQL 15+ (проверено на 16), расширенное журналирование, роли наименьших привилегий |
| Бэкенд | Python 3.11+, FastAPI, SQLAlchemy 2.x (async, asyncpg), Pydantic v2 |
| Фронтенд | React 18 + Vite 5, Axios, Recharts |
| Инфраструктура | Docker Compose (postgres + backend + frontend/nginx), `.env` |
| Тесты | pytest + httpx (77 тестов, матрица пейлоадов) |

## Быстрый запуск (Docker)

```bash
cp .env.example .env   # необязательно: compose содержит дефолты для стенда
docker compose up --build
```

| Сервис | URL |
|---|---|
| Фронтенд (SQLi Playground / Dashboard / Журнал) | http://localhost:8080 |
| API + Swagger | http://localhost:8000/api/docs |
| PostgreSQL | localhost:5432 (db `securedemo`) |

Инициализация БД (схема, роли, seed) выполняется автоматически при первом старте контейнера
postgres (`db/init/`). Журнал СУБД: `docker compose logs postgres` (там видны в т.ч.
инъецированные запросы и ошибки).

### Демо-учётные данные (только для стенда)

| Что | Значение |
|---|---|
| Вход (secure login) | `admin / admin123`, `jdoe / jdoe123`, `analyst / analyst123`, `o_brien / obrien123` |
| PostgreSQL `app_admin` | `app_admin / admin_change_me` |
| PostgreSQL `app_readonly` | `app_readonly / readonly_change_me` (только SELECT) |
| PostgreSQL `app_logger` | `app_logger / logger_change_me` (аудит/инциденты) |

Все значения переопределяются в `.env`.

## Запуск без Docker

```bash
# 1) PostgreSQL 15+ (свой локальный)
python scripts/local_init.py --dsn postgresql://postgres:postgres@127.0.0.1:5432/postgres

# 2) Бэкенд
cd backend && pip install -r requirements.txt
DB_HOST=127.0.0.1 DB_PORT=5432 python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3) Фронтенд
cd frontend && npm install && npm run dev     # http://localhost:5173 (прокси /api -> :8000)
```

## Тесты

```bash
cd backend
pip install -r requirements.txt pytest pytest-asyncio httpx
DB_PORT=5432 python -m pytest tests/ -q          # 77 тестов
```

Результаты матрицы «пейлоад × режим» пишутся в `backend/test_results/matrix.md` и `matrix.json`
(detection rate, false positive rate, полный список 30 пейлоадов × 4 комбинации).

Наполнить дашборд демо-атаками:

```bash
python scripts/fill_demo_attacks.py --base-url http://127.0.0.1:8000 --rounds 3 --spread
```

## Структура

```
db-security-lab/
├── docker-compose.yml          # postgres (+логирование) / backend / frontend(nginx)
├── .env.example                # все переменные окружения
├── db/
│   ├── init/                   # авто-инициализация контейнера postgres
│   │   ├── 01_schema.sql       # users, products, audit_logs, incidents
│   │   ├── roles.sql.tpl       # роли app_readonly/app_logger (пароли из окружения)
│   │   ├── 02_roles.sh         # подстановка паролей + psql
│   │   └── 03_seed.sql         # демо-данные (bcrypt-хэши)
│   └── postgresql.conf.example # расширенное журналирование СУБД
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI, CORS, порядок middleware
│   │   ├── middleware.py       # WAF + аудит (единый конвейер)
│   │   ├── waf.py              # 12 сигнатур + нормализация
│   │   ├── correlation.py      # группировка повторов, эскалация риска
│   │   ├── db.py               # 3 async-движка под роли БД
│   │   └── routers/            # insecure (УЯЗВИМЫЙ), secure, dashboard
│   ├── tests/                  # pytest: 77 тестов, матрица пейлоадов
│   └── test_results/           # matrix.md / matrix.json (генерируются тестами)
├── frontend/                   # React+Vite: Playground, Dashboard, Журнал аудита
├── scripts/                    # локальная инициализация, генерация демо-атак
├── docs/screenshots/           # скриншоты стенда
└── REPORT.md                   # подробный отчёт о реализации и тестировании
```

## Переменные окружения

См. `.env.example`: `POSTGRES_DB`, `POSTGRES_ADMIN_USER/PASSWORD`, `APP_READONLY_PASSWORD`,
`APP_LOGGER_PASSWORD`, `BACKEND_PORT`, `FRONTEND_PORT`, `WAF_DEFAULT_ENABLED`, `LOG_LEVEL`,
`CORS_ORIGINS`, `CORR_*` (пороги корреляции). Секреты не хранятся в коде.

## Известные компромиссы стенда (честно)

- Low-рисковые правила (кавычка, `;`) дают ложное срабатывание на легитимных данных с апострофом
  (`O'Brien`) — зафиксировано в тестах как ожидаемый FP; в продакшене такие правила переводят
  в режим логирования.
- Stacked queries (`; DROP ...`) не выполняются по двум независимым причинам: asyncpg запрещает
  несколько операторов в одном запросе, а роль `app_readonly` не имеет прав на DDL/DML.
  Обе защиты демонстрируются, ошибка СУБД видна в ответе уязвимого эндпоинта.
- Переключатель WAF (`X-WAF-Enabled`) — демонстрационная функция; в реальной системе управление
  WAF выносится на защищённый контур.

Подробности: **REPORT.md** (реализация, архитектура, результаты 77 тестов, приложения с кодом).
