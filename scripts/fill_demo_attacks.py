#!/usr/bin/env python3
"""DB Security Lab — генерация демо-атак для наполнения дашборда.

Шлёт через работающий API смесь атак (WAF блокирует -> инциденты) и легитимных
запросов с разных фейковых IP. Использовать ТОЛЬКО на локальном стенде.

  python scripts/fill_demo_attacks.py --base-url http://127.0.0.1:8000 --rounds 3

Опция --spread размазывает время записей аудита/инцидентов назад до 50 минут
(требует прав администратора БД; только для демонстрации графиков).
"""
import argparse
import asyncio
import os
import random

import httpx

ATTACKS = [
    ("search", "zz%' OR '1'='1"),
    ("search", "zz%' OR 1=1--"),
    ("login", "' OR '1'='1' --"),
    ("login", "admin'--"),
    ("search", "zz%' UNION SELECT 1,2,3,4--"),
    ("search", "zz%' UNION ALL SELECT id, username, password_hash, 1 FROM users--"),
    ("search", "zz' UNION SELECT NULL, version(), current_database(), NULL--"),
    ("search", "zz'--"),
    ("search", "zz' #"),
    ("search", "zz'; DROP TABLE products--"),
    ("search", "zz'; DELETE FROM users--"),
    ("search", "zz%' AND (SELECT pg_sleep(2) IS NOT NULL) AND '1'='1"),
    ("search", "zz' AND (SELECT current_database())::int = 1--"),
    ("search", "zz' AND 1=(SELECT 1/0)--"),
    ("search", "zz%' UNION SELECT table_name, column_name, NULL, NULL FROM information_schema.columns--"),
    ("search", "zz%' uNiOn SeLeCt 1,2,3,4--"),
    ("search", "zz%' UN/**/ION SE/**/LECT 1,2,3,4--"),
    ("search", "%27%20OR%20%271%27%3D%271"),
    ("search", "zz\""),
    ("search", "zz';"),
]

LEGIT = [
    ("search", "ноутбук"),
    ("search", "Logitech"),
    ("search", "мышь"),
    ("search", "SSD 1TB"),
    ("search", "роутер"),
]

IPS = [
    "203.0.113.7", "203.0.113.66", "198.51.100.23", "198.51.100.140",
    "192.0.2.44", "192.0.2.190", "203.0.113.99",
]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--spread", action="store_true", help="размазать ts записей назад (до 50 мин)")
    args = ap.parse_args()

    sent = blocked = 0
    async with httpx.AsyncClient(base_url=args.base_url, timeout=30,
                                 headers={"User-Agent": "db-security-lab-demo/1.0"}) as client:
        for _ in range(args.rounds):
            for kind, payload in random.sample(ATTACKS, len(ATTACKS)):
                ip = random.choice(IPS)
                headers = {"X-Forwarded-For": ip, "X-WAF-Enabled": "true"}
                if kind == "search":
                    r = await client.get(f"/api/insecure/search", params={"q": payload}, headers=headers)
                else:
                    r = await client.post("/api/insecure/login",
                                          json={"username": payload, "password": "guess"},
                                          headers=headers)
                sent += 1
                blocked += r.status_code == 403
            for kind, payload in random.sample(LEGIT, len(LEGIT)):
                headers = {"X-Forwarded-For": random.choice(IPS), "X-WAF-Enabled": "true"}
                await client.get("/api/secure/search", params={"q": payload}, headers=headers)
                sent += 1

    print(f"[demo] отправлено {sent} запросов, заблокировано WAF: {blocked}")

    if args.spread:
        dsn = os.environ.get("SPREAD_DSN", "postgresql://postgres@127.0.0.1:55432/securedemo")
        import asyncpg

        conn = await asyncpg.connect(dsn)
        await conn.execute("""
            UPDATE audit_logs
            SET ts = now() - (random() * interval '50 minutes')
            WHERE mode IN ('insecure', 'secure') AND ts > now() - interval '5 minutes'
        """)
        await conn.execute("""
            UPDATE incidents
            SET ts = ts - (random() * interval '50 minutes'),
                last_seen_at = last_seen_at - (random() * interval '50 minutes')
            WHERE ts > now() - interval '5 minutes'
        """)
        await conn.close()
        print("[demo] времена записей размазаны назад для наглядности графика")


if __name__ == "__main__":
    asyncio.run(main())
