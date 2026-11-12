#!/usr/bin/env python3
"""Keeper: держит встроенный PostgreSQL (pgserver) запущенным в песочнице.
Пишет актуальный DSN в /home/z/my-project/.runtime/pg_dsn.txt."""
import pathlib
import time

import pgserver

RT = pathlib.Path("/home/z/my-project/.runtime")
RT.mkdir(parents=True, exist_ok=True)

srv = pgserver.get_server(str(RT / "pgdata"))
uri = srv.get_uri()
(RT / "pg_dsn.txt").write_text(uri, encoding="utf-8")
print("PG READY:", uri, flush=True)

while True:
    time.sleep(3600)
