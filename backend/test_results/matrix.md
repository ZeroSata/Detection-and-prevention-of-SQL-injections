# DB Security Lab — матрица «пейлоад × режим → результат»

Дата: 2026-11-03 16:29:48 · генерируется автоматически (tests/conftest.py)

Обозначения: BLOCKED — 403 от WAF; EXPLOIT — видимый эффект инъекции (данные/вход/задержка);
ERROR — ошибка СУБД всплыла наружу; EMPTY/AUTH_FAIL — штатная безопасная обработка.

## Вредоносные пейлоады

| id | категория | цель | пейлоад | Insecure+WAF OFF | Insecure+WAF ON | Secure+WAF OFF | Secure+WAF ON |
|---|---|---|---|---|---|---|---|
| T01 | tautology | search | `' OR '1'='1` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| T02 | tautology | search | `zz%' OR '1'='1` | EMPTY | BLOCKED | EMPTY | BLOCKED |
| T03 | tautology | search | `zz%' OR 1=1--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| T04 | tautology | login | `' OR '1'='1' --` | EXPLOIT | BLOCKED | AUTH_FAIL | BLOCKED |
| T05 | tautology | login | `admin'--` | EXPLOIT | BLOCKED | AUTH_FAIL | BLOCKED |
| U01 | union | search | `zz%' UNION SELECT 1,'2','3',4--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| U02 | union | search | `zz%' UNION ALL SELECT id, username, password_hash, 1 FROM users--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| U03 | union | search | `zz' UNION SELECT NULL, version(), current_database(), NULL--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| C01 | comment | search | `zz'--` | EMPTY | BLOCKED | EMPTY | BLOCKED |
| C02 | comment | search | `zz' OR '1'='1' --` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| C03 | comment | search | `zz' #` | ERROR | BLOCKED | EMPTY | BLOCKED |
| C04 | comment | search | `zz' /*tail` | ERROR | BLOCKED | EMPTY | BLOCKED |
| S01 | stacked | search | `zz'; DROP TABLE products--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| S02 | stacked | search | `zz'; DELETE FROM users--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| S03 | stacked | search | `zz'; SELECT 1--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| B01 | time_based | search | `zz%' OR (SELECT count(*) FROM pg_sleep(2))>0--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| B02 | time_based | search | `zz' AND 1=(SELECT 1 FROM pg_sleep(2))--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| E01 | error_based | search | `zz' AND (SELECT current_database())::int = 1--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| E02 | error_based | search | `zz%' AND 1=CAST((SELECT current_database()) AS int)--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| E03 | error_based | search | `zz' AND 1=(SELECT 1/0)--` | ERROR | BLOCKED | EMPTY | BLOCKED |
| R01 | recon | search | `zz%' UNION SELECT 1, table_name::text, column_name::text, 1 FROM information_schema.columns--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| R02 | recon | search | `zz%' OR SUBSTRING(version(),1,1)='P'--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| R03 | recon | search | `zz%' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| O01 | obfuscation | search | `zz%' uNiOn SeLeCt 1,'2','3',4--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| O02 | obfuscation | search | `zz%' UNION/**/ALL/**/SELECT 1,'2','3',4--` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| O03 | obfuscation | search | `%27%20OR%20%271%27%3D%271` | EXPLOIT | BLOCKED | EMPTY | BLOCKED |
| O04 | obfuscation | search | `%2527%2520OR%2520%271%27%3D%271` | ERROR | BLOCKED | EMPTY | BLOCKED |
| M01 | semicolon | search | `zz';` | ERROR | BLOCKED | EMPTY | BLOCKED |
| M02 | quote | search | `zz"` | EMPTY | BLOCKED | EMPTY | BLOCKED |
| M03 | union | login | `zzz' UNION SELECT 7,'fake','Fake User','admin','notahash'--` | EXPLOIT | BLOCKED | AUTH_FAIL | BLOCKED |

## Легитимные запросы (проверка ложных срабатываний)

| id | цель | ввод | WAF ON | WAF OFF | ложное срабатывание |
|---|---|---|---|---|---|
| L01 | search | `ноутбук` | PASS | PASS | нет |
| L02 | search | `Logitech` | PASS | PASS | нет |
| L03 | search | `980 Pro` | PASS | PASS | нет |
| L04 | search | `мышь` | PASS | PASS | нет |
| L05 | search | `роутер` | PASS | PASS | нет |
| L06 | search | `O'Brien` | BLOCKED | PASS | ДА |
| L09 | search | `монитор 27` | PASS | PASS | нет |
| L07 | login | `admin` | PASS | PASS | нет |
| L08 | login | `jdoe` | PASS | PASS | нет |

## Метрики

- Malicious пейлоадов: **30**
- WAF detection rate (Insecure+WAF ON, доля заблокированных): **1.0**
- Легитимных запросов: **9**, ложных срабатываний: **1** (['L06'])
- False positive rate: **0.1111**
- Эксплуатаций/ошибок в Secure-режиме (WAF OFF): **0** (параметризация безопасна: True)
