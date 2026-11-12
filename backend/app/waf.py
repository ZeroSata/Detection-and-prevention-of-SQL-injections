"""DB Security Lab — WAF: сигнатуры SQL-инъекций и нормализация ввода.

Проверяются значения query-параметров, строковые значения тела (JSON) и
избранные заголовки. Каждое значение проверяется ДВАЖДЫ: в исходном виде и
после нормализации (URL-decode x2, нижний регистр, удаление блочных
комментариев, схлопывание пробелов) — это ловит базовую обфускацию
(регистр, %27, двойное кодирование, UN/**/ION).

ВНИМАНИЕ: демонстрационный WAF. Подход "всё, что похоже на SQL — блокируем"
даёт высокий detection rate ценой ложных срабатываний на апострофах
(см. отчёт, раздел 6). В продакшене так не делают: параметризация + менее
хрупкие правила + режим логирования без блокировки.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import unquote

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class WafRule:
    rule_id: str
    pattern: str
    attack_type: str
    risk: str
    description: str


RULES: tuple[WafRule, ...] = (
    WafRule(
        "SQLI-TAUTOLOGY",
        r"\b(?:or|and)\b\s*\(?\s*['\"]?[\w.]{1,32}['\"]?\s*=\s*['\"]?[\w.]{1,32}",
        "tautology", "high",
        "Логическая тавтология (OR/AND x=y)",
    ),
    WafRule(
        "SQLI-UNION-SELECT",
        r"union\s+(?:all\s+)?select",
        "union", "high",
        "UNION-based инъекция (объединение запросов)",
    ),
    WafRule(
        "SQLI-COMMENT-LINE",
        r"(?:--|#)",
        "comment", "medium",
        "Комментарий SQL (-- или #) — усечение хвоста запроса",
    ),
    WafRule(
        "SQLI-COMMENT-BLOCK",
        r"/\*|\*/",
        "comment", "medium",
        "Блочный комментарий SQL (/* */) — обфускация",
    ),
    WafRule(
        "SQLI-STACKED",
        r";\s*(?:select|insert|update|delete|drop|truncate|alter|create|grant|revoke|copy)\b",
        "stacked", "critical",
        "Stacked queries — второй оператор после ;",
    ),
    WafRule(
        "SQLI-TIME-BASED",
        r"(?:pg_sleep|sleep)\s*\(|waitfor\s+delay|benchmark\s*\(|dbms_pipe\.receive_message",
        "time_based", "critical",
        "Time-based инъекция (задержка выполнения)",
    ),
    WafRule(
        "SQLI-ERROR-BASED",
        r"(?:extractvalue|updatexml)\s*\(|::\s*(?:int|integer|numeric|money)|cast\s*\(|\b1\s*/\s*0\b",
        "error_based", "high",
        "Error-based инъекция (ошибки приведения типов)",
    ),
    WafRule(
        "SQLI-RECON",
        r"information_schema|pg_catalog|pg_tables|pg_user|pg_shadow|pg_read_file|dblink|"
        r"current_database\s*\(|current_user|version\s*\(\s*\)|substring\s*\(|substr\s*\(|"
        r"ascii\s*\(|chr\s*\(",
        "recon", "high",
        "Разведка структуры/версии БД (системные объекты и функции)",
    ),
    WafRule(
        "SQLI-DDL",
        r"\b(?:drop|truncate|alter|create)\b",
        "keyword", "critical",
        "Деструктивные DDL-операторы во вводе",
    ),
    WafRule(
        "SQLI-SELECT-KEYWORD",
        r"\bselect\b",
        "keyword", "medium",
        "Ключевое слово SELECT во вводе",
    ),
    WafRule(
        "SQLI-QUOTE",
        r"['\"`]",
        "quote", "low",
        "Кавычка во вводе (проба инъекции)",
    ),
    WafRule(
        "SQLI-SEMICOLON",
        r";",
        "semicolon", "low",
        "Точка с запятой во вводе (разделитель операторов)",
    ),
)

_COMPILED = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in RULES]

_INLINE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS = re.compile(r"\s+")
_NULL_BYTES = re.compile(r"%00|\x00", re.IGNORECASE)


@dataclass(frozen=True)
class WafMatch:
    rule: WafRule
    snippet: str          # фрагмент ввода, на котором сработало правило
    source: str           # "raw" | "normalized"


def normalize(value: str) -> str:
    """Нормализация для выявления обфускации:
    1) URL-decode (дважды — ловит двойное кодирование %2527);
    2) удаление нулевых байтов;
    3) нижний регистр;
    4) блочные комментарии -> пробел (UN/**/ION -> un ion);
    5) схлопывание пробелов.
    """
    s = unquote(value)
    s = unquote(s)
    s = _NULL_BYTES.sub("", s)
    s = s.lower()
    s = _INLINE_BLOCK_COMMENT.sub(" ", s)
    s = _WS.sub(" ", s)
    return s.strip()


def inspect_value(value: str, include_low_risk: bool = True) -> list[WafMatch]:
    """Проверка одного значения по сигнатурам (raw + normalized).

    include_low_risk=False — пропустить low-рисковые правила (кавычка, точка
    с запятой). Используется для ЗАГОЛОВКОВ: в легитимных User-Agent всегда
    есть "; " (пример: "X11; Linux x86_64") и кавычки — проверка заголовков
    по low-правилам даёт 100% ложных срабатываний (найдено при тестировании).
    """
    matches: list[WafMatch] = []
    seen: set[str] = set()
    for variant, source in ((value, "raw"), (normalize(value), "normalized")):
        if not variant:
            continue
        for rule, rx in _COMPILED:
            if not include_low_risk and RISK_ORDER[rule.risk] < RISK_ORDER["medium"]:
                continue
            m = rx.search(variant)
            if m and rule.rule_id not in seen:
                start = max(0, m.start() - 10)
                snippet = variant[start:m.end() + 10].strip()
                matches.append(WafMatch(rule=rule, snippet=snippet[:120], source=source))
                seen.add(rule.rule_id)
    return matches


def inspect(values: Iterable[str], include_low_risk: bool = True) -> list[WafMatch]:
    """Проверка набора значений; уникальные совпадения по rule_id."""
    all_matches: dict[str, WafMatch] = {}
    for value in values:
        if not value:
            continue
        for m in inspect_value(value, include_low_risk=include_low_risk):
            current = all_matches.get(m.rule.rule_id)
            if current is None or RISK_ORDER[m.rule.risk] > RISK_ORDER[current.rule.risk]:
                all_matches[m.rule.rule_id] = m
    return list(all_matches.values())


def pick_top(matches: list[WafMatch]) -> WafMatch:
    """Самое рискованное совпадение (порядок правил — приоритет при равном риске)."""
    return max(matches, key=lambda m: (RISK_ORDER[m.rule.risk], -RULES.index(m.rule)))


def rules_report() -> list[dict]:
    """Список правил для /api/meta/waf-rules и отчёта."""
    return [
        {"rule_id": r.rule_id, "attack_type": r.attack_type, "risk": r.risk,
         "pattern": r.pattern, "description": r.description}
        for r, _ in _COMPILED
    ]
