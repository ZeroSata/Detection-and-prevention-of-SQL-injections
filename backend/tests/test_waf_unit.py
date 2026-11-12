"""DB Security Lab — модульные тесты WAF: нормализация и каждая сигнатура."""
import pytest

from app.waf import normalize, inspect, inspect_value, pick_top, RISK_ORDER


def matched_ids(values, **kw):
    return {m.rule.rule_id for m in inspect(values, **kw)}


class TestNormalize:
    def test_lowercase(self):
        assert normalize("uNiOn SeLeCt") == "union select"

    def test_url_decode(self):
        assert normalize("%27 OR %271%27=%271") == "' or '1'='1"

    def test_double_url_decode(self):
        assert normalize("%2527%2520OR%2527") == "' or'"

    def test_inline_comments_removed(self):
        # комментарии = пробелы: UNION/**/SELECT эквивалентен UNION SELECT
        assert normalize("UNION/**/SELECT") == "union select"
        # UN/**/ION -> "un ion" — это НЕ валидный SQL (комментарий рвёт токен),
        # реальный обход — пробел внутри ключевого слова не нужен, см. test_union
        assert normalize("UN/**/ION") == "un ion"

    def test_whitespace_collapsed(self):
        assert normalize("a \t\n  b") == "a b"

    def test_null_bytes(self):
        assert normalize("un%00ion") == "union"


class TestRules:
    def test_tautology(self):
        assert "SQLI-TAUTOLOGY" in matched_ids(["' OR '1'='1"])
        assert "SQLI-TAUTOLOGY" in matched_ids(["zz%' OR 1=1--"])
        assert "SQLI-TAUTOLOGY" in matched_ids(["') OR ('1'='1"])

    def test_union(self):
        assert "SQLI-UNION-SELECT" in matched_ids(["zz%' UNION SELECT 1,2,3,4--"])
        assert "SQLI-UNION-SELECT" in matched_ids(["zz%' UNION ALL SELECT x--"])
        assert "SQLI-UNION-SELECT" in matched_ids(["zz%' uNiOn SeLeCt 1--"])       # регистр
        assert "SQLI-UNION-SELECT" in matched_ids(["zz%' UNION/**/ALL/**/SELECT 1--"])  # комментарии как пробелы
        assert "SQLI-UNION-SELECT" in matched_ids(["%27%20UNION%20SELECT%201--"])   # URL-encoding

    def test_comments(self):
        assert "SQLI-COMMENT-LINE" in matched_ids(["zz'--"])
        assert "SQLI-COMMENT-LINE" in matched_ids(["zz' #"])
        assert "SQLI-COMMENT-BLOCK" in matched_ids(["zz' /*x*/"])

    def test_stacked(self):
        assert "SQLI-STACKED" in matched_ids(["zz'; DROP TABLE products--"])
        assert "SQLI-STACKED" in matched_ids(["zz'; DELETE FROM users--"])
        assert "SQLI-STACKED" in matched_ids(["zz'; COPY t TO STDOUT--"])

    def test_time_based(self):
        assert "SQLI-TIME-BASED" in matched_ids(["zz%' AND (SELECT pg_sleep(2))--"])
        assert "SQLI-TIME-BASED" in matched_ids(["'; WAITFOR DELAY '0:0:5'--"])

    def test_error_based(self):
        assert "SQLI-ERROR-BASED" in matched_ids(["zz' AND (SELECT db)::int = 1--"])
        assert "SQLI-ERROR-BASED" in matched_ids(["zz' AND 1=CAST((SELECT 1) AS int)--"])
        assert "SQLI-ERROR-BASED" in matched_ids(["zz' AND 1=(SELECT 1/0)--"])

    def test_recon(self):
        assert "SQLI-RECON" in matched_ids(["zz' FROM information_schema.tables--"])
        assert "SQLI-RECON" in matched_ids(["zz' AND SUBSTRING(version(),1,1)='P'--"])

    def test_ddl_and_select(self):
        assert "SQLI-DDL" in matched_ids(["zz' DROP TABLE x--"])
        assert "SQLI-SELECT-KEYWORD" in matched_ids(["zz' OR EXISTS(SELECT 1)--"])

    def test_double_encoding_caught_by_normalization(self):
        # сервер декодирует %2527 -> %27 (литерал), WAF декодирует повторно -> кавычка
        ids = matched_ids(["%2527%2520OR%2520%271%27%3D%271"])
        assert "SQLI-TAUTOLOGY" in ids


class TestLegitValues:
    """Легитимные поисковые строки не должны совпадать ни по одному правилу."""

    LEGIT = ["ноутбук", "Logitech", "SSD 1TB", "мышь беспроводная", "роутер Wi-Fi 6", "монитор 27 дюймов"]

    def test_no_matches(self):
        for v in self.LEGIT:
            assert inspect([v]) == [], f"ложное срабатывание на {v!r}"

    def test_obrien_quote_is_low_risk_trigger(self):
        # честный известный компромисс: апостроф в данных ловит low-правило QUOTE
        ids = matched_ids(["O'Brien"])
        assert ids == {"SQLI-QUOTE"}


class TestHeaderPolicy:
    def test_browser_user_agent_not_flagged_without_low_rules(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        # полный набор ловит ';' из UA (известный FP, найден при тестировании стенда)…
        assert "SQLI-SEMICOLON" in matched_ids([ua])
        # …поэтому для заголовков low-правила отключены
        assert matched_ids([ua], include_low_risk=False) == set()

    def test_header_strong_signature_still_blocked(self):
        ua = "sqlmap/1.8' UNION SELECT 1--"
        ids = matched_ids([ua], include_low_risk=False)
        assert "SQLI-UNION-SELECT" in ids


class TestPickTop:
    def test_highest_risk_wins(self):
        matches = inspect(["zz'; DROP TABLE products--"])
        top = pick_top(matches)
        assert top.rule.rule_id in ("SQLI-STACKED", "SQLI-DDL")
        assert RISK_ORDER[top.rule.risk] == RISK_ORDER["critical"]


@pytest.mark.parametrize("value", ["", "  "])
def test_empty_values_no_crash(value):
    assert inspect([value]) == []
    assert inspect_value(value) == []
