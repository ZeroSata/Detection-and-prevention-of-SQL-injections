"""DB Security Lab — мелкие вспомогательные функции."""
from decimal import Decimal
from datetime import datetime


def jsonable(obj) -> dict:
    """dict из SQLAlchemy Row.mapping() с приведением типов к JSON-сериализуемым."""
    out = {}
    for key, value in dict(obj).items():
        if isinstance(value, Decimal):
            out[key] = float(value)
        elif isinstance(value, datetime):
            out[key] = value.isoformat()
        elif isinstance(value, bytes):
            out[key] = value.decode("utf-8", errors="replace")
        else:
            out[key] = value
    return out
