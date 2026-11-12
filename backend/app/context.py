"""DB Security Lab — передача данных из эндпоинтов в audit-слой.

ВАЖНО: используем request.state (общий scope-словарь), а не contextvars.
BaseHTTPMiddleware.call_next выполняет эндпоинт в отдельной asyncio-задаче:
копия contextvars создаётся при старте задачи, и изменения ВНУТРИ эндпоинта
не возвращаются в middleware. request.state хранится в scope-словаре, который
у middleware и эндпоинта один и тот же — значения проходят (найдено
тестами: с contextvars generated_sql в audit_logs всегда пустой).
"""
from starlette.requests import Request


def set_generated_sql(request: Request, sql: str) -> None:
    request.state.generated_sql = sql[:2000]


def set_result_status(request: Request, status: str) -> None:
    request.state.result_status = status


def get_generated_sql(request: Request) -> str:
    return getattr(request.state, "generated_sql", "")


def get_result_status(request: Request) -> str:
    return getattr(request.state, "result_status", "")
