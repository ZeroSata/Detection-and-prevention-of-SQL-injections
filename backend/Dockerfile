# DB Security Lab — backend (FastAPI + asyncpg)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# Учебный стенд: без авторизации на уровне приложения, под ролями
# наименьших привилегий БД. Не выставлять в публичную сеть.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
