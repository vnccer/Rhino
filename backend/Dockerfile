FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/pyproject.toml ./
COPY backend/app ./app
COPY rules ./rules
COPY assets.yaml ./assets.yaml
RUN pip install --no-cache-dir .

COPY backend/alembic.ini ./
COPY backend/migrations ./migrations

EXPOSE 8000

FROM base AS test
RUN pip install --no-cache-dir ".[dev]"
COPY backend/tests ./tests
COPY demo ./demo
CMD ["pytest"]

FROM base AS runtime
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
