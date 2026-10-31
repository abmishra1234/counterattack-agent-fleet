FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && groupadd --system counterstrike \
    && useradd --system --gid counterstrike --home-dir /app counterstrike \
    && mkdir -p /app/out \
    && chown -R counterstrike:counterstrike /app

COPY --chown=counterstrike:counterstrike frontend ./frontend
COPY --chown=counterstrike:counterstrike data ./data
COPY --chown=counterstrike:counterstrike migrations ./migrations
COPY --chown=counterstrike:counterstrike alembic.ini ./alembic.ini

USER counterstrike
EXPOSE 8000
CMD ["counterstrike-api"]
