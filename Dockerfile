FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    APP_LOG_LEVEL=INFO \
    APP_AUTO_SEED=true \
    APP_DATA_DIR=/app/data \
    APP_DOCS_DIR=/app/data/docs \
    APP_DB_PATH=/app/data/app.db

WORKDIR /app

RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["python", "-m", "scripts.run_server"]
