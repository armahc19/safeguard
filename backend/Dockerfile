FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./
COPY safeguard_fraud_knowledge_base_v1.json ./safeguard_fraud_knowledge_base_v1.json
COPY models ./models

RUN useradd --create-home --uid 10001 safeguard \
    && chown -R safeguard:safeguard /app
USER safeguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
