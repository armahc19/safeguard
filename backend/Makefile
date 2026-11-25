.PHONY: install infra-up infra-down migrate migrate-check run run-prod test lint check image-build

install:
	python -m pip install -r requirements-dev.txt

infra-up:
	docker compose up -d postgres redis

infra-down:
	docker compose down

migrate:
	alembic upgrade head

migrate-check:
	alembic check

run:
	uvicorn app.main:app --reload

run-prod:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

image-build:
	docker build -f Dockerfile -t safeguard-api:local ..

test:
	pytest -q

lint:
	ruff check app tests

check: lint test
