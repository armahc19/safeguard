# Fraud DB: setup

```bash
pip install -r requirements.txt
export DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/fraud
mkdir -p migrations/versions
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

Review the generated migration before applying it. Note: `UniqueConstraint(..., postgresql_nulls_not_distinct=True)`
on `threat_indicators` needs PostgreSQL 15+ and SQLAlchemy 2.0.20+.

`gen_random_uuid()` is built in from PostgreSQL 13; on older versions add `CREATE EXTENSION pgcrypto`.
