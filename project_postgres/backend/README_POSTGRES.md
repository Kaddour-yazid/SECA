# Backend PostgreSQL Setup

This backend copy is configured for PostgreSQL by default.

## 1) Configure environment

Create `.env` in `project_postgres/backend` and set:

```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/sonprj
SECA_DB_SSLMODE=prefer
SECA_PBKDF2_ITERATIONS=600000
SECA_URL_ENCRYPTION_KEY=<FERNET_KEY>
```

You can copy from `.env.example`.

Generate an encryption key:

```powershell
cd db
python generate_url_key.py
```

## 2) Install dependencies

From `project_postgres/backend`:

```powershell
pip install -r requirements.txt
```

## 3) Ensure database exists

Example in `psql`:

```sql
CREATE DATABASE sonprj;
```

## 4) Start API

From `project_postgres/backend/db`:

```powershell
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Tables are created automatically at startup (`Base.metadata.create_all(bind=engine)`).

## 5) Optional admin seed

```powershell
python admingen.py
```
