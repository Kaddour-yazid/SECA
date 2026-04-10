# Backend PostgreSQL Setup

This backend copy is configured for PostgreSQL by default.

## 1) Configure environment

Create `.env` in `project_postgres/backend` and set:

```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/sonprj
SECA_DB_SSLMODE=prefer
SECA_PBKDF2_ITERATIONS=600000
SECA_URL_ENCRYPTION_KEY=<FERNET_KEY>
SECA_PROXY_AUTOSTART=false
SECA_PROXY_LISTEN_HOST=127.0.0.1
SECA_PROXY_LISTEN_PORT=3128
SECA_OTP_EXPIRE_MINUTES=10
SECA_OTP_RESEND_COOLDOWN_SECONDS=60
SECA_OTP_MAX_REQUESTS_PER_HOUR=5
SECA_OTP_SECRET=<RANDOM_SECRET>
SECA_SMTP_HOST=smtp.example.com
SECA_SMTP_PORT=587
SECA_SMTP_USERNAME=alerts@example.com
SECA_SMTP_PASSWORD=<SMTP_PASSWORD>
SECA_SMTP_FROM_EMAIL=alerts@example.com
SECA_SMTP_FROM_NAME=SECA Security
SECA_SMTP_USE_TLS=true
SECA_SMTP_USE_SSL=false
```

You can copy from `.env.example`.

If SMTP is not configured, OTP delivery falls back to development mode and the backend logs the code. That is acceptable for local testing only. For production, configure SMTP and disable the fallback.

Example provider settings:

Gmail with App Password:

```env
SECA_SMTP_HOST=smtp.gmail.com
SECA_SMTP_PORT=587
SECA_SMTP_USERNAME=youraddress@gmail.com
SECA_SMTP_PASSWORD=<16_CHAR_APP_PASSWORD>
SECA_SMTP_FROM_EMAIL=youraddress@gmail.com
SECA_SMTP_FROM_NAME=SECA Security
SECA_SMTP_USE_TLS=true
SECA_SMTP_USE_SSL=false
```

Outlook / Microsoft 365 with SMTP AUTH enabled:

```env
SECA_SMTP_HOST=smtp.office365.com
SECA_SMTP_PORT=587
SECA_SMTP_USERNAME=youraddress@outlook.com
SECA_SMTP_PASSWORD=<ACCOUNT_PASSWORD_OR_APP_PASSWORD>
SECA_SMTP_FROM_EMAIL=youraddress@outlook.com
SECA_SMTP_FROM_NAME=SECA Security
SECA_SMTP_USE_TLS=true
SECA_SMTP_USE_SSL=false
```

Generate an encryption key:

```powershell
cd db
python generate_url_key.py
```

## 2) One-command backend start (recommended)

From `project_postgres/backend`:

```powershell
.\run_backend.bat
```

From `project_postgres/backend/db` (also works):

```powershell
.\run_backend.bat
```

What it does automatically:
- Creates `project_postgres/backend/.venv` if missing.
- Installs requirements only on first run (or when `requirements.txt` changes).
- Starts Uvicorn from `backend/db` with the correct interpreter.

This avoids common issues with using the wrong virtualenv (for example `project/backend/db/.venv` vs `project_postgres/backend/.venv`).

Optional:

```powershell
python run_backend.py --setup-only
python run_backend.py --no-reload
```

## Website suggestion search with Meilisearch

SECA can use Meilisearch for much faster website suggestions in Access Control.

Add these variables to `.env`:

```env
SECA_SUGGEST_ENGINE=meili
SECA_MEILI_URL=http://127.0.0.1:7700
SECA_MEILI_MASTER_KEY=seca-dev-master-key
SECA_MEILI_INDEX=website_suggestions
SECA_MEILI_TIMEOUT_SECONDS=1.0
SECA_MEILI_AUTOSEED=true
```

Included files:

- `run_meilisearch.ps1`: starts a local Meilisearch instance if `backend/tools/meilisearch.exe` exists
- `seed_meilisearch.py`: pushes `db/website_suggestions.json` into the configured Meilisearch index

Typical local flow:

```powershell
cd project_postgres/backend
.\run_meilisearch.ps1
python seed_meilisearch.py
python run_backend.py
```

If Meilisearch is not available, the backend falls back to the built-in hybrid suggestion logic.

## 3) Ensure database exists

Example in `psql`:

```sql
CREATE DATABASE sonprj;
```

## 4) Manual API start (if needed)

If you prefer manual startup, always use `project_postgres/backend/.venv`:

```powershell
cd project_postgres/backend
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload --app-dir db
```

Tables are created automatically at startup (`Base.metadata.create_all(bind=engine)`).

## 5) Optional admin seed

```powershell
python admingen.py
```

## 6) Security verification checks

Run an automatic DB encryption/SSL check:

```powershell
cd db
python check_db_security.py
```

Safe dynamic sandbox test sample is available at:

`db/test_samples/benign_dynamic_probe.cmd`

## Threat feed import from Kaggle

The backend can import the public dataset `sid321axn/malicious-urls-dataset` into `threat_urls`.

From `project_postgres/backend`:

```powershell
.\.venv\Scripts\python.exe .\db\import_kaggle_malicious_urls.py
```

What it does:
- downloads the dataset through `kagglehub`
- reads `malicious_phish.csv`
- imports only `phishing`, `malware`, and `defacement`
- skips `benign`
- normalizes scheme-less rows to `https://...`
- stores URLs encrypted in `threat_urls`

Useful options:

```powershell
.\.venv\Scripts\python.exe .\db\import_kaggle_malicious_urls.py --dry-run
.\.venv\Scripts\python.exe .\db\import_kaggle_malicious_urls.py --limit 5000
.\.venv\Scripts\python.exe .\db\import_kaggle_malicious_urls.py --verified
```
