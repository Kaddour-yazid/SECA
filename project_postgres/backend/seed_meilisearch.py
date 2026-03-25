from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parent
ENV_FILE = BACKEND_DIR / ".env"
SEED_FILE = BACKEND_DIR / "db" / "website_suggestions.json"


def meili_url() -> str:
    return os.environ.get("SECA_MEILI_URL", "http://127.0.0.1:7700").strip().rstrip("/")


def meili_key() -> str:
    return os.environ.get("SECA_MEILI_MASTER_KEY", "").strip()


def meili_index() -> str:
    return os.environ.get("SECA_MEILI_INDEX", "website_suggestions").strip() or "website_suggestions"


def headers() -> dict[str, str]:
    data = {"Content-Type": "application/json"}
    key = meili_key()
    if key:
        data["Authorization"] = f"Bearer {key}"
    return data


def request(method: str, path: str, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{meili_url()}{path}", data=body, method=method.upper(), headers=headers())
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read().decode("utf-8", "ignore").strip()
    return json.loads(raw) if raw else {}


def ensure_index() -> None:
    index = meili_index()
    try:
        request("GET", f"/indexes/{index}")
    except Exception:
        request("POST", "/indexes", {"uid": index, "primaryKey": "id"})

    request(
        "PATCH",
        f"/indexes/{index}/settings",
        {
            "searchableAttributes": ["label", "pattern", "aliases", "description", "category"],
            "filterableAttributes": ["category"],
            "sortableAttributes": ["popularity"],
        },
    )


def main() -> int:
    load_dotenv(ENV_FILE)

    if not SEED_FILE.exists():
        print(f"Seed file not found: {SEED_FILE}")
        return 1

    with SEED_FILE.open("r", encoding="utf-8") as handle:
        docs = json.load(handle)

    ensure_index()
    result = request("POST", f"/indexes/{meili_index()}/documents", docs)
    print(f"Seeded {len(docs)} website suggestions into {meili_index()}")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
