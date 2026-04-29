from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, BackgroundTasks, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import or_, inspect, text
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel
from collections import Counter, defaultdict, deque
from email import policy
from email.parser import BytesParser, Parser
from email.utils import getaddresses
import asyncio
import base64
import uuid
import fnmatch
from concurrent.futures import ThreadPoolExecutor
import json
import ipaddress
import hashlib
import io
import math
import re
import os
import socket
import ssl
import shutil
import subprocess
import tempfile
import time
import logging
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlsplit, urljoin
from datetime import datetime, timedelta
from html import unescape
import unicodedata

from database import get_db, engine, Base
from models import (
    User,
    Scan,
    AuditLog,
    PhishTankEntry,
    ThreatUrl,
    ProxyBlockRule,
    DesktopDevice,
    DesktopSession,
    GroupProxyAssignment,
    ExternalReputationCache,
)
import schemas
from auth import (
    get_current_user,
    require_admin,
    create_access_token,
    router as auth_router,
    DEPARTMENT_GROUPS,
    DEPARTMENT_ALIASES,
)
from sandbox_runner import run_dynamic_scan as sandbox_run_dynamic_scan
from security_utils import sha256_hex

try:
    import pefile  # type: ignore
except Exception:
    pefile = None

try:
    import yara  # type: ignore
except Exception:
    yara = None

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError  # type: ignore
except Exception:
    async_playwright = None
    PlaywrightTimeoutError = Exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)


def _ensure_auth_profile_columns() -> None:
    column_defs = {
        "users": {
            "first_name": "VARCHAR",
            "last_name": "VARCHAR",
            "sex": "VARCHAR",
            "department": "VARCHAR",
            "group_name": "VARCHAR",
        },
        "email_otps": {
            "first_name": "VARCHAR",
            "last_name": "VARCHAR",
            "sex": "VARCHAR",
            "department": "VARCHAR",
            "group_name": "VARCHAR",
        },
    }

    with engine.begin() as connection:
        inspector = inspect(connection)
        for table_name, columns in column_defs.items():
            try:
                existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            except Exception as exc:
                logger.warning("Unable to inspect %s for auth profile migration: %s", table_name, exc)
                continue

            for column_name, column_type in columns.items():
                if column_name in existing_columns:
                    continue
                connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
                logger.info("Added missing column %s.%s", table_name, column_name)


_ensure_auth_profile_columns()

app = FastAPI(title="Security Analyzer API")

gateway_history = deque(maxlen=1000)
gateway_clients: Dict[str, int] = {}
gateway_devices: Dict[str, Dict[str, Any]] = {}
gateway_device_aliases: Dict[str, str] = {}
gateway_method_counts: Dict[str, int] = {}
gateway_blocked_count = 0
gateway_allowed_count = 0
gateway_device_counter = 0
gateway_state_lock = threading.Lock()
gateway_active_connections: Dict[str, int] = {}
gateway_client_last_activity: Dict[str, float] = {}
gateway_device_online_state: Dict[str, bool] = {}
gateway_audit_queue: deque[Tuple[str, str]] = deque()
gateway_audit_queue_lock = threading.Lock()
gateway_started_at = datetime.utcnow()
proxy_client_writers: set = set()
proxy_client_writers_lock = threading.Lock()
desktop_sessions: Dict[str, Dict[str, Any]] = {}
desktop_session_lock = threading.Lock()
GATEWAY_INGEST_TOKEN = os.environ.get("SECA_GATEWAY_INGEST_TOKEN", "").strip()
DEFAULT_PROXY_BLOCK_RULES = [
    ("*.youtube.com", "Starter default rule"),
    ("*.facebook.com", "Starter default rule"),
]


def _read_int_env(name: str, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        parsed = int(raw_value.strip())
    except ValueError:
        logger.warning("Invalid %s value %r; using default %s", name, raw_value, default)
        return default

    if minimum is not None and parsed < minimum:
        logger.warning("%s=%s is below minimum %s; clamping to %s", name, parsed, minimum, minimum)
        parsed = minimum
    if maximum is not None and parsed > maximum:
        logger.warning("%s=%s is above maximum %s; clamping to %s", name, parsed, maximum, maximum)
        parsed = maximum
    return parsed


def _read_float_env(name: str, default: float, minimum: Optional[float] = None, maximum: Optional[float] = None) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        parsed = float(raw_value.strip())
    except ValueError:
        logger.warning("Invalid %s value %r; using default %s", name, raw_value, default)
        return default

    if minimum is not None and parsed < minimum:
        logger.warning("%s=%s is below minimum %s; clamping to %s", name, parsed, minimum, minimum)
        parsed = minimum
    if maximum is not None and parsed > maximum:
        logger.warning("%s=%s is above maximum %s; clamping to %s", name, parsed, maximum, maximum)
        parsed = maximum
    return parsed


def _read_bool_env(name: str, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


SECA_PROXY_AUTOSTART = _read_bool_env("SECA_PROXY_AUTOSTART", False)
SECA_PROXY_LISTEN_HOST = os.environ.get("SECA_PROXY_LISTEN_HOST", "127.0.0.1").strip() or "127.0.0.1"
SECA_PROXY_LISTEN_PORT = _read_int_env("SECA_PROXY_LISTEN_PORT", 3128, minimum=1, maximum=65535)
SECA_PROXY_BLOCKLIST_REFRESH_SECONDS = _read_int_env("SECA_PROXY_BLOCKLIST_REFRESH_SECONDS", 10, minimum=2)
SECA_PROXY_ACTIVE_WINDOW_SECONDS = _read_int_env("SECA_PROXY_ACTIVE_WINDOW_SECONDS", 60, minimum=5)
SECA_PROXY_TUNNEL_CHUNK_BYTES = _read_int_env("SECA_PROXY_TUNNEL_CHUNK_BYTES", 262144, minimum=16384, maximum=1048576)
SECA_PROXY_ACTIVITY_TOUCH_SECONDS = _read_float_env("SECA_PROXY_ACTIVITY_TOUCH_SECONDS", 1.0, minimum=0.2, maximum=10.0)
SECA_PROXY_STATIC_SCAN_DELAY_MS = _read_int_env("SECA_PROXY_STATIC_SCAN_DELAY_MS", 400, minimum=0, maximum=10000)
SECA_PROXY_STATIC_AUDIT_SYNC = _read_bool_env("SECA_PROXY_STATIC_AUDIT_SYNC", True)
SECA_PROXY_TLS_INTERCEPT = _read_bool_env("SECA_PROXY_TLS_INTERCEPT", False)
SECA_PROXY_TLS_CA_CERT_PATH = os.environ.get("SECA_PROXY_TLS_CA_CERT_PATH", "").strip()
SECA_PROXY_TLS_CA_KEY_PATH = os.environ.get("SECA_PROXY_TLS_CA_KEY_PATH", "").strip()
SECA_GATEWAY_AUDIT_ASYNC = os.environ.get("SECA_GATEWAY_AUDIT_ASYNC", "true").strip().lower() in {"1", "true", "yes", "on"}
SECA_GATEWAY_AUDIT_FLUSH_SECONDS = _read_float_env("SECA_GATEWAY_AUDIT_FLUSH_SECONDS", 0.5, minimum=0.1, maximum=5.0)
SECA_GATEWAY_AUDIT_BATCH_SIZE = _read_int_env("SECA_GATEWAY_AUDIT_BATCH_SIZE", 200, minimum=20, maximum=2000)
SECA_SUGGEST_ENGINE = os.environ.get("SECA_SUGGEST_ENGINE", "hybrid").strip().lower() or "hybrid"
SECA_MEILI_URL = os.environ.get("SECA_MEILI_URL", "http://127.0.0.1:7700").strip().rstrip("/")
SECA_MEILI_MASTER_KEY = os.environ.get("SECA_MEILI_MASTER_KEY", "").strip()
SECA_MEILI_INDEX = os.environ.get("SECA_MEILI_INDEX", "website_suggestions").strip() or "website_suggestions"
SECA_MEILI_TIMEOUT_SECONDS = _read_float_env("SECA_MEILI_TIMEOUT_SECONDS", 1.0, minimum=0.2, maximum=5.0)
SECA_MEILI_AUTOSEED = _read_bool_env("SECA_MEILI_AUTOSEED", True)
SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS = _read_int_env("SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS", 15, minimum=5, maximum=120)
SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS = _read_int_env(
    "SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS",
    max(SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS * 3, 45),
    minimum=15,
    maximum=600,
)
SECA_DESKTOP_SESSION_RETENTION_SECONDS = _read_int_env(
    "SECA_DESKTOP_SESSION_RETENTION_SECONDS",
    3600,
    minimum=300,
    maximum=86400,
)
SECA_GROUP_PROXY_DEFAULT_HOST = os.environ.get("SECA_GROUP_PROXY_DEFAULT_HOST", SECA_PROXY_LISTEN_HOST).strip() or SECA_PROXY_LISTEN_HOST
SECA_GROUP_PROXY_BASE_PORT = _read_int_env("SECA_GROUP_PROXY_BASE_PORT", 3201, minimum=1025, maximum=65000)
SECA_MALWAREBAZAAR_ENABLED = _read_bool_env("SECA_MALWAREBAZAAR_ENABLED", True)
SECA_MALWAREBAZAAR_API_URL = os.environ.get("SECA_MALWAREBAZAAR_API_URL", "https://mb-api.abuse.ch/api/v1/").strip() or "https://mb-api.abuse.ch/api/v1/"
SECA_MALWAREBAZAAR_API_KEY = os.environ.get("SECA_MALWAREBAZAAR_API_KEY", "").strip()
SECA_MALWAREBAZAAR_TIMEOUT_SECONDS = _read_float_env("SECA_MALWAREBAZAAR_TIMEOUT_SECONDS", 4.0, minimum=1.0, maximum=15.0)
SECA_HASHLOOKUP_ENABLED = _read_bool_env("SECA_HASHLOOKUP_ENABLED", True)
SECA_HASHLOOKUP_API_URL = os.environ.get("SECA_HASHLOOKUP_API_URL", "https://hashlookup.circl.lu").strip().rstrip("/") or "https://hashlookup.circl.lu"
SECA_HASHLOOKUP_TIMEOUT_SECONDS = _read_float_env("SECA_HASHLOOKUP_TIMEOUT_SECONDS", 3.0, minimum=0.5, maximum=10.0)
SECA_YARA_RULES_DIR = os.environ.get("SECA_YARA_RULES_DIR", "").strip()
SECA_AUTHENTICODE_ENABLED = _read_bool_env("SECA_AUTHENTICODE_ENABLED", os.name == "nt")
SECA_AUTHENTICODE_TIMEOUT_SECONDS = _read_float_env("SECA_AUTHENTICODE_TIMEOUT_SECONDS", 8.0, minimum=2.0, maximum=30.0)
SECA_CLAMAV_ENABLED = _read_bool_env("SECA_CLAMAV_ENABLED", False)
SECA_CLAMAV_MODE = os.environ.get("SECA_CLAMAV_MODE", "auto").strip().lower() or "auto"
SECA_CLAMAV_TIMEOUT_SECONDS = _read_float_env("SECA_CLAMAV_TIMEOUT_SECONDS", 20.0, minimum=2.0, maximum=120.0)
SECA_CLAMAV_DETECT_PUA = _read_bool_env("SECA_CLAMAV_DETECT_PUA", False)
SECA_CLAMSCAN_PATH = os.environ.get("SECA_CLAMSCAN_PATH", "clamscan").strip() or "clamscan"
SECA_CLAMD_HOST = os.environ.get("SECA_CLAMD_HOST", "127.0.0.1").strip() or "127.0.0.1"
SECA_CLAMD_PORT = _read_int_env("SECA_CLAMD_PORT", 3310, minimum=1, maximum=65535)
proxy_server = None
proxy_blocklist_cache: List[str] = []
proxy_blocklist_last_fetch = 0.0
proxy_blocklist_suggestion_cache: Dict[str, Tuple[float, List[Dict[str, str]]]] = {}
proxy_meili_seed_attempted = False

PROXY_BLOCKLIST_SHORTCUTS = {
    "yt": "youtube",
    "youtube": "youtube",
    "fb": "facebook",
    "facebook": "facebook",
    "ig": "instagram",
    "insta": "instagram",
    "instagram": "instagram",
    "wa": "whatsapp",
    "whatsapp": "whatsapp",
    "tw": "twitter",
    "twitter": "twitter",
    "x": "twitter",
}

PROXY_SERVICE_BLOCK_BUNDLES = {
    "youtube": ["*youtube*", "*ytimg*", "*googlevideo*", "*youtu.be*", "*yt3*"],
    "facebook": ["*facebook*", "*fbcdn*", "*fbsbx*", "*messenger*"],
    "instagram": ["*instagram*", "*cdninstagram*"],
    "twitter": ["*twitter*", "*twimg*", "*x.com*"],
    "whatsapp": ["*whatsapp*", "*whatsapp.net*", "*wa.me*"],
}

PROXY_SERVICE_DOMAIN_HINTS = {
    "youtube": ("youtube", "youtu.be", "ytimg", "googlevideo", "yt3"),
    "facebook": ("facebook", "fbcdn", "fbsbx", "messenger"),
    "instagram": ("instagram", "cdninstagram"),
    "twitter": ("twitter", "twimg", "x.com"),
    "whatsapp": ("whatsapp", "whatsapp.net", "wa.me"),
}

PROXY_WEBSITE_SUGGESTIONS = [
    {
        "id": "youtube-main",
        "label": "YouTube main domain",
        "pattern": "youtube.com",
        "description": "Blocks the main YouTube website.",
        "aliases": ("youtube", "you", "yt", "video"),
    },
    {
        "id": "youtube-dns",
        "label": "YouTube API / DNS",
        "pattern": "youtubei.googleapis.com",
        "description": "Useful for mobile app traffic and API calls.",
        "aliases": ("youtube", "you", "yt", "dns", "api", "googleapis"),
    },
    {
        "id": "youtube-media",
        "label": "YouTube media CDN",
        "pattern": "googlevideo.com",
        "description": "Used for YouTube video delivery.",
        "aliases": ("youtube", "yt", "cdn", "media", "googlevideo"),
    },
    {
        "id": "youtube-assets",
        "label": "YouTube static assets",
        "pattern": "ytimg.com",
        "description": "Used for thumbnails and static resources.",
        "aliases": ("youtube", "yt", "assets", "thumb", "ytimg"),
    },
    {
        "id": "facebook-main",
        "label": "Facebook main domain",
        "pattern": "facebook.com",
        "description": "Blocks the main Facebook website.",
        "aliases": ("facebook", "face", "fb", "meta"),
    },
    {
        "id": "facebook-cdn",
        "label": "Facebook CDN",
        "pattern": "fbcdn.net",
        "description": "Useful for Facebook app assets and media.",
        "aliases": ("facebook", "fb", "cdn", "fbcdn"),
    },
    {
        "id": "messenger-main",
        "label": "Messenger",
        "pattern": "messenger.com",
        "description": "Blocks the Messenger web service.",
        "aliases": ("facebook", "fb", "messenger", "meta"),
    },
    {
        "id": "instagram-main",
        "label": "Instagram",
        "pattern": "instagram.com",
        "description": "Blocks the Instagram website.",
        "aliases": ("instagram", "insta", "ig", "meta"),
    },
    {
        "id": "instagram-cdn",
        "label": "Instagram CDN",
        "pattern": "cdninstagram.com",
        "description": "Useful for Instagram media delivery.",
        "aliases": ("instagram", "insta", "ig", "cdn"),
    },
    {
        "id": "whatsapp-main",
        "label": "WhatsApp Web",
        "pattern": "web.whatsapp.com",
        "description": "Blocks WhatsApp Web access.",
        "aliases": ("whatsapp", "wa", "chat"),
    },
    {
        "id": "whatsapp-network",
        "label": "WhatsApp network",
        "pattern": "whatsapp.net",
        "description": "Useful for broader WhatsApp app traffic.",
        "aliases": ("whatsapp", "wa", "network"),
    },
    {
        "id": "discord-main",
        "label": "Discord",
        "pattern": "discord.com",
        "description": "Blocks the main Discord website.",
        "aliases": ("discord", "disc", "chat"),
    },
    {
        "id": "discord-invite",
        "label": "Discord invite links",
        "pattern": "discord.gg",
        "description": "Useful for invitation and shared links.",
        "aliases": ("discord", "disc", "invite", "gg"),
    },
    {
        "id": "openai-main",
        "label": "OpenAI",
        "pattern": "openai.com",
        "description": "Blocks the OpenAI website.",
        "aliases": ("openai", "ai", "gpt"),
    },
    {
        "id": "chatgpt-main",
        "label": "ChatGPT",
        "pattern": "chatgpt.com",
        "description": "Blocks the ChatGPT app website.",
        "aliases": ("chatgpt", "gpt", "openai", "chat"),
    },
    {
        "id": "github-main",
        "label": "GitHub",
        "pattern": "github.com",
        "description": "Blocks the GitHub website.",
        "aliases": ("github", "git", "code"),
    },
    {
        "id": "linkedin-main",
        "label": "LinkedIn",
        "pattern": "linkedin.com",
        "description": "Blocks the LinkedIn website.",
        "aliases": ("linkedin", "link", "jobs"),
    },
    {
        "id": "reddit-main",
        "label": "Reddit",
        "pattern": "reddit.com",
        "description": "Blocks the Reddit website.",
        "aliases": ("reddit", "forum", "social"),
    },
    {
        "id": "spotify-main",
        "label": "Spotify",
        "pattern": "spotify.com",
        "description": "Blocks the Spotify website.",
        "aliases": ("spotify", "music", "audio"),
    },
    {
        "id": "tiktok-main",
        "label": "TikTok",
        "pattern": "tiktok.com",
        "description": "Blocks the TikTok website.",
        "aliases": ("tiktok", "tik", "tt"),
    },
    {
        "id": "telegram-main",
        "label": "Telegram",
        "pattern": "telegram.org",
        "description": "Blocks the Telegram website.",
        "aliases": ("telegram", "tele", "chat"),
    },
    {
        "id": "x-main",
        "label": "X / Twitter",
        "pattern": "x.com",
        "description": "Blocks the X main domain.",
        "aliases": ("x", "twitter", "tw"),
    },
    {
        "id": "twitter-cdn",
        "label": "Twitter media CDN",
        "pattern": "twimg.com",
        "description": "Useful for media and static assets.",
        "aliases": ("twitter", "tw", "x", "cdn"),
    },
]

PROXY_SUGGESTION_STOPWORDS = {"download", "login", "support", "web", "api", "key", "platform", "official", "site"}
PROXY_SUGGESTION_CACHE_SECONDS = 300.0
WEBSITE_SUGGESTIONS_FILE = os.path.join(os.path.dirname(__file__), "website_suggestions.json")


class GatewayBlockRuleCreate(BaseModel):
    pattern: str
    note: Optional[str] = None
    enabled: bool = True


class GatewayBlockRuleUpdate(BaseModel):
    pattern: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class DesktopSessionHeartbeat(BaseModel):
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    hostname: Optional[str] = None
    app_version: Optional[str] = None
    platform: Optional[str] = None
    local_ips: Optional[List[str]] = None
    proxy_host: Optional[str] = None
    proxy_port: Optional[int] = None


def _is_web_session_payload(payload: DesktopSessionHeartbeat) -> bool:
    app_version = str(payload.app_version or "").strip().lower()
    return app_version.startswith("web")


class DesktopSessionStop(BaseModel):
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    reason: Optional[str] = None


def _require_gateway_ingest_token(x_gateway_token: Optional[str]) -> None:
    if GATEWAY_INGEST_TOKEN and x_gateway_token != GATEWAY_INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid gateway token")


def _effective_blocklist(db: Session) -> List[str]:
    rows = (
        db.query(ProxyBlockRule)
        .filter(ProxyBlockRule.enabled.is_(True))
        .order_by(ProxyBlockRule.pattern.asc())
        .all()
    )
    return [r.pattern for r in rows]


def _normalize_proxy_block_pattern(raw_pattern: str) -> str:
    value = (raw_pattern or "").strip().lower()
    if not value:
        raise HTTPException(status_code=400, detail="Pattern is required")

    if value.startswith("http://") or value.startswith("https://"):
        try:
            value = urlsplit(value).hostname or ""
        except Exception:
            raise HTTPException(status_code=400, detail="Pattern is invalid")

    value = value.split("/")[0].strip().strip(".")
    if value.startswith("www."):
        value = value[4:]
    if not value:
        raise HTTPException(status_code=400, detail="Pattern is required")

    service_key = _proxy_service_key_from_value(value)
    if service_key:
        return f"*{service_key}*"

    if "*" in value:
        return value

    if "." in value:
        return f"*.{value}"

    shortcut = PROXY_BLOCKLIST_SHORTCUTS.get(value, value)
    return f"*{shortcut}*"


def _invalidate_proxy_blocklist_cache() -> None:
    global proxy_blocklist_cache, proxy_blocklist_last_fetch
    proxy_blocklist_cache = []
    proxy_blocklist_last_fetch = 0.0


def _blocklist_suggestion_score(entry: Dict[str, Any], query: str) -> int:
    q = (query or "").strip().lower()
    if not q:
        return 0
    label = str(entry.get("label") or "").lower()
    pattern = str(entry.get("pattern") or "").lower()
    aliases = [str(alias).lower() for alias in entry.get("aliases") or ()]
    score = 0
    if pattern.startswith(q):
        score += 120
    if any(alias.startswith(q) for alias in aliases):
        score += 100
    if q in label:
        score += 80
    if q in pattern:
        score += 60
    if any(q in alias for alias in aliases):
        score += 50
    return score


def _catalog_blocklist_suggestions(query: str) -> List[Dict[str, Any]]:
    scored = []
    for entry in PROXY_WEBSITE_SUGGESTIONS:
        score = _blocklist_suggestion_score(entry, query)
        if score > 0:
            scored.append((score, entry))
    scored.sort(key=lambda item: (-item[0], str(item[1].get("label") or "")))
    return [item[1] for item in scored]


def _guess_domain_from_phrase(phrase: str) -> Optional[str]:
    normalized = unicodedata.normalize("NFKD", phrase or "").encode("ascii", "ignore").decode("ascii").lower()
    normalized = re.sub(r"[^a-z0-9.\s-]", " ", normalized)
    tokens = [token for token in re.split(r"[\s/]+", normalized) if token and token not in PROXY_SUGGESTION_STOPWORDS]
    if not tokens:
        return None

    dotted = next((token for token in tokens if "." in token and len(token) >= 4), None)
    if dotted:
        return dotted.strip(".")

    compact = "".join(tokens[:2]).strip(".")
    if compact in {"chatgpt", "openai", "youtube", "discord", "facebook", "instagram", "linkedin", "spotify", "reddit", "tiktok", "telegram", "github"}:
        return f"{compact}.com" if compact not in {"telegram"} else "telegram.org"

    first = tokens[0].strip(".")
    if len(first) < 3:
        return None
    return f"{first}.com"


def _fetch_live_blocklist_suggestions(query: str) -> List[str]:
    if len((query or "").strip()) < 2:
        return []
    url = f"https://duckduckgo.com/ac/?q={quote(query.strip())}&type=list"
    req = urllib.request.Request(url, headers={"User-Agent": "SECA/1.0"})
    with urllib.request.urlopen(req, timeout=1.5) as response:
        payload = json.loads(response.read().decode("utf-8", "ignore"))
    if isinstance(payload, list) and len(payload) >= 2 and isinstance(payload[1], list):
        return [str(item).strip() for item in payload[1] if str(item).strip()]
    return []


def _meili_enabled() -> bool:
    return SECA_SUGGEST_ENGINE in {"meili", "meilisearch", "hybrid"} and bool(SECA_MEILI_URL)


def _meili_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if SECA_MEILI_MASTER_KEY:
        headers["Authorization"] = f"Bearer {SECA_MEILI_MASTER_KEY}"
    return headers


def _meili_request(method: str, path: str, payload: Optional[Dict[str, Any] | List[Dict[str, Any]]] = None) -> Any:
    if not _meili_enabled():
        raise RuntimeError("Meilisearch is not enabled")
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{SECA_MEILI_URL}{path}",
        data=body,
        method=method.upper(),
        headers=_meili_headers(),
    )
    with urllib.request.urlopen(request, timeout=SECA_MEILI_TIMEOUT_SECONDS) as response:
        raw = response.read().decode("utf-8", "ignore").strip()
    return json.loads(raw) if raw else None


def _load_seed_website_suggestions() -> List[Dict[str, Any]]:
    documents: List[Dict[str, Any]] = []
    if os.path.exists(WEBSITE_SUGGESTIONS_FILE):
        try:
            with open(WEBSITE_SUGGESTIONS_FILE, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, list):
                documents.extend([item for item in payload if isinstance(item, dict)])
        except Exception as exc:
            logger.warning("Failed to load website suggestions file %s: %s", WEBSITE_SUGGESTIONS_FILE, exc)

    if not documents:
        for entry in PROXY_WEBSITE_SUGGESTIONS:
            documents.append({
                "id": str(entry.get("id") or entry.get("pattern")),
                "label": str(entry.get("label") or entry.get("pattern")),
                "pattern": str(entry.get("pattern") or ""),
                "description": str(entry.get("description") or "Popular service suggestion."),
                "aliases": list(entry.get("aliases") or ()),
                "category": "featured",
                "popularity": 100,
            })

    seen_ids: set[str] = set()
    normalized_docs: List[Dict[str, Any]] = []
    for index, doc in enumerate(documents):
        pattern = str(doc.get("pattern") or "").strip()
        label = str(doc.get("label") or pattern).strip()
        if not pattern or not label:
            continue
        doc_id = str(doc.get("id") or f"seed-{index}")
        if doc_id in seen_ids:
            continue
        seen_ids.add(doc_id)
        aliases = [str(alias).strip() for alias in doc.get("aliases") or [] if str(alias).strip()]
        normalized_docs.append({
            "id": doc_id,
            "label": label,
            "pattern": pattern,
            "description": str(doc.get("description") or "Website suggestion."),
            "aliases": aliases,
            "category": str(doc.get("category") or "general"),
            "popularity": int(doc.get("popularity") or 50),
        })
    return normalized_docs


def _ensure_meili_index() -> None:
    try:
        _meili_request("GET", f"/indexes/{SECA_MEILI_INDEX}")
    except Exception:
        _meili_request("POST", "/indexes", {"uid": SECA_MEILI_INDEX, "primaryKey": "id"})
    settings = {
        "searchableAttributes": ["label", "pattern", "aliases", "description", "category"],
        "filterableAttributes": ["category"],
        "sortableAttributes": ["popularity"],
        "rankingRules": [
            "words",
            "typo",
            "proximity",
            "attribute",
            "sort",
            "exactness",
        ],
    }
    _meili_request("PATCH", f"/indexes/{SECA_MEILI_INDEX}/settings", settings)


def _seed_meili_index() -> Dict[str, Any]:
    documents = _load_seed_website_suggestions()
    _ensure_meili_index()
    result = _meili_request("POST", f"/indexes/{SECA_MEILI_INDEX}/documents", documents)
    return {
        "documents": len(documents),
        "task": result or {},
    }


def _meili_blocklist_suggestions(query: str, limit: int = 8) -> List[Dict[str, str]]:
    search_payload = {
        "q": query,
        "limit": limit,
        "sort": ["popularity:desc"],
        "attributesToRetrieve": ["id", "label", "pattern", "description", "category"],
    }
    response = _meili_request("POST", f"/indexes/{SECA_MEILI_INDEX}/search", search_payload) or {}
    hits = response.get("hits") or []
    return [
        {
            "id": str(hit.get("id") or hit.get("pattern") or f"meili-{index}"),
            "label": str(hit.get("label") or hit.get("pattern") or "Website"),
            "pattern": str(hit.get("pattern") or ""),
            "description": str(hit.get("description") or "Meilisearch suggestion."),
            "source": "meili",
        }
        for index, hit in enumerate(hits)
        if str(hit.get("pattern") or "").strip()
    ]


def _build_proxy_blocklist_suggestions(query: str) -> List[Dict[str, str]]:
    global proxy_meili_seed_attempted
    q = (query or "").strip().lower()
    if len(q) < 2:
        return []

    cached = proxy_blocklist_suggestion_cache.get(q)
    now = time.monotonic()
    if cached and now - cached[0] < PROXY_SUGGESTION_CACHE_SECONDS:
        return cached[1]

    suggestions: List[Dict[str, str]] = []
    seen_patterns: set[str] = set()

    if _meili_enabled():
        try:
            if SECA_MEILI_AUTOSEED and not proxy_meili_seed_attempted:
                _seed_meili_index()
                proxy_meili_seed_attempted = True
            else:
                _ensure_meili_index()
            meili_hits = _meili_blocklist_suggestions(q, limit=8)
            for item in meili_hits:
                normalized = _normalize_proxy_block_pattern(item["pattern"])
                if normalized in seen_patterns:
                    continue
                seen_patterns.add(normalized)
                suggestions.append(item)
        except Exception as exc:
            logger.warning("Meilisearch suggestions failed for %s: %s", q, exc)

    for entry in _catalog_blocklist_suggestions(q):
        pattern = str(entry.get("pattern") or "").strip()
        normalized = _normalize_proxy_block_pattern(pattern)
        if normalized in seen_patterns:
            continue
        seen_patterns.add(normalized)
        suggestions.append({
            "id": str(entry.get("id") or normalized),
            "label": str(entry.get("label") or pattern),
            "pattern": pattern,
            "description": str(entry.get("description") or "Popular service suggestion."),
            "source": "featured",
        })

    try:
        live_terms = _fetch_live_blocklist_suggestions(q)
    except Exception as exc:
        logger.warning("Blocklist live suggestions failed for %s: %s", q, exc)
        live_terms = []

    for index, term in enumerate(live_terms):
        matched_catalog = _catalog_blocklist_suggestions(term)
        if matched_catalog:
            for entry in matched_catalog[:2]:
                pattern = str(entry.get("pattern") or "").strip()
                normalized = _normalize_proxy_block_pattern(pattern)
                if normalized in seen_patterns:
                    continue
                seen_patterns.add(normalized)
                suggestions.append({
                    "id": f"live-{entry.get('id')}",
                    "label": str(entry.get("label") or pattern),
                    "pattern": pattern,
                    "description": f"Live match for '{term}'.",
                    "source": "live",
                })
            continue

        domain = _guess_domain_from_phrase(term)
        if not domain:
            continue
        normalized = _normalize_proxy_block_pattern(domain)
        if normalized in seen_patterns:
            continue
        seen_patterns.add(normalized)
        suggestions.append({
            "id": f"live-domain-{index}",
            "label": term.title(),
            "pattern": domain,
            "description": f"Live web suggestion for '{term}'.",
            "source": "live",
        })

    final = suggestions[:10]
    proxy_blocklist_suggestion_cache[q] = (now, final)
    return final


def _register_proxy_client_writer(writer: asyncio.StreamWriter) -> None:
    with proxy_client_writers_lock:
        proxy_client_writers.add(writer)


def _unregister_proxy_client_writer(writer: asyncio.StreamWriter) -> None:
    with proxy_client_writers_lock:
        proxy_client_writers.discard(writer)


async def _reset_active_proxy_connections() -> None:
    with proxy_client_writers_lock:
        writers = list(proxy_client_writers)

    if not writers:
        return

    for writer in writers:
        try:
            writer.close()
        except Exception:
            pass

    await asyncio.gather(
        *(writer.wait_closed() for writer in writers),
        return_exceptions=True,
    )


def _proxy_service_key_from_value(value: str) -> Optional[str]:
    candidate = str(value or "").lower().strip().strip(".")
    if not candidate:
        return None

    shortcut = PROXY_BLOCKLIST_SHORTCUTS.get(candidate)
    if shortcut:
        return shortcut

    trimmed = candidate.lstrip("*.").replace("*", "").strip().strip(".")
    if not trimmed:
        return None

    for service_key, hints in PROXY_SERVICE_DOMAIN_HINTS.items():
        if trimmed == service_key:
            return service_key
        for hint in hints:
            normalized_hint = hint.lower().strip().strip(".")
            if (
                trimmed == normalized_hint
                or trimmed.endswith(f".{normalized_hint}")
                or normalized_hint in trimmed
            ):
                return service_key
    return None


def _proxy_pattern_variants(pattern: str) -> List[str]:
    candidate = str(pattern or "").lower().strip().strip(".")
    if not candidate:
        return []

    variants: List[str] = [candidate]
    trimmed = candidate.lstrip("*.").strip()
    if trimmed and trimmed != candidate:
        variants.append(trimmed)

    bundle_key = trimmed.replace("*", "").strip().strip(".")
    if bundle_key and "." not in bundle_key:
        variants.extend(PROXY_SERVICE_BLOCK_BUNDLES.get(bundle_key, []))

    deduped: List[str] = []
    seen = set()
    for item in variants:
        normalized = str(item).lower().strip().strip(".")
        if not normalized or normalized in seen:
            continue
        deduped.append(normalized)
        seen.add(normalized)
    return deduped


def _proxy_rule_identity(pattern: str) -> str:
    normalized = str(pattern or "").lower().strip().strip(".")
    if not normalized:
        return ""
    service_key = _proxy_service_key_from_value(normalized)
    if service_key:
        return f"service:{service_key}"
    return normalized


def _gateway_protocol(method: str, target: Optional[str], port: int) -> str:
    method_u = (method or "").upper()
    target_s = (target or "").lower()
    if method_u == "CONNECT":
        return "https"
    if target_s.startswith("https://") or port == 443:
        return "https"
    return "http"


def _get_or_create_device_alias(client_ip: str) -> str:
    global gateway_device_counter
    alias = gateway_device_aliases.get(client_ip)
    if alias:
        return alias
    gateway_device_counter += 1
    alias = f"PC {gateway_device_counter}"
    gateway_device_aliases[client_ip] = alias
    return alias


def _mark_proxy_client_connected(client_ip: str) -> None:
    now_dt = datetime.utcnow()
    now = now_dt.isoformat()
    now_ts = now_dt.timestamp()
    with gateway_state_lock:
        gateway_active_connections[client_ip] = gateway_active_connections.get(client_ip, 0) + 1
        gateway_client_last_activity[client_ip] = now_ts
        gateway_device_online_state[client_ip] = True
        device_name = _get_or_create_device_alias(client_ip)
        device = gateway_devices.get(client_ip)
        if not device:
            device = {
                "device_name": device_name,
                "client_ip": client_ip,
                "first_seen": now,
                "last_seen": now,
                "total_requests": 0,
                "blocked_requests": 0,
                "allowed_requests": 0,
                "methods": {},
                "last_host": "",
            }
            gateway_devices[client_ip] = device
        else:
            device["device_name"] = device_name
            device["last_seen"] = now


def _mark_proxy_client_disconnected(client_ip: str) -> None:
    now_dt = datetime.utcnow()
    now = now_dt.isoformat()
    with gateway_state_lock:
        current = gateway_active_connections.get(client_ip, 0)
        if current <= 1:
            gateway_active_connections.pop(client_ip, None)
            gateway_device_online_state[client_ip] = False
        else:
            gateway_active_connections[client_ip] = current - 1
        device = gateway_devices.get(client_ip)
        if device:
            device["last_seen"] = now


def _mark_proxy_client_activity(client_ip: str, update_last_seen: bool = False) -> None:
    now_ts = time.time()
    with gateway_state_lock:
        gateway_client_last_activity[client_ip] = now_ts
        gateway_device_online_state[client_ip] = True
        if update_last_seen:
            device = gateway_devices.get(client_ip)
            if device:
                device["last_seen"] = datetime.utcnow().isoformat()


def _is_client_online_locked(client_ip: str, now_ts: Optional[float] = None) -> bool:
    if now_ts is None:
        now_ts = time.time()
    # Treat a proxy client as online only while it still has fresh proxy
    # activity. This prevents stale sockets from keeping a device "connected"
    # long after the proxy was disabled on the client machine.
    return _is_client_activity_online_locked(client_ip, now_ts)


def _is_client_activity_online_locked(client_ip: str, now_ts: Optional[float] = None) -> bool:
    if now_ts is None:
        now_ts = time.time()
    last_activity = gateway_client_last_activity.get(client_ip, 0.0)
    if last_activity <= 0:
        return False
    return (now_ts - last_activity) <= SECA_PROXY_ACTIVE_WINDOW_SECONDS


def _connected_client_ips_locked() -> List[str]:
    now_ts = time.time()
    candidates = set(gateway_devices.keys()) | set(gateway_client_last_activity.keys()) | set(gateway_active_connections.keys())
    return [ip for ip in candidates if _is_client_online_locked(ip, now_ts)]


def _gateway_presence_action(online: bool) -> str:
    return "Gateway Client Online" if online else "Gateway Client Offline"


def _gateway_presence_details(client_ip: str, device_name: str, online: bool) -> str:
    if online:
        return f"{device_name} ({client_ip}) started using enterprise proxy."
    return f"{device_name} ({client_ip}) disconnected from enterprise proxy."


def _record_gateway_presence_sync(client_ip: str, device_name: str, online: bool, db: Optional[Session] = None) -> None:
    action = _gateway_presence_action(online)
    details = _gateway_presence_details(client_ip, device_name, online)
    _emit_system_audit_log(action, details, db=db)


def _emit_system_audit_log(action: str, details: str, db: Optional[Session] = None) -> None:
    if db is not None:
        create_system_audit_log(db, action, details)
        return

    if not SECA_GATEWAY_AUDIT_ASYNC:
        with Session(engine) as local_db:
            create_system_audit_log(local_db, action, details)
        return

    with gateway_audit_queue_lock:
        gateway_audit_queue.append((action, details))


def _desktop_user_display_name(user: User) -> str:
    parts = [str(user.first_name or "").strip(), str(user.last_name or "").strip()]
    combined = " ".join(part for part in parts if part).strip()
    return combined or str(user.email or f"user-{user.id}")


def _normalize_department_code(value: Optional[str]) -> str:
    cleaned = str(value or "").strip().upper()
    cleaned = DEPARTMENT_ALIASES.get(cleaned, cleaned)
    if cleaned not in DEPARTMENT_GROUPS:
        raise HTTPException(status_code=400, detail="Invalid department")
    return cleaned


def _normalize_local_ip_list(values: Optional[List[str]]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for raw in values or []:
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip_obj.is_loopback:
            continue
        compact = ip_obj.compressed
        if compact in seen:
            continue
        seen.add(compact)
        normalized.append(compact)
    return normalized


def _serialize_local_ips(values: Optional[List[str]]) -> str:
    return json.dumps(_normalize_local_ip_list(values))


def _deserialize_local_ips(value: Optional[str]) -> List[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return _normalize_local_ip_list([str(item) for item in parsed])


def _group_proxy_scope_rows() -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for department, payload in DEPARTMENT_GROUPS.items():
        for group_name in payload.get("groups", {}).values():
            rows.append((department, group_name))
    return rows


def seed_group_proxy_assignments() -> None:
    try:
        with Session(engine) as db:
            for index, (department, group_name) in enumerate(_group_proxy_scope_rows()):
                existing = (
                    db.query(GroupProxyAssignment)
                    .filter(
                        GroupProxyAssignment.department == department,
                        GroupProxyAssignment.group_name == group_name,
                    )
                    .first()
                )
                if existing:
                    continue
                db.add(
                    GroupProxyAssignment(
                        department=department,
                        group_name=group_name,
                        proxy_host=SECA_GROUP_PROXY_DEFAULT_HOST,
                        proxy_port=SECA_GROUP_PROXY_BASE_PORT + index,
                        enabled=True,
                        note="Auto-seeded group proxy assignment",
                    )
                )
            db.commit()
    except Exception as exc:
        logger.warning("Failed to seed group proxy assignments: %s", exc)


def mark_persisted_desktop_sessions_offline_on_startup() -> None:
    try:
        with Session(engine) as db:
            rows = db.query(DesktopSession).filter(DesktopSession.online.is_(True)).all()
            if not rows:
                return
            now = datetime.utcnow()
            for row in rows:
                row.online = False
                row.disconnect_reason = "backend-restart"
                row.ended_at = now
            db.commit()
    except Exception as exc:
        logger.warning("Failed to reset persisted desktop sessions on startup: %s", exc)


def _desktop_presence_details(session: Dict[str, Any], online: bool, reason: Optional[str] = None) -> str:
    user_name = session.get("user_name") or session.get("email") or f"user-{session.get('user_id')}"
    device_label = session.get("hostname") or session.get("device_id") or "unknown-device"
    scope = f"{session.get('department') or '-'} / {session.get('group_name') or '-'}"
    if online:
        return f"{user_name} connected from {device_label} to SECA desktop. scope={scope}"
    suffix = f" reason={reason}" if reason else ""
    return f"{user_name} disconnected from SECA desktop on {device_label}. scope={scope}{suffix}"


def _emit_desktop_presence_audit(session: Dict[str, Any], online: bool, reason: Optional[str] = None) -> None:
    action = "Desktop Session Online" if online else "Desktop Session Offline"
    _emit_system_audit_log(action, _desktop_presence_details(session, online, reason=reason))


def _desktop_session_scope_matches(session: Dict[str, Any], current_user: User) -> bool:
    admin_department = str(current_user.department or "").strip()
    admin_group = str(current_user.group_name or "").strip()
    if not admin_department or not admin_group:
        return True
    return (
        str(session.get("department") or "").strip() == admin_department
        and str(session.get("group_name") or "").strip() == admin_group
        and not bool(session.get("is_admin"))
    )


def _desktop_session_payload(session: Dict[str, Any]) -> Dict[str, Any]:
    last_heartbeat_ts = float(session.get("last_heartbeat_ts") or 0.0)
    seconds_since_last_heartbeat = int(max(0.0, time.time() - last_heartbeat_ts)) if last_heartbeat_ts > 0 else None
    return {
        "session_id": session.get("session_id"),
        "user_id": session.get("user_id"),
        "user_name": session.get("user_name"),
        "email": session.get("email"),
        "department": session.get("department"),
        "group_name": session.get("group_name"),
        "role": session.get("role"),
        "is_admin": bool(session.get("is_admin", False)),
        "device_id": session.get("device_id"),
        "hostname": session.get("hostname"),
        "platform": session.get("platform"),
        "app_version": session.get("app_version"),
        "local_ips": list(session.get("local_ips") or []),
        "proxy_host": session.get("proxy_host"),
        "proxy_port": session.get("proxy_port"),
        "started_at": session.get("started_at"),
        "last_heartbeat": session.get("last_heartbeat"),
        "online": bool(session.get("online", False)),
        "disconnect_reason": session.get("disconnect_reason"),
        "seconds_since_last_heartbeat": seconds_since_last_heartbeat,
    }


def _desktop_proxy_state_label(session: Dict[str, Any], assignment: Optional[GroupProxyAssignment]) -> str:
    if not bool(session.get("online", False)):
        return "offline"
    if str(session.get("app_version") or "").strip().lower().startswith("web"):
        return "browser-unavailable"
    if not assignment:
        return "unassigned"

    actual_host = str(session.get("proxy_host") or "").strip().lower()
    actual_port = int(session.get("proxy_port") or 0) if session.get("proxy_port") else 0
    assigned_host = str(assignment.proxy_host or "").strip().lower()
    assigned_port = int(assignment.proxy_port or 0) if assignment.proxy_port else 0

    if not actual_host or actual_port <= 0:
        return "disabled"
    if actual_host == assigned_host and actual_port == assigned_port:
        return "ok"
    return "mismatch"


def _desktop_proxy_status_details(
        session: Dict[str, Any],
        previous_state: str,
        current_state: str,
        assignment: Optional[GroupProxyAssignment]
) -> str:
    device_label = session.get("hostname") or session.get("device_id") or "unknown-device"
    user_name = session.get("user_name") or session.get("email") or f"user-{session.get('user_id')}"
    expected = (
        f"{assignment.proxy_host}:{assignment.proxy_port}"
        if assignment and assignment.proxy_host and assignment.proxy_port
        else "none"
    )
    actual_host = str(session.get("proxy_host") or "").strip()
    actual_port = int(session.get("proxy_port") or 0) if session.get("proxy_port") else 0
    actual = f"{actual_host}:{actual_port}" if actual_host and actual_port > 0 else "disabled-or-missing"
    return (
        f"{user_name} on {device_label} changed proxy state "
        f"from {previous_state} to {current_state}. expected={expected} actual={actual}"
    )


def _persist_desktop_session_state(session: Dict[str, Any]) -> None:
    session_started_at = datetime.fromisoformat(session["started_at"]) if session.get("started_at") else datetime.utcnow()
    session_last_heartbeat = datetime.fromisoformat(session["last_heartbeat"]) if session.get("last_heartbeat") else datetime.utcnow()
    local_ips_json = _serialize_local_ips(session.get("local_ips"))
    with Session(engine) as db:
        device = db.query(DesktopDevice).filter(DesktopDevice.device_id == session["device_id"]).first()
        if not device:
            device = DesktopDevice(
                device_id=session["device_id"],
                first_seen=session_started_at,
            )
            db.add(device)

        device.hostname = session.get("hostname")
        device.platform = session.get("platform")
        device.app_version = session.get("app_version")
        device.local_ips = local_ips_json
        device.last_user_id = session.get("user_id")
        device.last_department = session.get("department")
        device.last_group_name = session.get("group_name")
        device.proxy_host = session.get("proxy_host")
        device.proxy_port = session.get("proxy_port")
        device.last_seen = session_last_heartbeat

        session_row = db.query(DesktopSession).filter(DesktopSession.session_id == session["session_id"]).first()
        if not session_row:
            session_row = DesktopSession(
                session_id=session["session_id"],
                user_id=session["user_id"],
                started_at=session_started_at,
            )
            db.add(session_row)

        session_row.user_id = session["user_id"]
        session_row.device_id = session["device_id"]
        session_row.hostname = session.get("hostname")
        session_row.platform = session.get("platform")
        session_row.app_version = session.get("app_version")
        session_row.department = session.get("department")
        session_row.group_name = session.get("group_name")
        session_row.proxy_host = session.get("proxy_host")
        session_row.proxy_port = session.get("proxy_port")
        session_row.local_ips = local_ips_json
        session_row.online = bool(session.get("online", False))
        session_row.disconnect_reason = session.get("disconnect_reason")
        session_row.last_heartbeat_at = session_last_heartbeat
        session_row.ended_at = None if session_row.online else session_last_heartbeat
        db.commit()


def _active_desktop_session_for_client_ip(client_ip: str) -> Optional[Dict[str, Any]]:
    with desktop_session_lock:
        candidates = [
            dict(session)
            for session in desktop_sessions.values()
            if session.get("online") and client_ip in set(session.get("local_ips") or [])
        ]

    if not candidates:
        return None

    candidates.sort(key=lambda session: float(session.get("last_heartbeat_ts") or 0.0), reverse=True)
    return candidates[0]


def _group_proxy_assignment_for_scope(department: Optional[str], group_name: Optional[str], db: Optional[Session] = None) -> Optional[GroupProxyAssignment]:
    dep = str(department or "").strip()
    grp = str(group_name or "").strip()
    if not dep or not grp:
        return None

    def _query(session: Session) -> Optional[GroupProxyAssignment]:
        return (
            session.query(GroupProxyAssignment)
            .filter(
                GroupProxyAssignment.department == dep,
                GroupProxyAssignment.group_name == grp,
                GroupProxyAssignment.enabled.is_(True),
            )
            .first()
        )

    if db is not None:
        return _query(db)
    with Session(engine) as local_db:
        return _query(local_db)


def _db_desktop_session_payload(row: DesktopSession) -> Dict[str, Any]:
    last_heartbeat = row.last_heartbeat_at.isoformat() if row.last_heartbeat_at else None
    last_heartbeat_ts = row.last_heartbeat_at.timestamp() if row.last_heartbeat_at else 0.0
    return {
        "session_id": row.session_id,
        "user_id": row.user_id,
        "user_name": "",
        "email": "",
        "department": row.department,
        "group_name": row.group_name,
        "role": None,
        "is_admin": False,
        "device_id": row.device_id,
        "hostname": row.hostname,
        "platform": row.platform,
        "app_version": row.app_version,
        "local_ips": _deserialize_local_ips(row.local_ips),
        "proxy_host": row.proxy_host,
        "proxy_port": row.proxy_port,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "last_heartbeat": last_heartbeat,
        "last_heartbeat_ts": last_heartbeat_ts,
        "online": row.online,
        "disconnect_reason": row.disconnect_reason,
    }


def _find_existing_desktop_session(user: User, device_id: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    requested_session_id = str(session_id or "").strip()
    normalized_device_id = str(device_id or "").strip()
    if not normalized_device_id:
        return None

    session_for_device: Optional[Dict[str, Any]] = None
    for existing in desktop_sessions.values():
        if int(existing.get("user_id") or 0) != int(user.id):
            continue
        if requested_session_id and str(existing.get("session_id")) == requested_session_id:
            return existing
        if str(existing.get("device_id") or "").strip() == normalized_device_id:
            session_for_device = existing
    return session_for_device


def _touch_desktop_session(user: User, payload: DesktopSessionHeartbeat, client_host: Optional[str] = None) -> Tuple[Dict[str, Any], bool]:
    now_dt = datetime.utcnow()
    now_iso = now_dt.isoformat()
    now_ts = now_dt.timestamp()
    normalized_device_id = str(payload.device_id or "").strip() or f"user-{user.id}"
    normalized_app_version = str(payload.app_version or "").strip() or ""
    normalized_client_host = str(client_host or "").strip()
    normalized_hostname = str(payload.hostname or "").strip()
    if not normalized_hostname:
        if normalized_app_version.lower().startswith("web"):
            normalized_hostname = f"Web client ({normalized_client_host})" if normalized_client_host else "Web client"
        else:
            normalized_hostname = normalized_device_id
    normalized_platform = str(payload.platform or "").strip() or ""
    normalized_local_ips = _normalize_local_ip_list(payload.local_ips)
    if not normalized_local_ips and normalized_client_host:
        normalized_local_ips = [normalized_client_host]
    normalized_proxy_host = str(payload.proxy_host or "").strip() or None
    normalized_proxy_port = payload.proxy_port if payload.proxy_port and payload.proxy_port > 0 else None
    created = False
    assignment = _group_proxy_assignment_for_scope(user.department, user.group_name)
    previous_proxy_state: Optional[str] = None

    with desktop_session_lock:
        session = _find_existing_desktop_session(user, normalized_device_id, payload.session_id)
        if session:
            previous_proxy_state = _desktop_proxy_state_label(session, assignment)
        if not session:
            created = True
            session = {
                "session_id": str(uuid.uuid4()),
                "user_id": user.id,
                "user_name": _desktop_user_display_name(user),
                "email": user.email,
                "department": user.department,
                "group_name": user.group_name,
                "role": getattr(user, "role", None),
                "is_admin": bool(user.is_admin),
                "device_id": normalized_device_id,
                "hostname": normalized_hostname,
                "platform": normalized_platform,
                "app_version": normalized_app_version,
                "local_ips": normalized_local_ips,
                "proxy_host": normalized_proxy_host,
                "proxy_port": normalized_proxy_port,
                "started_at": now_iso,
                "last_heartbeat": now_iso,
                "last_heartbeat_ts": now_ts,
                "online": True,
                "disconnect_reason": None,
            }
            desktop_sessions[session["session_id"]] = session
        else:
            session["user_name"] = _desktop_user_display_name(user)
            session["email"] = user.email
            session["department"] = user.department
            session["group_name"] = user.group_name
            session["role"] = getattr(user, "role", None)
            session["is_admin"] = bool(user.is_admin)
            session["device_id"] = normalized_device_id
            session["hostname"] = normalized_hostname
            session["platform"] = normalized_platform or session.get("platform")
            session["app_version"] = normalized_app_version or session.get("app_version")
            session["local_ips"] = normalized_local_ips or session.get("local_ips") or []
            session["proxy_host"] = normalized_proxy_host or session.get("proxy_host")
            session["proxy_port"] = normalized_proxy_port or session.get("proxy_port")
            session["last_heartbeat"] = now_iso
            session["last_heartbeat_ts"] = now_ts
            session["online"] = True
            session["disconnect_reason"] = None

    current_proxy_state = _desktop_proxy_state_label(session, assignment)
    _persist_desktop_session_state(session)
    if created:
        _emit_desktop_presence_audit(session, True)
    elif (
        previous_proxy_state
        and previous_proxy_state != current_proxy_state
        and current_proxy_state != "browser-unavailable"
    ):
        _emit_system_audit_log(
            "Desktop Proxy State Changed",
            _desktop_proxy_status_details(session, previous_proxy_state, current_proxy_state, assignment),
        )
    return _desktop_session_payload(session), created


def _stop_desktop_session(user: User, payload: DesktopSessionStop) -> Optional[Dict[str, Any]]:
    normalized_session_id = str(payload.session_id or "").strip()
    normalized_device_id = str(payload.device_id or "").strip()
    reason = str(payload.reason or "").strip() or "manual-stop"
    now_iso = datetime.utcnow().isoformat()
    stopped_session: Optional[Dict[str, Any]] = None
    should_emit_offline = False

    with desktop_session_lock:
        for existing in desktop_sessions.values():
            if int(existing.get("user_id") or 0) != int(user.id):
                continue
            if normalized_session_id and str(existing.get("session_id")) != normalized_session_id:
                continue
            if normalized_device_id and str(existing.get("device_id") or "").strip() != normalized_device_id:
                continue
            if existing.get("online"):
                existing["online"] = False
                existing["disconnect_reason"] = reason
                existing["last_heartbeat"] = now_iso
                existing["last_heartbeat_ts"] = time.time()
                should_emit_offline = True
            stopped_session = dict(existing)
            break

    if stopped_session and should_emit_offline:
        _persist_desktop_session_state(stopped_session)
        _emit_desktop_presence_audit(stopped_session, False, reason=reason)
    elif stopped_session:
        _persist_desktop_session_state(stopped_session)
    return _desktop_session_payload(stopped_session) if stopped_session else None


def _collect_persisted_desktop_sessions_for_admin(current_user: User, db: Session, limit: int = 100) -> List[Dict[str, Any]]:
    query = db.query(DesktopSession).order_by(DesktopSession.last_heartbeat_at.desc())

    admin_department = str(current_user.department or "").strip()
    admin_group = str(current_user.group_name or "").strip()
    if admin_department and admin_group:
        query = query.filter(
            DesktopSession.department == admin_department,
            DesktopSession.group_name == admin_group,
        )

    rows = query.limit(limit).all()
    if not rows:
        return []

    user_ids = {row.user_id for row in rows}
    users = db.query(User).filter(User.id.in_(user_ids)).all() if user_ids else []
    user_map = {user.id: user for user in users}

    latest_by_scope_key: Dict[Tuple[int, str], Dict[str, Any]] = {}
    for row in rows:
        payload = _db_desktop_session_payload(row)
        linked_user = user_map.get(row.user_id)
        if linked_user:
            payload["user_name"] = _desktop_user_display_name(linked_user)
            payload["email"] = linked_user.email
            payload["role"] = linked_user.role
            payload["is_admin"] = bool(linked_user.is_admin)
        normalized = _desktop_session_payload(payload)
        assignment = _group_proxy_assignment_for_scope(normalized.get("department"), normalized.get("group_name"), db=db)
        if assignment:
            normalized["assigned_proxy_host"] = assignment.proxy_host
            normalized["assigned_proxy_port"] = assignment.proxy_port
        normalized["proxy_state"] = _desktop_proxy_state_label(normalized, assignment)
        if bool(normalized.get("is_admin")):
            continue

        scope_key = (
            int(normalized.get("user_id") or 0),
            str(normalized.get("device_id") or normalized.get("hostname") or normalized.get("session_id") or ""),
        )
        existing = latest_by_scope_key.get(scope_key)
        if existing is None:
            latest_by_scope_key[scope_key] = normalized
            continue

        existing_online = bool(existing.get("online"))
        candidate_online = bool(normalized.get("online"))
        if candidate_online and not existing_online:
            latest_by_scope_key[scope_key] = normalized
            continue
        if existing_online and not candidate_online:
            continue

        existing_ts = float(existing.get("last_heartbeat_ts") or 0.0)
        candidate_ts = float(normalized.get("last_heartbeat_ts") or 0.0)
        if candidate_ts >= existing_ts:
            latest_by_scope_key[scope_key] = normalized

    payloads = list(latest_by_scope_key.values())
    payloads.sort(
        key=lambda item: (
            not bool(item.get("online")),
            -float(item.get("last_heartbeat_ts") or 0.0),
            str(item.get("user_name") or ""),
        )
    )
    return payloads[:limit]


def _flush_gateway_audit_queue_sync() -> int:
    if not SECA_GATEWAY_AUDIT_ASYNC:
        return 0

    batch: List[Tuple[str, str]] = []
    with gateway_audit_queue_lock:
        while gateway_audit_queue and len(batch) < SECA_GATEWAY_AUDIT_BATCH_SIZE:
            batch.append(gateway_audit_queue.popleft())

    if not batch:
        return 0

    try:
        with Session(engine) as db:
            rows = [AuditLog(user_id=None, action=action, details=details) for action, details in batch]
            db.add_all(rows)
            db.commit()
        return len(batch)
    except Exception as exc:
        logger.warning("Failed to flush gateway audit batch: %s", exc)
        with gateway_audit_queue_lock:
            for item in reversed(batch):
                gateway_audit_queue.appendleft(item)
        return 0


async def flush_gateway_audit_loop() -> None:
    while True:
        await asyncio.sleep(SECA_GATEWAY_AUDIT_FLUSH_SECONDS)
        await asyncio.to_thread(_flush_gateway_audit_queue_sync)


async def monitor_desktop_sessions() -> None:
    while True:
        await asyncio.sleep(1.0)
        now_ts = time.time()
        timeout = float(SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS)
        retention = float(SECA_DESKTOP_SESSION_RETENTION_SECONDS)
        expired_sessions: List[Dict[str, Any]] = []

        with desktop_session_lock:
            stale_session_ids: List[str] = []
            for session_id, session in list(desktop_sessions.items()):
                last_heartbeat_ts = float(session.get("last_heartbeat_ts") or 0.0)
                if session.get("online") and last_heartbeat_ts > 0 and (now_ts - last_heartbeat_ts) > timeout:
                    session["online"] = False
                    session["disconnect_reason"] = "heartbeat-timeout"
                    expired_sessions.append(dict(session))

                if not session.get("online") and last_heartbeat_ts > 0 and (now_ts - last_heartbeat_ts) > retention:
                    stale_session_ids.append(session_id)

            for session_id in stale_session_ids:
                desktop_sessions.pop(session_id, None)

        for session in expired_sessions:
            await asyncio.to_thread(_persist_desktop_session_state, session)
            await asyncio.to_thread(_emit_desktop_presence_audit, session, False, "heartbeat-timeout")


async def monitor_gateway_presence() -> None:
    while True:
        await asyncio.sleep(1.0)
        now_ts = time.time()
        transitions: List[Tuple[str, str]] = []
        with gateway_state_lock:
            for ip in list(gateway_devices.keys()):
                is_online = _is_client_online_locked(ip, now_ts)
                previous = gateway_device_online_state.get(ip, False)
                if previous and not is_online:
                    gateway_device_online_state[ip] = False
                    transitions.append((ip, _get_or_create_device_alias(ip)))
                elif is_online and not previous:
                    gateway_device_online_state[ip] = True
        for ip, alias in transitions:
            await asyncio.to_thread(_record_gateway_presence_sync, ip, alias, False)



def _gateway_event_for_history(event: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.utcnow()
    method = (event.get("method") or "").upper()
    port = int(event.get("port") or 0)
    target = event.get("target")
    protocol = _gateway_protocol(method, target, port)
    client_ip = event.get("client_ip", "unknown")
    return {
        "time": now.strftime("%H:%M:%S"),
        "timestamp": now.isoformat(),
        "type": event.get("type", "proxy"),
        "client_ip": client_ip,
        "method": method,
        "protocol": protocol,
        "host": (event.get("host") or "").strip(),
        "port": port,
        "target": target,
        "blocked": bool(event.get("blocked", False)),
        "scan_url": event.get("scan_url"),
        "static_status": event.get("static_status"),
        "static_threat_score": event.get("static_threat_score"),
        "static_match_type": event.get("static_match_type"),
        "static_source": event.get("static_source"),
        "static_signals": list(event.get("static_signals") or []),
        "block_reason": event.get("block_reason"),
        "device": event.get("device") or "PC-CLIENT",
        "audit": event.get("audit") or "realtime",
        "company_mode": bool(event.get("company_mode", True)),
    }


def _gateway_audit_action(event: Dict[str, Any]) -> str:
    protocol = str(event.get("protocol") or "http").upper()
    method = str(event.get("method") or "?").upper()
    verdict = "Block" if bool(event.get("blocked", False)) else "Allow"
    return f"Gateway {protocol} {method} {verdict}"


def _gateway_audit_details(event: Dict[str, Any]) -> str:
    status = "BLOCKED" if event.get("blocked") else "ALLOWED"
    protocol = str(event.get("protocol") or "http").upper()
    method = (event.get("method") or "?").upper()
    host = event.get("host") or "unknown-host"
    client_ip = event.get("client_ip") or "unknown"
    device_name = event.get("device_name") or "unknown-device"
    port = event.get("port") or 0
    target = event.get("target")
    parts = [f"{status} {protocol} {method} {host}:{port}", f"client={client_ip}", f"device={device_name}"]
    if target:
        parts.append(f"target={target}")
    if event.get("scan_url"):
        parts.append(f"scan_url={event.get('scan_url')}")
    if event.get("static_status"):
        parts.append(f"url_static={event.get('static_status')}")
    if event.get("static_threat_score") is not None:
        parts.append(f"score={event.get('static_threat_score')}")
    if event.get("static_match_type") and event.get("static_match_type") != "none":
        parts.append(f"match={event.get('static_match_type')}")
    if event.get("static_source"):
        parts.append(f"source={event.get('static_source')}")
    signals = list(event.get("static_signals") or [])
    if signals:
        parts.append(f"signals={'; '.join(signals[:4])}")
    if event.get("block_reason"):
        parts.append(f"block_reason={event.get('block_reason')}")
    if event.get("user_email"):
        parts.append(f"user={event.get('user_email')}")
    if event.get("department") and event.get("group_name"):
        parts.append(f"scope={event.get('department')}/{event.get('group_name')}")
    return " | ".join(parts)


def _enrich_gateway_event_with_desktop_session(normalized: Dict[str, Any]) -> Dict[str, Any]:
    client_ip = normalized.get("client_ip") or ""
    if not client_ip:
        return normalized

    session = _active_desktop_session_for_client_ip(client_ip)
    if not session:
        return normalized

    normalized["desktop_session_id"] = session.get("session_id")
    normalized["user_id"] = session.get("user_id")
    normalized["user_name"] = session.get("user_name")
    normalized["user_email"] = session.get("email")
    normalized["department"] = session.get("department")
    normalized["group_name"] = session.get("group_name")
    normalized["device_id"] = session.get("device_id")
    normalized["hostname"] = session.get("hostname")
    normalized["local_ips"] = list(session.get("local_ips") or [])

    assignment = _group_proxy_assignment_for_scope(session.get("department"), session.get("group_name"))
    if assignment:
        normalized["assigned_proxy_host"] = assignment.proxy_host
        normalized["assigned_proxy_port"] = assignment.proxy_port

    return normalized


def _update_gateway_runtime_state(normalized: Dict[str, Any]) -> Dict[str, Any]:
    global gateway_blocked_count, gateway_allowed_count
    client_ip = normalized.get("client_ip") or "unknown"
    method = (normalized.get("method") or "UNKNOWN").upper()
    host = normalized.get("host") or ""
    blocked = bool(normalized.get("blocked", False))
    now_dt = datetime.utcnow()
    now = now_dt.isoformat()
    now_ts = now_dt.timestamp()

    normalized = _enrich_gateway_event_with_desktop_session(normalized)

    with gateway_state_lock:
        gateway_client_last_activity[client_ip] = now_ts
        device_name = _get_or_create_device_alias(client_ip)
        normalized["device_name"] = device_name
        was_online = gateway_device_online_state.get(client_ip, False)
        gateway_device_online_state[client_ip] = True
        normalized["presence_online_transition"] = not was_online
        gateway_history.appendleft(normalized)
        gateway_clients[client_ip] = gateway_clients.get(client_ip, 0) + 1

        if blocked:
            gateway_blocked_count += 1
        else:
            gateway_allowed_count += 1

        gateway_method_counts[method] = gateway_method_counts.get(method, 0) + 1

        device = gateway_devices.get(client_ip)
        if not device:
            device = {
                "device_name": device_name,
                "client_ip": client_ip,
                "first_seen": now,
                "last_seen": now,
                "total_requests": 0,
                "blocked_requests": 0,
                "allowed_requests": 0,
                "methods": {},
                "last_host": "",
            }
            gateway_devices[client_ip] = device

        device["last_seen"] = now
        device["last_host"] = host or device.get("last_host") or ""
        device["total_requests"] = int(device.get("total_requests", 0)) + 1
        if blocked:
            device["blocked_requests"] = int(device.get("blocked_requests", 0)) + 1
        else:
            device["allowed_requests"] = int(device.get("allowed_requests", 0)) + 1

        methods = dict(device.get("methods", {}))
        methods[method] = int(methods.get(method, 0)) + 1
        device["methods"] = methods

    return normalized


def _record_gateway_event_sync(event: Dict[str, Any], db: Optional[Session] = None) -> Dict[str, Any]:
    normalized = _gateway_event_for_history(event)
    normalized = _update_gateway_runtime_state(normalized)

    action = _gateway_audit_action(normalized)
    if normalized.get("presence_online_transition"):
        _record_gateway_presence_sync(
            normalized.get("client_ip", "unknown"),
            normalized.get("device_name", "unknown-device"),
            True,
            db=db,
        )
    _emit_system_audit_log(action, _gateway_audit_details(normalized), db=db)
    return normalized


def _record_gateway_event_with_sync_audit(event: Dict[str, Any]) -> Dict[str, Any]:
    with Session(engine) as db:
        return _record_gateway_event_sync(event, db=db)


def _load_proxy_blocklist_sync() -> List[str]:
    with Session(engine) as db:
        return _effective_blocklist(db)


async def _proxy_get_blocklist() -> List[str]:
    global proxy_blocklist_last_fetch, proxy_blocklist_cache
    now = time.time()
    if now - proxy_blocklist_last_fetch < SECA_PROXY_BLOCKLIST_REFRESH_SECONDS:
        return proxy_blocklist_cache
    try:
        proxy_blocklist_cache = await asyncio.to_thread(_load_proxy_blocklist_sync)
        proxy_blocklist_last_fetch = now
    except Exception as exc:
        logger.warning("Failed to refresh proxy blocklist: %s", exc)
    return proxy_blocklist_cache


async def _proxy_is_blocked(host: str) -> bool:
    host = (host or "").lower().strip().strip(".")
    if not host:
        return False
    patterns = await _proxy_get_blocklist()
    for pat in patterns:
        for variant in _proxy_pattern_variants(pat):
            if fnmatch.fnmatch(host, variant) or fnmatch.fnmatch(host, variant.lstrip("*.")):
                return True
            legacy = variant.lstrip("*.").replace("*", "").strip()
            if legacy and "." not in legacy and legacy in host:
                return True
    return False


def _proxy_matching_block_rule_from_patterns(host: str, patterns: List[str]) -> Optional[str]:
    normalized_host = (host or "").lower().strip().strip(".")
    if not normalized_host:
        return None
    for pattern in patterns:
        for variant in _proxy_pattern_variants(pattern):
            if fnmatch.fnmatch(normalized_host, variant) or fnmatch.fnmatch(normalized_host, variant.lstrip("*.")):
                return pattern
            legacy = variant.lstrip("*.").replace("*", "").strip()
            if legacy and "." not in legacy and legacy in normalized_host:
                return pattern
    return None


async def _proxy_matching_block_rule(host: str) -> Optional[str]:
    normalized_host = (host or "").lower().strip().strip(".")
    if not normalized_host:
        return None
    patterns = await _proxy_get_blocklist()
    return _proxy_matching_block_rule_from_patterns(normalized_host, patterns)


def _proxy_tls_intercept_ready() -> bool:
    if not SECA_PROXY_TLS_INTERCEPT:
        return False
    if not SECA_PROXY_TLS_CA_CERT_PATH or not SECA_PROXY_TLS_CA_KEY_PATH:
        return False
    return os.path.exists(SECA_PROXY_TLS_CA_CERT_PATH) and os.path.exists(SECA_PROXY_TLS_CA_KEY_PATH)


def _build_proxy_scan_url(method: str, host: str, port: int, target: Optional[str]) -> str:
    method_u = (method or "").upper()
    normalized_host = (host or "").strip().strip("[]")
    if not normalized_host:
        return ""

    if method_u == "CONNECT":
        scheme = "https"
        path = "/"
        include_port = port not in {0, 443}
    else:
        scheme = "http"
        path = target or "/"
        parsed = None
        if path.lower().startswith(("http://", "https://")):
            try:
                parsed = urlsplit(path)
            except ValueError:
                parsed = None
        if parsed and parsed.hostname:
            scheme = parsed.scheme.lower() or "http"
            normalized_host = parsed.hostname
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        elif not path.startswith("/"):
            path = f"/{path}"
        include_port = port not in {0, 80} if scheme == "http" else port not in {0, 443}

    host_part = f"{normalized_host}:{port}" if include_port else normalized_host
    return f"{scheme}://{host_part}{path}"


def _summarize_proxy_static_signals(static_eval: Dict[str, Any]) -> List[str]:
    details = static_eval.get("details", {})
    layers = details.get("layers", {})
    layer1 = layers.get("layer1_format", {}) or {}
    layer2 = layers.get("layer2_phishtank", {}) or {}
    layer3 = layers.get("layer3_reputation", {}) or {}
    layer4 = layers.get("layer4_content", {}) or {}

    signals: List[str] = []
    signals.extend(list(layer1.get("issues") or [])[:2])
    if layer2.get("found"):
        message = str(layer2.get("message") or "").strip()
        if message:
            signals.append(message)
    signals.extend(list(layer3.get("issues") or [])[:2])
    signals.extend(list(layer4.get("indicators") or [])[:2])

    deduped: List[str] = []
    seen = set()
    for signal in signals:
        normalized = str(signal).strip()
        if not normalized or normalized in seen:
            continue
        deduped.append(normalized)
        seen.add(normalized)
    return deduped[:6]


def _should_block_proxy_static_eval(static_eval: Dict[str, Any]) -> bool:
    status = str(static_eval.get("status") or "clean").strip().lower()
    if status != "malicious":
        return False

    threat_score = int(static_eval.get("threat_score") or 0)
    layers = (((static_eval.get("details") or {}).get("layers")) or {})
    layer2 = layers.get("layer2_phishtank", {}) or {}
    layer3 = layers.get("layer3_reputation", {}) or {}
    layer4 = layers.get("layer4_content", {}) or {}

    match_type = str(layer2.get("match_type") or "none").strip().lower()
    source = str(layer2.get("source") or "").strip().lower()
    found = bool(layer2.get("found"))

    # Exact URL hits are strong enough to block immediately.
    if found and match_type == "exact_url":
        return True

    # Explicit domain-only rules from the curated local feed are also allowed
    # to block, but imported feed domain matches are too noisy for hard blocking.
    if found and match_type == "domain_only" and source == "local-url-feed":
        return True

    # Domain-only matches from broad imported feeds should inform the score, but
    # should not hard-block browsing on their own.
    if match_type == "domain_only":
        return False

    brand_impersonation = bool(layer3.get("brand_impersonation"))
    path_brand_abuse = bool(layer3.get("path_brand_abuse"))
    layer4_score = int(layer4.get("threat_score") or 0)

    # Keep proxy blocking for clearly dangerous heuristic outcomes, but require
    # a stronger signal than the general scanner uses.
    if threat_score >= 85:
        return True
    if threat_score >= 70 and (brand_impersonation or path_brand_abuse or layer4_score >= 35):
        return True
    return False


def _proxy_static_scan_event_sync(
    *,
    client_ip: str,
    method: str,
    host: str,
    port: int,
    target: Optional[str],
    scan_url: str,
    block_rule: Optional[str],
) -> Dict[str, Any]:
    static_status = "clean"
    static_threat_score = 0
    static_match_type = "none"
    static_source: Optional[str] = None
    static_signals: List[str] = []
    static_enforced_block = False
    block_reason = "policy_rule" if block_rule else None

    if scan_url:
        try:
            with Session(engine) as db:
                static_eval = _evaluate_url_static(scan_url, db)
            static_status = str(static_eval.get("status") or "clean")
            static_threat_score = int(static_eval.get("threat_score") or 0)
            layer2 = (((static_eval.get("details") or {}).get("layers") or {}).get("layer2_phishtank") or {})
            static_match_type = str(layer2.get("match_type") or "none")
            static_source = layer2.get("source") or layer2.get("phish_id")
            static_signals = _summarize_proxy_static_signals(static_eval)
            static_enforced_block = _should_block_proxy_static_eval(static_eval)
            if static_enforced_block:
                block_reason = "static_malicious" if not block_rule else f"policy_rule+static_malicious"
        except Exception as exc:
            logger.warning("Proxy URL static scan failed for %s: %s", scan_url, exc)
            static_status = "error"
            static_signals = [f"Static scan error: {str(exc)[:140]}"]
            static_enforced_block = False
            if not block_reason:
                block_reason = None

    blocked = bool(block_rule) or static_enforced_block
    if block_rule and not static_enforced_block:
        static_signals = [f"Matched proxy rule {block_rule}", *static_signals][:6]

    return {
        "type": "proxy",
        "client_ip": client_ip,
        "method": method,
        "host": host,
        "port": port,
        "target": target,
        "blocked": blocked,
        "scan_url": scan_url,
        "static_status": static_status,
        "static_threat_score": static_threat_score,
        "static_match_type": static_match_type,
        "static_source": static_source,
        "static_signals": static_signals,
        "block_reason": block_reason,
    }


async def _proxy_tunnel(c_reader, c_writer, u_reader, u_writer, client_ip: str):
    async def pump(src, dst, peer_to_close=None):
        last_touch = 0.0
        try:
            while True:
                data = await src.read(SECA_PROXY_TUNNEL_CHUNK_BYTES)
                if not data:
                    break
                now_mono = time.monotonic()
                if now_mono - last_touch >= SECA_PROXY_ACTIVITY_TOUCH_SECONDS:
                    _mark_proxy_client_activity(client_ip, update_last_seen=False)
                    last_touch = now_mono
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass
            if peer_to_close is not None:
                try:
                    peer_to_close.close()
                except Exception:
                    pass

    t1 = asyncio.create_task(pump(c_reader, u_writer, c_writer))
    t2 = asyncio.create_task(pump(u_reader, c_writer, u_writer))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)


async def _proxy_handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    _register_proxy_client_writer(writer)
    _mark_proxy_client_connected(client_ip)

    try:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except Exception:
            return

        try:
            lines = head.split(b"\r\n")
            first = lines[0].decode("utf-8", "ignore")
            method, target, version = first.split(" ", 2)
        except Exception:
            return

        method_u = method.upper()

        if method_u == "CONNECT":
            connect_target = target.strip()
            host = connect_target
            port = 443
            if connect_target.startswith("[") and "]" in connect_target:
                end = connect_target.find("]")
                host = connect_target[1:end]
                tail = connect_target[end + 1:]
                if tail.startswith(":"):
                    try:
                        port = int(tail[1:])
                    except ValueError:
                        port = 443
            elif ":" in connect_target:
                h, p = connect_target.rsplit(":", 1)
                host = h
                try:
                    port = int(p)
                except ValueError:
                    port = 443
            host = host.strip().strip("[]")

            block_rule = await _proxy_matching_block_rule(host)
            scan_url = _build_proxy_scan_url("CONNECT", host, port, None)
            gateway_event = await asyncio.to_thread(
                _proxy_static_scan_event_sync,
                client_ip=client_ip,
                method="CONNECT",
                host=host,
                port=port,
                target=connect_target,
                scan_url=scan_url,
                block_rule=block_rule,
            )
            if SECA_PROXY_STATIC_SCAN_DELAY_MS > 0:
                await asyncio.sleep(SECA_PROXY_STATIC_SCAN_DELAY_MS / 1000.0)
            blocked = bool(gateway_event.get("blocked"))
            if SECA_PROXY_STATIC_AUDIT_SYNC:
                await asyncio.to_thread(_record_gateway_event_with_sync_audit, gateway_event)
            else:
                asyncio.create_task(asyncio.to_thread(_record_gateway_event_sync, gateway_event))

            if blocked:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            try:
                u_reader, u_writer = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await _proxy_tunnel(reader, writer, u_reader, u_writer, client_ip)
            return

        header_pairs: List[Tuple[str, str]] = []
        host_header = ""
        for ln in lines[1:]:
            if not ln:
                continue
            decoded = ln.decode("utf-8", "ignore")
            if ":" not in decoded:
                continue
            k, v = decoded.split(":", 1)
            key = k.strip()
            value = v.strip()
            key_lower = key.lower()
            if key_lower == "host":
                host_header = value
            if key_lower in {"proxy-connection", "proxy-authenticate", "proxy-authorization"}:
                continue
            header_pairs.append((key, value))

        target_s = target.strip()
        upstream_host = ""
        upstream_port = 80
        upstream_target = target_s if target_s else "/"
        parsed_target = None

        if target_s.lower().startswith(("http://", "https://")):
            try:
                parsed_target = urlsplit(target_s)
            except ValueError:
                parsed_target = None

        if parsed_target and parsed_target.scheme.lower() == "https":
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        if parsed_target and parsed_target.hostname:
            upstream_host = parsed_target.hostname
            upstream_port = parsed_target.port or 80
            path = parsed_target.path or "/"
            if parsed_target.query:
                path = f"{path}?{parsed_target.query}"
            upstream_target = path

        if host_header:
            host_only = host_header
            host_port = None
            if host_header.startswith("[") and "]" in host_header:
                end = host_header.find("]")
                host_only = host_header[1:end]
                tail = host_header[end + 1:]
                if tail.startswith(":"):
                    host_port = tail[1:]
            elif ":" in host_header:
                host_only, host_port = host_header.rsplit(":", 1)
            upstream_host = host_only.strip().strip("[]") or upstream_host
            if host_port:
                try:
                    upstream_port = int(host_port)
                except ValueError:
                    pass

        if not upstream_host:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        block_rule = await _proxy_matching_block_rule(upstream_host)
        scan_url = _build_proxy_scan_url(method_u, upstream_host, upstream_port, target_s or upstream_target)
        gateway_event = await asyncio.to_thread(
            _proxy_static_scan_event_sync,
            client_ip=client_ip,
            method=method_u,
            host=upstream_host,
            port=upstream_port,
            target=target,
            scan_url=scan_url,
            block_rule=block_rule,
        )
        if SECA_PROXY_STATIC_SCAN_DELAY_MS > 0:
            await asyncio.sleep(SECA_PROXY_STATIC_SCAN_DELAY_MS / 1000.0)
        blocked = bool(gateway_event.get("blocked"))
        if SECA_PROXY_STATIC_AUDIT_SYNC:
            await asyncio.to_thread(_record_gateway_event_with_sync_audit, gateway_event)
        else:
            asyncio.create_task(asyncio.to_thread(_record_gateway_event_sync, gateway_event))

        if blocked:
            body = b"Blocked by SECA gateway proxy\r\n"
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Content-Type: text/plain\r\n\r\n"
                + body
            )
            await writer.drain()
            return

        if not any(k.lower() == "host" for k, _ in header_pairs):
            header_pairs.append(("Host", upstream_host if upstream_port == 80 else f"{upstream_host}:{upstream_port}"))

        request_line = f"{method_u} {upstream_target or '/'} {version}\r\n"
        forward_headers = "".join(f"{k}: {v}\r\n" for k, v in header_pairs)
        forward_head = f"{request_line}{forward_headers}\r\n".encode("utf-8", "ignore")

        try:
            u_reader, u_writer = await asyncio.open_connection(upstream_host, upstream_port)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        u_writer.write(forward_head)
        await u_writer.drain()
        await _proxy_tunnel(reader, writer, u_reader, u_writer, client_ip)
    finally:
        _unregister_proxy_client_writer(writer)
        _mark_proxy_client_disconnected(client_ip)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_embedded_proxy() -> None:
    global proxy_server
    if proxy_server is not None:
        existing_sockets = proxy_server.sockets or []
        if existing_sockets:
            return
        proxy_server = None
    try:
        proxy_server = await asyncio.start_server(
            _proxy_handle_client,
            SECA_PROXY_LISTEN_HOST,
            SECA_PROXY_LISTEN_PORT,
        )
        sockets = proxy_server.sockets or []
        addrs = ", ".join(str(sock.getsockname()) for sock in sockets)
        logger.info("Embedded proxy listening on %s", addrs)
    except OSError as exc:
        logger.error(
            "Embedded proxy failed to start on %s:%s (%s)",
            SECA_PROXY_LISTEN_HOST,
            SECA_PROXY_LISTEN_PORT,
            exc,
        )
        proxy_server = None
        return

    try:
        async with proxy_server:
            await proxy_server.serve_forever()
    finally:
        proxy_server = None


def seed_default_proxy_rules() -> None:
    try:
        with Session(engine) as db:
            for pattern, note in DEFAULT_PROXY_BLOCK_RULES:
                exists = db.query(ProxyBlockRule).filter(ProxyBlockRule.pattern == pattern).first()
                if exists:
                    continue
                db.add(ProxyBlockRule(pattern=pattern, note=note, enabled=True))
            db.commit()
    except Exception as exc:
        logger.warning("Failed to seed default proxy block rules: %s", exc)


def disable_legacy_default_proxy_rules() -> None:
    try:
        with Session(engine) as db:
            rows = (
                db.query(ProxyBlockRule)
                .filter(ProxyBlockRule.note == "Starter default rule", ProxyBlockRule.enabled.is_(True))
                .all()
            )
            if not rows:
                return
            for row in rows:
                row.enabled = False
            db.commit()
    except Exception as exc:
        logger.warning("Failed to disable legacy default proxy block rules: %s", exc)


@app.on_event("startup")
async def on_startup():
    seed_default_proxy_rules()
    disable_legacy_default_proxy_rules()
    seed_group_proxy_assignments()
    mark_persisted_desktop_sessions_offline_on_startup()
    if SECA_PROXY_TLS_INTERCEPT and not _proxy_tls_intercept_ready():
        logger.warning(
            "SECA_PROXY_TLS_INTERCEPT is enabled but CA files are missing or unreadable. "
            "HTTPS inspection remains domain-only until the interception pipeline is completed."
        )
    elif SECA_PROXY_TLS_INTERCEPT:
        logger.info("TLS interception readiness assets detected. CONNECT flow is still domain-only until MITM path is completed.")
    app.state.proxy_presence_task = asyncio.create_task(monitor_gateway_presence())
    app.state.proxy_audit_flush_task = asyncio.create_task(flush_gateway_audit_loop())
    app.state.desktop_session_monitor_task = asyncio.create_task(monitor_desktop_sessions())
    if SECA_PROXY_AUTOSTART:
        app.state.proxy_task = asyncio.create_task(start_embedded_proxy())


@app.on_event("shutdown")
async def on_shutdown():
    task = getattr(app.state, "proxy_task", None)
    presence_task = getattr(app.state, "proxy_presence_task", None)
    flush_task = getattr(app.state, "proxy_audit_flush_task", None)
    desktop_session_task = getattr(app.state, "desktop_session_monitor_task", None)
    if proxy_server is not None:
        proxy_server.close()
        await proxy_server.wait_closed()
    if task and not task.done():
        task.cancel()
    if presence_task and not presence_task.done():
        presence_task.cancel()
    if flush_task and not flush_task.done():
        flush_task.cancel()
    if desktop_session_task and not desktop_session_task.done():
        desktop_session_task.cancel()
    await asyncio.to_thread(_flush_gateway_audit_queue_sync)

@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_origin_regex=r"^https?://((localhost|127\.0\.0\.1)|(\d{1,3}\.){3}\d{1,3})(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include auth router
app.include_router(auth_router, tags=["auth"])


def create_audit_log(db: Session, user_id: int, action: str, details: str):
    audit_log = AuditLog(user_id=user_id, action=action, details=details)
    db.add(audit_log)
    db.commit()


def create_system_audit_log(db: Session, action: str, details: str):
    audit_log = AuditLog(user_id=None, action=action, details=details)
    db.add(audit_log)
    db.commit()


EMAIL_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
EMAIL_URGENCY_PATTERNS = [
    "urgent",
    "immediately",
    "verify your account",
    "confirm your identity",
    "payment failed",
    "invoice attached",
    "reset your password",
    "your mailbox",
    "click here",
    "limited time",
    "suspended",
    "security alert",
]
EMAIL_CREDENTIAL_PATTERNS = [
    "password",
    "login",
    "signin",
    "sign in",
    "2fa",
    "mfa",
    "one-time code",
    "otp",
    "bank account",
    "wallet",
    "gift card",
]
EMAIL_BRAND_KEYWORDS = [
    "microsoft",
    "google",
    "paypal",
    "bank",
    "amazon",
    "apple",
    "linkedin",
    "facebook",
    "instagram",
    "github",
]
DOMAIN_ONLY_REPUTATION_HOSTS = {
    "drive.google.com",
    "docs.google.com",
    "mail.google.com",
    "accounts.google.com",
    "ssl.gstatic.com",
    "dropbox.com",
    "www.dropbox.com",
    "onedrive.live.com",
    "1drv.ms",
    "wetransfer.com",
    "www.wetransfer.com",
    "mega.nz",
    "discord.com",
    "cdn.discordapp.com",
}
TRUSTED_ROOT_DOMAINS = {
    "youtube.com",
    "google.com",
    "facebook.com",
    "instagram.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "reddit.com",
    "tiktok.com",
    "discord.com",
    "dropbox.com",
    "openai.com",
    "chatgpt.com",
    "whatsapp.com",
    "x.com",
    "twitter.com",
    "netflix.com",
    "spotify.com",
    "telegram.org",
}
TRUSTED_BRAND_TOKENS = {
    "youtube": {"youtube.com", "youtu.be"},
    "google": {"google.com", "googleapis.com", "gstatic.com"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "github": {"github.com", "githubusercontent.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "linkedin": {"linkedin.com"},
    "paypal": {"paypal.com"},
    "discord": {"discord.com", "discord.gg"},
    "openai": {"openai.com", "chatgpt.com"},
}
TRUSTED_BRAND_PATH_TOKENS = tuple(TRUSTED_BRAND_TOKENS.keys())
MULTI_LABEL_PUBLIC_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "com.br",
    "com.tr",
    "co.in",
    "com.mx",
    "com.cn",
}


def _hostname_matches_root(hostname: str, root: str) -> bool:
    host = (hostname or "").strip().lower()
    normalized_root = (root or "").strip().lower()
    return bool(host) and (host == normalized_root or host.endswith(f".{normalized_root}"))


def _is_trusted_root_domain(hostname: str) -> bool:
    return any(_hostname_matches_root(hostname, root) for root in TRUSTED_ROOT_DOMAINS)


def _brand_impersonation_tokens(hostname: str) -> List[str]:
    host = (hostname or "").strip().lower()
    if not host:
        return []

    found: List[str] = []
    for token, allowed_roots in TRUSTED_BRAND_TOKENS.items():
        if token not in host:
            continue
        if any(_hostname_matches_root(host, allowed_root) for allowed_root in allowed_roots):
            continue
        found.append(token)
    return found


def _guess_registered_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().strip(".")
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host

    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:])
    if tail2 in MULTI_LABEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return tail3
    if ".".join(parts[-2:]) in {"co", "com", "net", "org"} and len(parts) >= 3:
        return tail3
    return tail2


def _clean_email_text(text: str) -> str:
    cleaned = unescape(text or "")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _normalize_email_label(label: str) -> str:
    normalized = unicodedata.normalize("NFKD", label or "")
    normalized = normalized.encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized.lower()).strip()
    return normalized


def _parse_pasted_email_summary(raw_text: str) -> Dict[str, Any]:
    field_map = {
        "de": "from",
        "from": "from",
        "a": "to",
        "to": "to",
        "date": "date",
        "objet": "subject",
        "subject": "subject",
        "reply to": "reply_to",
        "repondre a": "reply_to",
        "envoye par": "mailed_by",
        "envoy par": "mailed_by",
        "signed by": "signed_by",
        "signe par": "signed_by",
        "sign par": "signed_by",
        "securite": "security",
        "securit": "security",
        "security": "security",
    }
    parsed: Dict[str, str] = {}
    body_lines: List[str] = []

    for line in (raw_text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(r"^\s*([^:]+):\s*(.+?)\s*$", line)
        if not match:
            body_lines.append(stripped)
            continue

        normalized_label = _normalize_email_label(match.group(1))
        field_key = field_map.get(normalized_label)
        if not field_key:
            body_lines.append(stripped)
            continue
        parsed[field_key] = match.group(2).strip()

    from_name, from_address = ("", "")
    to_name, to_address = ("", "")
    reply_to_name, reply_to_address = ("", "")

    if parsed.get("from"):
        entries = getaddresses([parsed["from"]])
        if entries:
            from_name, from_address = entries[0]
    if parsed.get("to"):
        entries = getaddresses([parsed["to"]])
        if entries:
            to_name, to_address = entries[0]
    if parsed.get("reply_to"):
        entries = getaddresses([parsed["reply_to"]])
        if entries:
            reply_to_name, reply_to_address = entries[0]

    return {
        "subject": parsed.get("subject", "").strip(),
        "from_name": from_name,
        "from_address": from_address,
        "to_name": to_name,
        "to_address": to_address,
        "reply_to_name": reply_to_name,
        "reply_to_address": reply_to_address,
        "date": parsed.get("date", "").strip(),
        "mailed_by": parsed.get("mailed_by", "").strip(),
        "signed_by": parsed.get("signed_by", "").strip(),
        "security": parsed.get("security", "").strip(),
        "body_text": "\n".join(body_lines).strip(),
        "recognized_fields": len(parsed),
    }


def _strip_html_tags(html_text: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html_text or "")
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return _clean_email_text(text)


def _extract_urls_from_text(text: str) -> List[str]:
    values = []
    for match in EMAIL_URL_RE.findall(text or ""):
        candidate = match.rstrip(".,);]>\"'")
        if candidate:
            values.append(candidate)
    # preserve order
    deduped: List[str] = []
    seen = set()
    for value in values:
        if value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped


def _extract_html_link_indicators(html_text: str) -> List[Dict[str, str]]:
    indicators: List[Dict[str, str]] = []
    pattern = re.compile(r'(?is)<a\b[^>]*href=["\']?([^"\' >]+)[^>]*>(.*?)</a>')
    for href, anchor_raw in pattern.findall(html_text or ""):
        anchor_text = _strip_html_tags(anchor_raw)
        href_clean = (href or "").strip()
        if not href_clean:
            continue
        indicators.append({
            "href": href_clean,
            "text": anchor_text,
            "mismatch": bool(anchor_text and anchor_text.startswith(("http://", "https://", "www.")) and anchor_text not in href_clean),
        })
    return indicators


def _parse_auth_signal_from_headers(message: Any) -> Dict[str, str]:
    auth_blob = " ".join(message.get_all("Authentication-Results", []) or [])
    spf_blob = " ".join(message.get_all("Received-SPF", []) or [])
    combined = f"{auth_blob} {spf_blob}".lower()

    def pick(label: str) -> str:
        patterns = [
            rf"{label}\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none)",
            rf"{label}\s+(pass|fail|softfail|neutral|temperror|permerror|none)",
        ]
        for pattern in patterns:
            match = re.search(pattern, combined)
            if match:
                return match.group(1)
        return "unknown"

    return {
        "spf": pick("spf"),
        "dkim": pick("dkim"),
        "dmarc": pick("dmarc"),
    }


def _email_domain(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" not in address:
        return ""
    return address.split("@", 1)[1]


def _score_email_heuristics(
    subject: str,
    combined_text: str,
    auth_results: Dict[str, str],
    from_name: str,
    from_domain: str,
    reply_to_domain: str,
    html_links: List[Dict[str, str]],
    url_results: List[Dict[str, Any]],
    attachment_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    indicators: List[str] = []
    score = 0
    lowered_subject = (subject or "").lower()
    lowered_text = (combined_text or "").lower()

    urgency_hits = [item for item in EMAIL_URGENCY_PATTERNS if item in lowered_subject or item in lowered_text]
    if urgency_hits:
        indicators.append(f"Urgency language detected ({', '.join(urgency_hits[:3])})")
        score += min(18, 6 * len(urgency_hits))

    credential_hits = [item for item in EMAIL_CREDENTIAL_PATTERNS if item in lowered_text]
    if credential_hits:
        indicators.append(f"Credential/payment lure language detected ({', '.join(credential_hits[:3])})")
        score += min(20, 5 * len(credential_hits))

    if auth_results.get("dmarc") == "fail":
        indicators.append("DMARC failed")
        score += 25
    if auth_results.get("spf") in {"fail", "softfail"}:
        indicators.append(f"SPF {auth_results.get('spf')}")
        score += 15
    if auth_results.get("dkim") == "fail":
        indicators.append("DKIM failed")
        score += 15

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        indicators.append("Reply-To domain does not match sender domain")
        score += 18

    brand_hits = [brand for brand in EMAIL_BRAND_KEYWORDS if brand in (from_name or "").lower()]
    if brand_hits and from_domain and not any(brand in from_domain for brand in brand_hits):
        indicators.append("Display name suggests brand impersonation")
        score += 16

    mismatch_count = sum(1 for item in html_links if item.get("mismatch"))
    if mismatch_count:
        indicators.append(f"{mismatch_count} HTML link text mismatch indicator(s)")
        score += min(18, mismatch_count * 6)

    malicious_urls = sum(1 for item in url_results if item.get("status") == "malicious")
    suspicious_urls = sum(1 for item in url_results if item.get("status") == "suspicious")
    if malicious_urls:
        indicators.append(f"{malicious_urls} extracted URL(s) classified as malicious")
        score += min(35, malicious_urls * 18)
    if suspicious_urls:
        indicators.append(f"{suspicious_urls} extracted URL(s) classified as suspicious")
        score += min(20, suspicious_urls * 8)

    bad_attachments = sum(1 for item in attachment_results if item.get("status") == "malicious")
    suspicious_attachments = sum(1 for item in attachment_results if item.get("status") == "suspicious")
    if bad_attachments:
        indicators.append(f"{bad_attachments} attachment(s) classified as malicious")
        score += min(35, bad_attachments * 18)
    if suspicious_attachments:
        indicators.append(f"{suspicious_attachments} attachment(s) classified as suspicious")
        score += min(20, suspicious_attachments * 8)

    if len(url_results) >= 6:
        indicators.append("Email contains unusually high number of links")
        score += 8

    return {
        "score": min(100, score),
        "indicators": indicators,
        "urgency_hits": urgency_hits[:5],
        "credential_hits": credential_hits[:5],
    }


def _analyze_email_payload(
    *,
    email_bytes: Optional[bytes],
    raw_email: Optional[str],
    db: Session,
    source_name: str,
) -> Dict[str, Any]:
    parsed_message = None
    parse_source = "raw_text" if raw_email else "eml_file"
    pasted_summary = _parse_pasted_email_summary(raw_email or "") if raw_email else None

    if email_bytes:
        parsed_message = BytesParser(policy=policy.default).parsebytes(email_bytes)
    elif raw_email:
        parsed_message = Parser(policy=policy.default).parsestr(raw_email)
    else:
        raise ValueError("Either email_bytes or raw_email must be provided.")

    headers = {key: str(value) for key, value in parsed_message.items()}
    subject = str(parsed_message.get("Subject") or "").strip() or "(No subject)"
    from_entries = getaddresses(parsed_message.get_all("From", []))
    reply_to_entries = getaddresses(parsed_message.get_all("Reply-To", []))
    return_path_entries = getaddresses(parsed_message.get_all("Return-Path", []))

    from_name, from_address = from_entries[0] if from_entries else ("", "")
    reply_to_name, reply_to_address = reply_to_entries[0] if reply_to_entries else ("", "")
    _, return_path_address = return_path_entries[0] if return_path_entries else ("", "")

    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if parsed_message.is_multipart():
        for part in parsed_message.walk():
            if part.is_multipart():
                continue
            content_disposition = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            content_type = part.get_content_type()

            if content_disposition == "attachment" or filename:
                if len(attachments) >= 5:
                    continue
                attachment_name = filename or f"attachment_{len(attachments) + 1}"
                static_result = _build_file_scan_result(
                    filename=attachment_name,
                    content_type=content_type,
                    file_bytes=payload,
                    db=db,
                )
                attachments.append({
                    "filename": attachment_name,
                    "content_type": content_type,
                    "size": len(payload),
                    "status": static_result["status"],
                    "threat_score": static_result["threat_score"],
                    "risk_category": static_result["details"].get("layers", {}).get("layer1_info", {}).get("riskCategory", "unknown"),
                })
                continue

            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")

            if content_type == "text/plain":
                plain_parts.append(decoded)
            elif content_type == "text/html":
                html_parts.append(decoded)
    else:
        payload = parsed_message.get_payload(decode=True)
        if payload is None:
            payload = str(parsed_message.get_payload() or "").encode("utf-8", errors="replace")
        charset = parsed_message.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            decoded = payload.decode("utf-8", errors="replace")
        if parsed_message.get_content_type() == "text/html":
            html_parts.append(decoded)
        else:
            plain_parts.append(decoded)

    if (
        raw_email
        and pasted_summary
        and pasted_summary.get("recognized_fields", 0) >= 3
        and subject == "(No subject)"
        and not from_address
    ):
        parse_source = "pasted_summary"
        subject = pasted_summary.get("subject") or "(No subject)"
        from_name = pasted_summary.get("from_name", "")
        from_address = pasted_summary.get("from_address", "")
        reply_to_name = pasted_summary.get("reply_to_name", "")
        reply_to_address = pasted_summary.get("reply_to_address", "")
        plain_parts = [pasted_summary.get("body_text", "") or raw_email]

    plain_text = _clean_email_text("\n".join(plain_parts))
    html_text = "\n".join(html_parts)
    html_text_content = _strip_html_tags(html_text)
    combined_text = _clean_email_text(" ".join([subject, plain_text, html_text_content]))

    extracted_urls = _extract_urls_from_text(f"{plain_text}\n{html_text}")
    html_link_details = _extract_html_link_indicators(html_text)
    for item in html_link_details:
        href = item.get("href")
        if href and href not in extracted_urls:
            extracted_urls.append(href)
    extracted_urls = extracted_urls[:15]
    web_urls: List[str] = []
    ignored_links: List[str] = []
    for extracted_url in extracted_urls:
        scheme = urlparse(extracted_url).scheme.lower()
        if scheme in {"http", "https"}:
            web_urls.append(extracted_url)
        else:
            ignored_links.append(extracted_url)

    url_results: List[Dict[str, Any]] = []
    for extracted_url in web_urls:
        static_eval = _evaluate_url_static(extracted_url, db)
        url_results.append({
            "url": extracted_url,
            "status": static_eval["status"],
            "threat_score": int(static_eval["threat_score"]),
            "matched_feed": bool(static_eval["details"]["layers"]["layer2_phishtank"].get("found")),
            "match_type": static_eval["details"]["layers"]["layer2_phishtank"].get("match_type"),
        })

    auth_results = _parse_auth_signal_from_headers(parsed_message)
    if parse_source == "pasted_summary" and pasted_summary:
        mailed_by = pasted_summary.get("mailed_by", "").lower()
        signed_by = pasted_summary.get("signed_by", "").lower()
        if mailed_by and from_address and mailed_by == _email_domain(from_address):
            auth_results["spf"] = "pass"
        if signed_by and from_address and signed_by == _email_domain(from_address):
            auth_results["dkim"] = "pass"
    from_domain = _email_domain(from_address)
    reply_to_domain = _email_domain(reply_to_address)
    return_path_domain = _email_domain(return_path_address)
    heuristic_summary = _score_email_heuristics(
        subject=subject,
        combined_text=combined_text,
        auth_results=auth_results,
        from_name=from_name,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        html_links=html_link_details,
        url_results=url_results,
        attachment_results=attachments,
    )

    max_url_score = max((item["threat_score"] for item in url_results), default=0)
    max_attachment_score = max((item["threat_score"] for item in attachments), default=0)
    combined_score = min(
        100,
        heuristic_summary["score"]
        + min(25, round(max_url_score * 0.35))
        + min(25, round(max_attachment_score * 0.35)),
    )

    status = "clean"
    if combined_score >= 70 or any(item["status"] == "malicious" for item in url_results + attachments):
        status = "malicious"
    elif combined_score >= 35 or any(item["status"] == "suspicious" for item in url_results + attachments):
        status = "suspicious"

    target_label = subject
    if subject == "(No subject)" and from_address:
        target_label = from_address
    if subject == "(No subject)" and not from_address:
        target_label = source_name

    details = {
        "source": parse_source,
        "source_name": source_name,
        "subject": subject,
        "headers": {
            "from": from_address,
            "from_name": from_name,
            "to": pasted_summary.get("to_address", "") if pasted_summary else "",
            "to_name": pasted_summary.get("to_name", "") if pasted_summary else "",
            "reply_to": reply_to_address,
            "reply_to_name": reply_to_name,
            "return_path": return_path_address,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "message_id": str(parsed_message.get("Message-ID") or "").strip(),
            "date": (
                pasted_summary.get("date", "").strip()
                if parse_source == "pasted_summary" and pasted_summary and pasted_summary.get("date")
                else str(parsed_message.get("Date") or "").strip()
            ),
            "mailed_by": pasted_summary.get("mailed_by", "") if pasted_summary else "",
            "signed_by": pasted_summary.get("signed_by", "") if pasted_summary else "",
            "security": pasted_summary.get("security", "") if pasted_summary else "",
        },
        "authentication": auth_results,
        "body_summary": {
            "plain_text_chars": len(plain_text),
            "html_chars": len(html_text),
            "has_html": bool(html_text),
            "preview": combined_text[:280],
        },
        "url_analysis": {
            "count": len(url_results),
            "ignored_non_web_links": ignored_links[:8],
            "malicious": sum(1 for item in url_results if item["status"] == "malicious"),
            "suspicious": sum(1 for item in url_results if item["status"] == "suspicious"),
            "results": url_results,
            "html_link_mismatches": [item for item in html_link_details if item.get("mismatch")][:8],
        },
        "attachment_analysis": {
            "count": len(attachments),
            "malicious": sum(1 for item in attachments if item["status"] == "malicious"),
            "suspicious": sum(1 for item in attachments if item["status"] == "suspicious"),
            "results": attachments,
        },
        "phishing_signals": heuristic_summary["indicators"],
        "overall_threat_score": combined_score,
        "status": status,
        "scan_timestamp": datetime.utcnow().isoformat(),
    }

    return {
        "status": status,
        "threat_score": combined_score,
        "details": details,
        "target": target_label,
    }


# ============= URL SCANNER - 4 LAYER SYSTEM =============

def layer1_format_validation(url: str) -> Dict[str, Any]:
    """Layer 1: Format Validation"""
    try:
        normalized_url = _normalize_scan_url(url)
        if not normalized_url:
            return {
                "passed": False,
                "issues": ["Invalid URL format"],
            }

        parsed = urlparse(normalized_url)

        issues = []
        suspicious = False
        full_lower = url.lower()
        query_lower = parsed.query.lower()

        # Check protocol
        if parsed.scheme not in ['http', 'https']:
            issues.append("Invalid protocol")
            suspicious = True

        # Check for suspicious characters
        suspicious_chars = ['@', '..', '///', '%00']
        if any(char in normalized_url for char in suspicious_chars):
            issues.append("Suspicious characters detected")
            suspicious = True

        # Check URL length (phishing URLs are often very long)
        if len(normalized_url) > 200:
            issues.append("Unusually long URL")
            suspicious = True

        # Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, parsed.netloc):
            issues.append("Uses IP address instead of domain")
            suspicious = True

        sqli_signatures = [
            r"(?:\b|%20)(union)(?:\b|%20).{0,30}(?:\b|%20)(select)(?:\b|%20)",
            r"(?:\b|%20)(or|and)(?:\b|%20)[^=&]{0,30}(?:=|%3d)[^=&]{0,30}",
            r"(?:\b|%20)(drop|insert|update|delete)(?:\b|%20)",
            r"(?:--|%2d%2d|/\*|\*/|%23)",
            r"(?:\b|%20)(information_schema|xp_cmdshell|benchmark|sleep)(?:\b|%20)",
        ]
        if query_lower and any(re.search(pattern, query_lower) for pattern in sqli_signatures):
            issues.append("SQL injection-style query payload detected")
            suspicious = True
        elif any(re.search(pattern, full_lower) for pattern in sqli_signatures):
            issues.append("SQL injection-style path or query pattern detected")
            suspicious = True

        return {
            "passed": not suspicious,
            "issues": issues,
            "protocol": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "normalized_url": normalized_url,
        }
    except Exception as e:
        return {
            "passed": False,
            "issues": ["Invalid URL format"],
            "error": str(e)
        }


def layer2_phishtank_check(url: str, db: Session) -> Dict[str, Any]:
    """Layer 2: Malicious URL Database Check (75K+ URLs)"""
    normalized_url = _normalize_scan_url(url) or url.strip()
    parsed_url = urlparse(normalized_url)
    domain = (parsed_url.hostname or parsed_url.netloc or "").lower()
    effective_domain = _get_effective_host(domain)

    local_feed = _load_local_url_feed()
    if normalized_url in local_feed["exact"]:
        threat_type = local_feed["exact"][normalized_url]
        return {
            "found": True,
            "verified": True,
            "threat_type": threat_type,
            "source": "local-url-feed",
            "threat_level": "high",
            "match_type": "exact_url",
            "message": "URL found in local curated threat feed",
        }
    if domain and domain in local_feed["domains"]:
        return {
            "found": True,
            "verified": True,
            "threat_type": local_feed["domains"][domain],
            "source": "local-url-feed",
            "threat_level": "high",
            "match_type": "domain_only",
            "message": "Domain found in local curated threat feed",
        }
    if effective_domain and effective_domain in local_feed["domains"]:
        return {
            "found": True,
            "verified": True,
            "threat_type": local_feed["domains"][effective_domain],
            "source": "local-url-feed",
            "threat_level": "high",
            "match_type": "domain_only",
            "message": "Effective domain found in local curated threat feed",
        }

    # Check imported threat feed entries stored in PostgreSQL.
    try:
        url_hash = sha256_hex(normalized_url)
        threat_entry = db.query(ThreatUrl).filter(ThreatUrl.url_hash == url_hash).first()
        if threat_entry:
            source = threat_entry.source or "threat-feed"
            threat_type = threat_entry.threat_type or "malicious-url"
            logger.info(f"THREAT FEED HIT: {normalized_url} - {source} - {threat_type}")
            return {
                "found": True,
                "verified": bool(threat_entry.verified),
                "threat_type": threat_type,
                "source": source,
                "threat_level": "high",
                "match_type": "exact_url",
                "message": f"URL found in imported threat feed ({source})",
            }

        if domain:
            domain_matches = db.query(ThreatUrl).filter(ThreatUrl.domain == domain).count()
            if domain_matches > 0:
                logger.info(f"DOMAIN MATCH: {domain} appears in {domain_matches} threat feed entries")
                shared_host = domain in DOMAIN_ONLY_REPUTATION_HOSTS
                trusted_root = _is_trusted_root_domain(domain)
                downgraded = shared_host or trusted_root
                domain_context = (
                    "trusted_root"
                    if trusted_root
                    else "shared_host"
                    if shared_host
                    else "standard"
                )
                domain_only_score = 0 if downgraded else 20
                return {
                    "found": False if downgraded else True,
                    "verified": False,
                    "domain_matches": domain_matches,
                    "threat_level": "low" if downgraded else "medium",
                    "match_type": "domain_only",
                    "downgraded_shared_host": shared_host,
                    "downgraded_trusted_root": trusted_root,
                    "domain_context": domain_context,
                    "domain_only_score": domain_only_score,
                    "message": (
                        f"Domain appears in {domain_matches} imported threat feed entries, but this is a trusted root domain and only exact URL hits are treated as malicious"
                        if trusted_root
                        else f"Domain appears in {domain_matches} imported threat feed entries, but this is a shared hosting platform"
                        if shared_host
                        else f"Domain appears in {domain_matches} imported threat feed entries"
                    ),
                }

    except Exception as e:
        logger.error(f"Error checking imported threat feed: {e}")

    # Also check PhishTank table as fallback (plain URL table).
    phish_entry = db.query(PhishTankEntry).filter(
        PhishTankEntry.url == normalized_url
    ).first()

    if phish_entry:
        return {
            "found": True,
            "verified": phish_entry.verified,
            "phish_id": phish_entry.phish_id,
            "threat_level": "high",
            "match_type": "exact_url",
            "message": "URL found in PhishTank database"
        }

    return {
        "found": False,
        "threat_level": "low",
        "match_type": "none",
        "message": "URL not found in threat databases (75K+ URLs checked)"
    }


def layer3_domain_reputation(url: str) -> Dict[str, Any]:
    """Layer 3: Domain Reputation Check"""
    normalized_url = _normalize_scan_url(url) or url
    parsed = urlparse(normalized_url)
    domain = (parsed.hostname or parsed.netloc or "").lower()
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()

    # Simulate domain reputation checks
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    is_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)

    # Check for suspicious patterns in domain
    suspicious_keywords = ['secure', 'account', 'verify', 'login', 'bank', 'paypal', 'update']
    has_suspicious_keywords = any(keyword in domain.lower() for keyword in suspicious_keywords)

    # Check for subdomain tricks (e.g., paypal.malicious.com)
    subdomain_count = domain.count('.')
    suspicious_subdomain = subdomain_count > 2
    trusted_root = _is_trusted_root_domain(domain)
    brand_impersonation = _brand_impersonation_tokens(domain)
    trusted_brand_path_tokens = [
        token for token in TRUSTED_BRAND_PATH_TOKENS
        if token in path_and_query and token not in domain
    ]

    issues = []
    reputation_score = 100

    if is_suspicious_tld:
        issues.append("Suspicious top-level domain")
        reputation_score -= 30

    if has_suspicious_keywords:
        issues.append("Domain contains suspicious keywords")
        reputation_score -= 20

    if suspicious_subdomain and not trusted_root:
        issues.append("Multiple subdomains detected")
        reputation_score -= 15

    if brand_impersonation:
        issues.append(f"Domain imitates trusted brands: {', '.join(brand_impersonation[:3])}")
        reputation_score -= 35

    if trusted_brand_path_tokens and not trusted_root:
        issues.append(f"Path/query references trusted brands on an unrelated host: {', '.join(trusted_brand_path_tokens[:3])}")
        reputation_score -= 10

    # Check for homograph attacks (IDN)
    if any(ord(char) > 127 for char in domain):
        issues.append("Contains non-ASCII characters (possible homograph attack)")
        reputation_score -= 25

    return {
        "domain": domain,
        "reputation_score": max(0, reputation_score),
        "suspicious_tld": is_suspicious_tld,
        "suspicious_keywords": has_suspicious_keywords,
        "trusted_root_domain": trusted_root,
        "brand_impersonation": brand_impersonation,
        "path_brand_abuse": trusted_brand_path_tokens,
        "issues": issues,
        "threat_level": "high" if reputation_score < 50 else "medium" if reputation_score < 75 else "low"
    }


def layer4_content_analysis(url: str) -> Dict[str, Any]:
    """Layer 4: Content Analysis (simulated)"""
    normalized_url = _normalize_scan_url(url) or url
    parsed = urlparse(normalized_url)
    host = (parsed.hostname or "").lower()
    full_lower = normalized_url.lower()
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = {key.lower() for key, _ in query_pairs}

    indicators = []
    threat_score = 0

    # Check for common phishing patterns
    if 'verify' in normalized_url.lower() or 'confirm' in normalized_url.lower():
        indicators.append("URL contains verification/confirmation language")
        threat_score += 15

    if 'suspended' in normalized_url.lower() or 'locked' in normalized_url.lower():
        indicators.append("URL suggests account suspension/lock")
        threat_score += 20

    # Check for URL shorteners (often used in phishing)
    shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl']
    if any(shortener in parsed.netloc for shortener in shorteners):
        indicators.append("URL shortener detected")
        threat_score += 10

    # Check for suspicious query parameters
    if 'token' in normalized_url.lower() or 'session' in normalized_url.lower():
        indicators.append("Contains authentication parameters")
        threat_score += 10

    if not _is_trusted_root_domain(host):
        host_impersonation = _brand_impersonation_tokens(host)
        if host_impersonation:
            indicators.append(f"Host imitates trusted brands: {', '.join(host_impersonation[:3])}")
            threat_score += 18

        deceptive_brands = [token for token in TRUSTED_BRAND_PATH_TOKENS if token in full_lower and token not in host]
        if deceptive_brands:
            indicators.append(f"Unrelated host references trusted brands: {', '.join(deceptive_brands[:3])}")
            threat_score += 15

    if re.search(r"https?%3a|https?://", parsed.path.lower()) or re.search(r"https?%3a|https?://", parsed.query.lower()):
        indicators.append("Embedded external URL detected in path or query")
        threat_score += 12

    # Open-source-inspired URL heuristics used by many scanners.
    if host.startswith("xn--") or any(ord(char) > 127 for char in host):
        indicators.append("Internationalized/punycode host detected")
        threat_score += 15

    if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        indicators.append("Direct IPv4 host used instead of domain")
        threat_score += 20

    if "@" in normalized_url:
        indicators.append("URL contains '@' userinfo obfuscation pattern")
        threat_score += 15

    if len(normalized_url) >= 200:
        indicators.append("Very long URL length")
        threat_score += 20
    elif len(normalized_url) >= 120:
        indicators.append("Long URL length")
        threat_score += 10

    if normalized_url.count("%") >= 6:
        indicators.append("Heavy URL encoding detected")
        threat_score += 8

    if parsed.port and parsed.port not in {80, 443}:
        indicators.append("Non-standard destination port")
        threat_score += 8

    if host.count(".") >= 4:
        indicators.append("Deep subdomain chain detected")
        threat_score += 8

    if len(query_pairs) >= 4:
        indicators.append("High number of query parameters")
        threat_score += 6

    if "option" in query_keys and any(value.lower().startswith("com_") for key, value in query_pairs if key.lower() == "option"):
        indicators.append("Legacy CMS component route detected")
        threat_score += 6

    if {"option", "tmpl"}.issubset(query_keys):
        option_value = next((value.lower() for key, value in query_pairs if key.lower() == "option"), "")
        tmpl_value = next((value.lower() for key, value in query_pairs if key.lower() == "tmpl"), "")
        if option_value == "com_mailto" and tmpl_value == "component":
            indicators.append("Encoded legacy mailto redirect pattern detected")
            threat_score += 18

    if any(key.lower().startswith("vsig") for key, _ in query_pairs):
        indicators.append("Suspicious legacy CMS signature parameter detected")
        threat_score += 20

    redirect_keys = {"link", "url", "target", "dest", "destination", "redir", "redirect"}
    for key, value in query_pairs:
        if key.lower() in redirect_keys and _looks_like_base64_token(value):
            indicators.append("Encoded redirect target detected in query string")
            threat_score += 18
            break

    sqli_regexes = [
        r"(?:\b|%20)union(?:\b|%20).{0,30}(?:\b|%20)select(?:\b|%20)",
        r"(?:\b|%20)(?:or|and)(?:\b|%20)[^=&]{0,30}(?:=|%3d)[^=&]{0,30}",
        r"(?:\b|%20)(?:information_schema|xp_cmdshell|benchmark|sleep)(?:\b|%20)",
    ]
    sqli_hits = sum(1 for pattern in sqli_regexes if re.search(pattern, full_lower))
    if sqli_hits:
        indicators.append("SQL injection-like payload detected in URL parameters")
        threat_score += 18 + min(18, (sqli_hits - 1) * 6)

    if any(marker in full_lower for marker in ["--", "%2d%2d", "/*", "%2f*", "*/", "%23"]):
        indicators.append("SQL comment/termination markers detected")
        threat_score += 10

    return {
        "indicators": indicators,
        "threat_score": threat_score,
        "ssl_expected": parsed.scheme == 'https',
        "analysis_complete": True
    }


URL_DETAILS_TIMEOUT_SECONDS = 6.0
URL_DETAILS_MAX_BODY_BYTES = 512 * 1024
URL_SCAN_MIN_DURATION_SECONDS = 1.6
URL_SCREENSHOT_TIMEOUT_MS = 12000
URL_SCREENSHOT_VIEWPORT_WIDTH = 1440
URL_SCREENSHOT_VIEWPORT_HEIGHT = 960
HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HTML_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)


class _TrackingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.chain: List[Dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({
            "status_code": int(code),
            "location": str(newurl),
        })
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def _extract_html_title(body_bytes: bytes) -> Optional[str]:
    if not body_bytes:
        return None
    try:
        snippet = body_bytes[:65536].decode("utf-8", "ignore")
    except Exception:
        return None
    match = HTML_TITLE_RE.search(snippet)
    if not match:
        return None
    title = unescape(match.group(1)).strip()
    title = re.sub(r"\s+", " ", title)
    return title[:240] if title else None


def _extract_links_from_html(base_url: str, body_bytes: bytes, limit: int = 20) -> List[str]:
    if not body_bytes:
        return []
    try:
        snippet = body_bytes[:200000].decode("utf-8", "ignore")
    except Exception:
        return []

    links: List[str] = []
    seen = set()
    for raw_link in HTML_HREF_RE.findall(snippet):
        try:
            absolute = urljoin(base_url, raw_link.strip())
            parsed = urlparse(absolute)
            if parsed.scheme not in {"http", "https"}:
                continue
            normalized = absolute.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            links.append(normalized)
            if len(links) >= limit:
                break
        except Exception:
            continue
    return links


def _resolve_dns_addresses(hostname: str) -> List[str]:
    host = (hostname or "").strip()
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []

    addresses: List[str] = []
    seen = set()
    for info in infos:
        sockaddr = info[4]
        ip = str(sockaddr[0]).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        addresses.append(ip)
    return addresses[:12]


def _fetch_tls_summary(target_url: str) -> Dict[str, Any]:
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").strip().lower()
    port = parsed.port or 443
    if parsed.scheme != "https" or not hostname:
        return {"available": False}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=URL_DETAILS_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
    except Exception as exc:
        return {
            "available": False,
            "error": str(exc),
        }

    def _flatten_name(parts: Any) -> str:
        try:
            flattened = []
            for item in parts or []:
                for key, value in item:
                    flattened.append(f"{key}={value}")
            return ", ".join(flattened)
        except Exception:
            return ""

    san_entries = []
    for kind, value in cert.get("subjectAltName", []) if isinstance(cert, dict) else []:
        if kind == "DNS":
            san_entries.append(str(value))

    return {
        "available": True,
        "subject": _flatten_name(cert.get("subject")) if isinstance(cert, dict) else "",
        "issuer": _flatten_name(cert.get("issuer")) if isinstance(cert, dict) else "",
        "valid_from": cert.get("notBefore") if isinstance(cert, dict) else None,
        "valid_to": cert.get("notAfter") if isinstance(cert, dict) else None,
        "serial_number": cert.get("serialNumber") if isinstance(cert, dict) else None,
        "subject_alt_names": san_entries[:10],
    }


def _extract_rdap_event(payload: Dict[str, Any], event_action: str) -> Optional[str]:
    for event in payload.get("events", []) if isinstance(payload, dict) else []:
        if str(event.get("eventAction") or "").lower() == event_action.lower():
            value = event.get("eventDate")
            if value:
                return str(value)
    return None


def _extract_registrar_name(payload: Dict[str, Any]) -> Optional[str]:
    entities = payload.get("entities", []) if isinstance(payload, dict) else []
    for entity in entities:
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for entry in vcard[1]:
                if isinstance(entry, list) and len(entry) >= 4 and str(entry[0]).lower() == "fn":
                    value = entry[3]
                    if value:
                        return str(value)
        handle = entity.get("handle")
        if handle:
            return str(handle)
    return None


def _extract_entity_vcard_text(entity: Dict[str, Any], field_name: str) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list)):
        return None
    for entry in vcard[1]:
        if not (isinstance(entry, list) and len(entry) >= 4):
            continue
        if str(entry[0]).lower() != field_name.lower():
            continue
        value = entry[3]
        if isinstance(value, list):
            flattened = [str(item).strip() for item in value if str(item).strip()]
            return ", ".join(flattened) if flattened else None
        if value:
            return str(value)
    return None


def _extract_entity_country(entity: Dict[str, Any]) -> Optional[str]:
    adr_value = _extract_entity_vcard_text(entity, "adr")
    if adr_value:
        parts = [part.strip() for part in adr_value.split(",") if part.strip()]
        if parts:
            return parts[-1]
    country_value = _extract_entity_vcard_text(entity, "country-name")
    if country_value:
        return country_value
    return None


def _extract_entity_email(entity: Dict[str, Any]) -> Optional[str]:
    email_value = _extract_entity_vcard_text(entity, "email")
    if email_value:
        return email_value
    return None


def _extract_registry_country(payload: Dict[str, Any]) -> Optional[str]:
    entities = payload.get("entities", []) if isinstance(payload, dict) else []
    for entity in entities:
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "registrar" in roles or "registrant" in roles:
            country = _extract_entity_country(entity)
            if country:
                return country
    return None


def _extract_abuse_contact(payload: Dict[str, Any]) -> Optional[str]:
    entities = payload.get("entities", []) if isinstance(payload, dict) else []
    for entity in entities:
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "abuse" in roles:
            email_value = _extract_entity_email(entity)
            if email_value:
                return email_value
            handle = entity.get("handle")
            if handle:
                return str(handle)
    return None


def _fetch_domain_info(hostname: str) -> Dict[str, Any]:
    host = (hostname or "").strip().lower()
    if not host:
        return {"available": False}

    if _is_private_or_local_target_url(f"https://{host}/"):
        return {
            "available": False,
            "error": "Refusing to collect domain intelligence for local/private targets.",
        }

    registered_domain = _guess_registered_domain(host)
    dns_addresses = _resolve_dns_addresses(host)

    rdap_url = f"https://rdap.org/domain/{registered_domain}"
    request = urllib.request.Request(
        rdap_url,
        headers={"User-Agent": "SECA/1.0", "Accept": "application/rdap+json, application/json"},
    )

    rdap_payload: Dict[str, Any] = {}
    rdap_error: Optional[str] = None
    try:
        with urllib.request.urlopen(request, timeout=URL_DETAILS_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", "ignore")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                rdap_payload = parsed
    except Exception as exc:
        rdap_error = str(exc)

    nameservers = []
    for entry in rdap_payload.get("nameservers", []) if isinstance(rdap_payload, dict) else []:
        value = entry.get("ldhName") or entry.get("unicodeName")
        if value:
            nameservers.append(str(value))

    return {
        "available": bool(rdap_payload) or bool(dns_addresses),
        "host": host,
        "registered_domain": registered_domain,
        "registrar": _extract_registrar_name(rdap_payload),
        "registry_country": _extract_registry_country(rdap_payload),
        "abuse_contact": _extract_abuse_contact(rdap_payload),
        "created_at": _extract_rdap_event(rdap_payload, "registration"),
        "updated_at": _extract_rdap_event(rdap_payload, "last changed"),
        "expires_at": _extract_rdap_event(rdap_payload, "expiration"),
        "dns_addresses": dns_addresses,
        "nameservers": nameservers[:10],
        "rdap_error": rdap_error,
        "rdap_source": rdap_url,
    }


def _build_url_detail_categories(static_eval: Dict[str, Any]) -> List[str]:
    categories: List[str] = []
    details = static_eval.get("details") or {}
    layers = details.get("layers") or {}
    layer2 = layers.get("layer2_phishtank") or {}
    layer4 = layers.get("layer4_content") or {}

    threat_type = str(layer2.get("threat_type") or "").strip()
    if threat_type:
        categories.append(threat_type)

    source = str(layer2.get("source") or "").strip()
    if source:
        categories.append(source)

    match_type = str(layer2.get("match_type") or "").strip()
    if match_type == "exact_url":
        categories.append("exact-url-hit")
    elif match_type == "domain_only":
        categories.append("domain-only-hit")

    for indicator in layer4.get("indicators") or []:
        normalized = str(indicator).strip()
        if normalized:
            categories.append(normalized)
        if len(categories) >= 6:
            break

    seen = set()
    deduped: List[str] = []
    for category in categories:
        key = category.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(category)
    return deduped[:6]


def _lookup_url_scan_history(url: str, db: Session) -> Dict[str, Any]:
    scans = (
        db.query(Scan)
        .filter(Scan.scan_type == "url_advanced", Scan.target == url)
        .order_by(Scan.created_at.asc())
        .all()
    )
    if not scans:
        return {
            "scan_count": 0,
            "first_submission": None,
            "last_submission": None,
            "last_analysis": None,
        }

    first = scans[0]
    last = scans[-1]
    return {
        "scan_count": len(scans),
        "first_submission": _safe_iso(first.created_at),
        "last_submission": _safe_iso(last.created_at),
        "last_analysis": _safe_iso(last.created_at),
    }


def _fetch_url_http_response_details(target_url: str) -> Dict[str, Any]:
    allowed, reason = _validate_dynamic_url_target(target_url)
    if not allowed:
        return {
            "fetch_allowed": False,
            "error": reason,
        }

    redirect_handler = _TrackingRedirectHandler()
    opener = urllib.request.build_opener(redirect_handler)
    request = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "SECA/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    response_obj = None
    body = b""
    status_code: Optional[int] = None
    final_url = target_url
    headers: Dict[str, str] = {}

    try:
        with opener.open(request, timeout=URL_DETAILS_TIMEOUT_SECONDS) as response:
            response_obj = response
            status_code = int(getattr(response, "status", 0) or response.getcode())
            final_url = response.geturl() or target_url
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            body = response.read(URL_DETAILS_MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        response_obj = exc
        status_code = int(exc.code)
        final_url = exc.geturl() or target_url
        headers = {str(key).lower(): str(value) for key, value in exc.headers.items()}
        body = exc.read(URL_DETAILS_MAX_BODY_BYTES + 1)
    except Exception as exc:
        return {
            "fetch_allowed": True,
            "error": str(exc),
        }

    truncated = len(body) > URL_DETAILS_MAX_BODY_BYTES
    body = body[:URL_DETAILS_MAX_BODY_BYTES]
    body_length = len(body)
    body_sha256 = hashlib.sha256(body).hexdigest() if body else None
    page_title = _extract_html_title(body)

    try:
        final_host = (urlparse(final_url).hostname or "").strip().lower()
        resolved_ips = _resolve_dns_addresses(final_host)
        serving_ip = resolved_ips[0] if resolved_ips else None
    except Exception:
        resolved_ips = []
        serving_ip = None

    header_items = [{"name": key, "value": value} for key, value in headers.items()]
    content_length_raw = headers.get("content-length", "").strip()
    try:
        content_length = int(content_length_raw) if content_length_raw else body_length
    except ValueError:
        content_length = body_length

    extracted_links = _extract_links_from_html(final_url, body)

    return {
        "fetch_allowed": True,
        "final_url": final_url,
        "serving_ip_address": serving_ip,
        "resolved_ips": resolved_ips,
        "status_code": status_code,
        "body_length": content_length,
        "body_sha256": body_sha256,
        "headers": header_items,
        "page_title": page_title,
        "redirect_chain": redirect_handler.chain,
        "outgoing_links": extracted_links,
        "redirected": final_url != target_url,
        "body_truncated": truncated,
        "fetched_at": datetime.utcnow().isoformat(),
        "tls": _fetch_tls_summary(final_url),
    }


async def _capture_url_screenshot_bytes(target_url: str) -> bytes:
    allowed, reason = _validate_dynamic_url_target(target_url)
    if not allowed:
        raise HTTPException(status_code=400, detail=reason)
    if async_playwright is None:
        raise HTTPException(status_code=503, detail="Playwright is not installed on this backend.")

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={
                    "width": URL_SCREENSHOT_VIEWPORT_WIDTH,
                    "height": URL_SCREENSHOT_VIEWPORT_HEIGHT,
                },
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            page = await context.new_page()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=URL_SCREENSHOT_TIMEOUT_MS)
            if response is None:
                raise HTTPException(status_code=502, detail="Website is unavailable or could not be reached for screenshot capture.")
            await page.wait_for_timeout(1200)
            screenshot = await page.screenshot(type="png", full_page=False)
            await context.close()
            await browser.close()
            return screenshot
    except PlaywrightTimeoutError:
        raise HTTPException(status_code=504, detail="Timed out while capturing website screenshot.")
    except HTTPException:
        raise
    except Exception as exc:
        message = str(exc)
        network_markers = [
            "ERR_NAME_NOT_RESOLVED",
            "ERR_CONNECTION_REFUSED",
            "ERR_CONNECTION_TIMED_OUT",
            "ERR_ADDRESS_UNREACHABLE",
            "ERR_INTERNET_DISCONNECTED",
            "ERR_CONNECTION_RESET",
            "net::",
        ]
        if any(marker in message for marker in network_markers):
            raise HTTPException(status_code=502, detail="Website is unavailable or could not be reached for screenshot capture.")
        raise HTTPException(status_code=500, detail=f"Website screenshot failed: {exc}")


def _image_bytes_to_data_url(image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def _truncate_text(value: Any, max_length: int = 240) -> str:
    text = str(value or "").strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def _extract_request_redirect_chain(request: Any) -> List[str]:
    chain: List[str] = []
    current = request
    while current is not None:
        try:
            chain.append(str(current.url))
            current = current.redirected_from
        except Exception:
            break
    chain.reverse()
    return chain


async def _collect_form_summary(page: Any) -> Dict[str, Any]:
    try:
        return await page.evaluate(
            """() => {
                const forms = Array.from(document.forms || []);
                const items = forms.slice(0, 10).map((form) => {
                    const inputs = Array.from(form.querySelectorAll('input'));
                    const passwordFields = inputs.filter((input) => (input.type || '').toLowerCase() === 'password').length;
                    return {
                        action: form.action || '',
                        method: (form.method || 'get').toUpperCase(),
                        inputCount: inputs.length,
                        passwordFields,
                    };
                });
                return {
                    count: forms.length,
                    passwordFormCount: items.filter((item) => item.passwordFields > 0).length,
                    items,
                };
            }"""
        )
    except Exception:
        return {"count": 0, "passwordFormCount": 0, "items": []}


def _detect_browser_dynamic_indicators(
    final_url: str,
    outgoing_hosts: List[str],
    console_messages: List[Dict[str, Any]],
    downloads: List[Dict[str, Any]],
    dialogs: List[Dict[str, Any]],
    page_errors: List[str],
    form_summary: Dict[str, Any],
    html_snapshot: str,
) -> List[str]:
    indicators: List[str] = []
    final_host = (urlparse(final_url).hostname or "").lower()

    if downloads:
        indicators.append("browser-triggered-download")
    if dialogs:
        indicators.append("browser-dialog")
    if page_errors:
        indicators.append("page-script-error")
    if int(form_summary.get("passwordFormCount") or 0) > 0:
        indicators.append("password-form-present")

    suspicious_console_keywords = ("credential", "wallet", "captcha", "token", "phish", "verify")
    for message in console_messages[:20]:
        text = str(message.get("text") or "").lower()
        if any(keyword in text for keyword in suspicious_console_keywords):
            indicators.append("suspicious-console-text")
            break

    if len(outgoing_hosts) >= 8:
        indicators.append("many-outgoing-hosts")

    suspicious_script_tokens = (
        "eval(",
        "document.write(",
        "fromcharcode(",
        "atob(",
        "unescape(",
        "window.location.replace(",
    )
    lowered_html = html_snapshot.lower()
    if any(token in lowered_html for token in suspicious_script_tokens):
        indicators.append("obfuscated-script-pattern")

    if final_host and int(form_summary.get("passwordFormCount") or 0) > 0:
        for item in form_summary.get("items") or []:
            action_host = (urlparse(str(item.get("action") or "")).hostname or "").lower()
            if action_host and action_host != final_host:
                indicators.append("cross-domain-password-form")
                break

    deduped: List[str] = []
    seen = set()
    for item in indicators:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _score_browser_dynamic_result(
    final_url: str,
    outgoing_hosts: List[str],
    downloads: List[Dict[str, Any]],
    dialogs: List[Dict[str, Any]],
    page_errors: List[str],
    form_summary: Dict[str, Any],
    indicators: List[str],
) -> Tuple[str, int, List[str]]:
    score = 0
    summary: List[str] = []

    if downloads:
        score += min(40, 20 + len(downloads) * 10)
        summary.append(f"{len(downloads)} browser download event(s) observed")
    if dialogs:
        score += min(12, 4 + len(dialogs) * 4)
        summary.append(f"{len(dialogs)} browser dialog event(s) observed")
    if page_errors:
        score += min(12, 4 + len(page_errors) * 2)
        summary.append(f"{len(page_errors)} page script error(s) captured")

    password_forms = int(form_summary.get("passwordFormCount") or 0)
    if password_forms > 0:
        score += min(20, 8 + password_forms * 5)
        summary.append(f"{password_forms} password form(s) detected in rendered DOM")

    if len(outgoing_hosts) >= 8:
        score += 8
        summary.append(f"{len(outgoing_hosts)} distinct outgoing host(s) observed")

    if "cross-domain-password-form" in indicators:
        score += 20
        summary.append("Password form submits to a different domain")
    if "obfuscated-script-pattern" in indicators:
        score += 14
        summary.append("Obfuscated JavaScript pattern observed in rendered HTML")
    if "suspicious-console-text" in indicators:
        score += 8
        summary.append("Suspicious security-related console text observed")
    if "browser-triggered-download" in indicators and password_forms > 0:
        score += 10
        summary.append("Download behaviour occurred alongside credential collection surface")

    score = min(100, score)
    verdict = "clean"
    if score >= 55:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"

    if not summary:
        summary.append("No suspicious browser-level behaviour detected during fast dynamic scan")

    summary.insert(0, f"Observed {len(outgoing_hosts)} outgoing host(s) while rendering {final_url}")
    return verdict, score, summary


async def _run_browser_dynamic_async(job_id: str, target_url: str) -> None:
    job = _browser_dynamic_jobs[job_id]
    started_at = time.time()

    def update(step: str, progress: int) -> None:
        job["step"] = step
        job["progress"] = max(0, min(100, int(progress)))
        logger.info("[job %s][browser] %s", job_id[:8], step)

    def ensure_not_cancelled() -> None:
        if job.get("cancel_requested"):
            raise RuntimeError("Browser dynamic analysis cancelled by user.")

    if async_playwright is None:
        raise RuntimeError("Playwright is not installed on this backend.")

    requests_seen: List[Dict[str, Any]] = []
    responses_seen: List[Dict[str, Any]] = []
    console_messages: List[Dict[str, Any]] = []
    page_errors: List[str] = []
    dialogs_seen: List[Dict[str, Any]] = []
    downloads_seen: List[Dict[str, Any]] = []
    outgoing_hosts: List[str] = []
    outgoing_host_seen = set()
    screenshot_timeline: List[Dict[str, Any]] = []
    redirect_chain: List[str] = []

    def on_request(request: Any) -> None:
        if len(requests_seen) >= BROWSER_DYNAMIC_MAX_REQUESTS:
            return
        host = (urlparse(str(request.url)).hostname or "").lower()
        if host and host not in outgoing_host_seen:
            outgoing_host_seen.add(host)
            outgoing_hosts.append(host)
        requests_seen.append(
            {
                "method": str(request.method),
                "url": str(request.url),
                "resourceType": str(request.resource_type),
            }
        )

    def on_response(response: Any) -> None:
        if len(responses_seen) >= BROWSER_DYNAMIC_MAX_RESPONSES:
            return
        headers = {}
        try:
            headers = response.headers
        except Exception:
            headers = {}
        responses_seen.append(
            {
                "url": str(response.url),
                "status": int(response.status),
                "contentType": str(headers.get("content-type") or ""),
            }
        )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 960},
            ignore_https_errors=True,
            java_script_enabled=True,
            accept_downloads=True,
        )
        page = await context.new_page()

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", lambda msg: console_messages.append({"type": str(msg.type), "text": _truncate_text(msg.text, 300)}) if len(console_messages) < 20 else None)
        page.on("pageerror", lambda exc: page_errors.append(_truncate_text(exc, 300)) if len(page_errors) < 20 else None)

        async def handle_dialog(dialog: Any) -> None:
            if len(dialogs_seen) < 10:
                dialogs_seen.append({"type": str(dialog.type), "message": _truncate_text(dialog.message, 300)})
            try:
                await dialog.dismiss()
            except Exception:
                pass

        async def handle_download(download: Any) -> None:
            if len(downloads_seen) >= 10:
                return
            try:
                downloads_seen.append(
                    {
                        "url": str(download.url),
                        "suggestedFilename": str(download.suggested_filename),
                    }
                )
            except Exception:
                downloads_seen.append({"url": "", "suggestedFilename": ""})

        page.on("dialog", handle_dialog)
        page.on("download", handle_download)

        try:
            update("Launching browser instrumentation...", 8)
            ensure_not_cancelled()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=URL_SCREENSHOT_TIMEOUT_MS)
            final_url = page.url
            try:
                nav_request = response.request if response else None
            except Exception:
                nav_request = None
            if nav_request is not None:
                redirect_chain = _extract_request_redirect_chain(nav_request)
                if final_url and (not redirect_chain or redirect_chain[-1] != final_url):
                    redirect_chain.append(final_url)

            initial_image = await page.screenshot(type="jpeg", quality=60, full_page=False)
            screenshot_timeline.append({"label": "after-domcontentloaded", "image": _image_bytes_to_data_url(initial_image, "image/jpeg")})

            update("Observing browser activity...", 42)
            remaining_wait = BROWSER_DYNAMIC_WAIT_MS
            while remaining_wait > 0:
                ensure_not_cancelled()
                step_wait = min(1000, remaining_wait)
                await page.wait_for_timeout(step_wait)
                remaining_wait -= step_wait

            settled_image = await page.screenshot(type="jpeg", quality=60, full_page=False)
            screenshot_timeline.append({"label": "after-settle", "image": _image_bytes_to_data_url(settled_image, "image/jpeg")})

            update("Collecting DOM intelligence...", 70)
            ensure_not_cancelled()
            final_title = await page.title()
            html_snapshot = await page.content()
            form_summary = await _collect_form_summary(page)

            indicators = _detect_browser_dynamic_indicators(
                final_url=final_url,
                outgoing_hosts=outgoing_hosts,
                console_messages=console_messages,
                downloads=downloads_seen,
                dialogs=dialogs_seen,
                page_errors=page_errors,
                form_summary=form_summary,
                html_snapshot=html_snapshot,
            )
            verdict, threat_score, summary = _score_browser_dynamic_result(
                final_url=final_url,
                outgoing_hosts=outgoing_hosts,
                downloads=downloads_seen,
                dialogs=dialogs_seen,
                page_errors=page_errors,
                form_summary=form_summary,
                indicators=indicators,
            )

            update("Browser dynamic analysis complete.", 100)
            job["status"] = "done"
            job["finished_at"] = datetime.utcnow().isoformat()
            job["result"] = {
                "verdict": verdict,
                "threatScore": threat_score,
                "duration": int(time.time() - started_at),
                "targetUrl": target_url,
                "finalUrl": final_url,
                "finalTitle": final_title,
                "requestCount": len(requests_seen),
                "responseCount": len(responses_seen),
                "requests": requests_seen,
                "responses": responses_seen,
                "redirectChain": redirect_chain,
                "consoleMessages": console_messages,
                "downloads": downloads_seen,
                "dialogs": dialogs_seen,
                "pageErrors": page_errors,
                "outgoingHosts": outgoing_hosts[:30],
                "forms": form_summary,
                "indicators": indicators,
                "screenshots": screenshot_timeline,
                "summary": summary,
            }
        finally:
            await context.close()
            await browser.close()


def _run_browser_dynamic_blocking(job_id: str, target_url: str) -> None:
    job = _browser_dynamic_jobs[job_id]
    try:
        asyncio.run(_run_browser_dynamic_async(job_id, target_url))
    except Exception as exc:
        logger.error("Browser dynamic job %s failed: %s", job_id, exc, exc_info=True)
        job["status"] = "error"
        job["error"] = str(exc)
        job["finished_at"] = datetime.utcnow().isoformat()


def _build_url_details_payload(url: str, db: Session) -> Dict[str, Any]:
    normalized_url = (url or "").strip()
    static_eval = _evaluate_url_static(normalized_url, db)
    categories = _build_url_detail_categories(static_eval)
    history = _lookup_url_scan_history(normalized_url, db)

    url_hash = sha256_hex(normalized_url)
    threat_entry = db.query(ThreatUrl).filter(ThreatUrl.url_hash == url_hash).first()
    feed_first_seen = _safe_iso(threat_entry.created_at) if threat_entry else None

    parsed = urlparse(normalized_url)
    domain = (parsed.hostname or "").strip().lower()
    domain_feed_matches = db.query(ThreatUrl).filter(ThreatUrl.domain == domain).count() if domain else 0
    domain_info = _fetch_domain_info(domain) if domain else {"available": False}

    return {
        "url": normalized_url,
        "categories": categories,
        "history": {
            **history,
            "feed_first_seen": feed_first_seen,
            "domain_feed_matches": domain_feed_matches,
        },
        "domain_info": domain_info,
        "http_response": _fetch_url_http_response_details(normalized_url),
        "static_context": {
            "status": static_eval.get("status"),
            "threat_score": static_eval.get("threat_score"),
            "scan_timestamp": ((static_eval.get("details") or {}).get("scan_timestamp")),
            "match_type": (((static_eval.get("details") or {}).get("layers") or {}).get("layer2_phishtank") or {}).get("match_type"),
            "source": (((static_eval.get("details") or {}).get("layers") or {}).get("layer2_phishtank") or {}).get("source"),
            "verified": bool(((((static_eval.get("details") or {}).get("layers") or {}).get("layer2_phishtank") or {}).get("verified"))),
        },
    }


def _evaluate_url_static(url: str, db: Session) -> Dict[str, Any]:
    """Compute 4-layer URL static verdict once and reuse for both static + dynamic flows."""
    normalized_url = _normalize_scan_url(url) or url.strip()

    # Layer 1: Format Validation
    layer1 = layer1_format_validation(normalized_url)

    # Layer 2: Threat DB check
    layer2 = layer2_phishtank_check(normalized_url, db)

    # Layer 3: Domain reputation
    layer3 = layer3_domain_reputation(normalized_url)

    # Layer 4: Content analysis
    layer4 = layer4_content_analysis(normalized_url)

    threat_score = 0
    status = "clean"

    if not layer1.get("passed", False):
        threat_score += 20

    if layer2.get("found"):
        if layer2.get("verified"):
            threat_score += 60
        else:
            threat_score += 40
    elif layer2.get("match_type") == "domain_only":
        threat_score += int(layer2.get("domain_only_score", 20))

    layer3_score = 100 - int(layer3.get("reputation_score", 100))
    threat_score += int(layer3_score * 0.25)
    if layer3.get("brand_impersonation"):
        threat_score += 20
    if layer3.get("path_brand_abuse"):
        threat_score += 20
    threat_score += int(layer4.get("threat_score", 0))

    if threat_score >= 60 or (layer2.get("found") and layer2.get("match_type") == "exact_url"):
        status = "malicious"
    elif threat_score >= 35:
        status = "suspicious"
    else:
        status = "clean"

    scan_details = {
        "url": normalized_url,
        "layers": {
            "layer1_format": layer1,
            "layer2_phishtank": layer2,
            "layer3_reputation": layer3,
            "layer4_content": layer4,
        },
        "overall_threat_score": min(100, threat_score),
        "status": status,
        "scan_timestamp": datetime.utcnow().isoformat(),
    }

    return {
        "status": status,
        "threat_score": min(100, threat_score),
        "details": scan_details,
    }


@app.post("/url-scan-advanced")
async def url_scan_advanced(
        url: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Advanced 4-layer URL scanning (authenticated)"""
    started_at = time.perf_counter()
    try:
        user_id = current_user.id
        normalized_url = _normalize_scan_url(url)
        if not normalized_url:
            raise HTTPException(status_code=400, detail="Invalid URL format")

        static_eval = _evaluate_url_static(normalized_url, db)
        status = static_eval["status"]
        threat_score = int(static_eval["threat_score"])
        scan_details = static_eval["details"]

        # Save scan to database
        scan = Scan(
            user_id=user_id,
            scan_type="url_advanced",
            target=normalized_url,
            status=status,
            threat_score=threat_score,
            details=json.dumps(scan_details)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Create audit log
        create_audit_log(db, user_id, "Advanced URL Scan", f"Scanned {normalized_url[:80]}...")

        elapsed = time.perf_counter() - started_at
        remaining = URL_SCAN_MIN_DURATION_SECONDS - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

        return {
            "success": True,
            "scan_id": scan.id,
            "status": status,
            "threat_score": threat_score,
            "details": scan_details
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/url-scan-details")
async def url_scan_details(
        url: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Return VT-style technical details for a scanned URL using local collection logic."""
    try:
        normalized_url = (url or "").strip()
        if not normalized_url:
            raise HTTPException(status_code=422, detail="URL is required.")
        return _build_url_details_payload(normalized_url, db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/url-scan-screenshot")
async def url_scan_screenshot(
        url: str,
        current_user: User = Depends(get_current_user),
):
    """Capture a normal browser screenshot for a scanned URL without launching sandbox analysis."""
    normalized_url = (url or "").strip()
    if not normalized_url:
        raise HTTPException(status_code=422, detail="URL is required.")

    screenshot_bytes = await _capture_url_screenshot_bytes(normalized_url)
    return StreamingResponse(
        io.BytesIO(screenshot_bytes),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/email-scan")
async def email_scan(
        email_file: Optional[UploadFile] = File(None),
        raw_email: Optional[str] = Form(None),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Analyze an .eml or pasted raw email and combine phishing, URL, and attachment signals."""
    try:
        if email_file is None and not (raw_email or "").strip():
            raise HTTPException(status_code=422, detail="Provide either an .eml file or raw email content.")

        email_bytes: Optional[bytes] = None
        source_name = "pasted_email.txt"
        if email_file is not None:
            email_bytes = await email_file.read()
            source_name = email_file.filename or "uploaded_email.eml"
            if not email_bytes:
                raise HTTPException(status_code=422, detail="Uploaded email file is empty.")

        analysis = _analyze_email_payload(
            email_bytes=email_bytes,
            raw_email=(raw_email or "").strip() or None,
            db=db,
            source_name=source_name,
        )

        scan = Scan(
            user_id=current_user.id,
            scan_type="email_scan",
            target=analysis["target"],
            status=analysis["status"],
            threat_score=int(analysis["threat_score"]),
            details=json.dumps(analysis["details"]),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        create_audit_log(
            db,
            current_user.id,
            "Email Scan",
            f"Scanned email {analysis['target'][:80]}",
        )

        return {
            "success": True,
            "scan_id": scan.id,
            "status": analysis["status"],
            "threat_score": int(analysis["threat_score"]),
            "target": analysis["target"],
            "details": analysis["details"],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


STATIC_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".msi", ".cpl", ".ocx"}
STATIC_SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta", ".py", ".sh"}
STATIC_DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt"}
STATIC_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}
STATIC_MEDIA_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".mp3", ".wav", ".mp4", ".avi", ".mkv"}
SUSPICIOUS_STRING_PATTERNS = [
    "powershell -enc",
    "frombase64string",
    "cmd.exe /c",
    "rundll32.exe",
    "regsvr32",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "createremotethread",
    "writeprocessmemory",
    "virtualalloc",
    "schtasks /create",
    "net user /add",
]
SUSPICIOUS_DLL_IMPORTS = {
    "wininet.dll",
    "urlmon.dll",
    "ws2_32.dll",
    "winhttp.dll",
    "crypt32.dll",
    "advapi32.dll",
    "ntdll.dll",
}
SUSPICIOUS_API_IMPORTS = {
    "createremotethread",
    "writeprocessmemory",
    "virtualalloc",
    "virtualallocex",
    "createprocessa",
    "createprocessw",
    "shellexecutea",
    "shellexecutew",
    "winexec",
    "internetopena",
    "internetopenw",
    "internetopenurla",
    "internetopenurlw",
    "urlmonikercreatefromurl",
}
_HASH_FEED_CACHE: Dict[str, Any] = {"path": None, "mtime": None, "entries": {}}
_URL_FEED_CACHE: Dict[str, Any] = {"path": None, "mtime": None, "exact": {}, "domains": {}}


def _normalize_scan_url(raw: str) -> Optional[str]:
    value = (raw or "").strip()
    if not value:
        return None

    if "://" not in value:
        value = f"http://{value}"

    try:
        parsed = urlsplit(value)
    except ValueError:
        return None

    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return None

    scheme = (parsed.scheme or "http").lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    include_port = bool(port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)))
    netloc = f"{host}:{port}" if include_port else host
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return f"{scheme}://{netloc}{path}"


def _get_effective_host(host: str) -> str:
    candidate = (host or "").lower().strip(".")
    if not candidate:
        return ""
    parts = candidate.split(".")
    if len(parts) < 2:
        return candidate
    suffix = ".".join(parts[-2:])
    if suffix in MULTI_LABEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _looks_like_base64_token(value: str) -> bool:
    token = (value or "").strip()
    if len(token) < 16:
        return False
    if len(token) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return False
    return any(char in token for char in "/+=")
_YARA_CACHE: Dict[str, Any] = {"key": None, "rules": None, "source": "disabled", "error": None}
YARA_EXT_VAR_EXCLUDED_FILES = {
    "generic_anomalies.yar",
    "general_cloaking.yar",
    "gen_webshells_ext_vars.yar",
    "thor_inverse_matches.yar",
    "yara_mixed_ext_vars.yar",
    "configured_vulns_ext_vars.yar",
    "gen_fake_amsi_dll.yar",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
}
YARA_EXTERNAL_VARIABLE_DEFAULTS = {
    "filepath": "",
    "filename": "",
    "extension": "",
    "filetype": "",
    "owner": "",
    "owner_domain": "",
    "tags": "",
    "md5": "",
    "imphash": "",
    "magic": "",
    "internal_filename": "",
}


def _classify_file_category(filename: str, content_type: Optional[str]) -> Tuple[str, int]:
    ext = os.path.splitext(filename or "")[1].lower()
    mime = (content_type or "").lower()
    if ext in STATIC_EXECUTABLE_EXTENSIONS or "x-msdownload" in mime or "executable" in mime:
        return "executable", 12
    if ext in STATIC_SCRIPT_EXTENSIONS or "javascript" in mime or "x-sh" in mime:
        return "script", 10
    if ext in STATIC_ARCHIVE_EXTENSIONS or "zip" in mime or "compressed" in mime:
        return "archive", 4
    if ext in STATIC_DOCUMENT_EXTENSIONS or "pdf" in mime or "document" in mime or "spreadsheet" in mime:
        return "document", 3
    if ext in STATIC_MEDIA_EXTENSIONS or mime.startswith("image/") or mime.startswith("audio/") or mime.startswith("video/"):
        return "media", 1
    return "unknown", 6


def _sample_bytes(data: bytes, max_size: int) -> bytes:
    if len(data) <= max_size:
        return data
    step = max(1, len(data) // max_size)
    return data[::step][:max_size]


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = float(len(data))
    for c in counts:
        if not c:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_ascii_strings(data: bytes, min_len: int = 4, limit: int = 5000) -> List[str]:
    out: List[str] = []
    current: List[str] = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                out.append("".join(current))
                if len(out) >= limit:
                    break
            current = []
    if len(out) < limit and len(current) >= min_len:
        out.append("".join(current))
    return out


def _load_local_hash_feed() -> Dict[str, str]:
    path = os.environ.get("SECA_FILE_HASH_FEED", "").strip()
    if not path:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _HASH_FEED_CACHE["path"] == path and _HASH_FEED_CACHE["mtime"] == mtime:
        return _HASH_FEED_CACHE["entries"]

    entries: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [part.strip() for part in line.split(",", 1)]
                hash_value = parts[0].lower()
                if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", hash_value):
                    continue
                entries[hash_value] = parts[1] if len(parts) > 1 and parts[1] else "known-malicious"
    except Exception as exc:
        logger.warning("Failed to load local hash feed from %s: %s", path, exc)
        entries = {}

    _HASH_FEED_CACHE["path"] = path
    _HASH_FEED_CACHE["mtime"] = mtime
    _HASH_FEED_CACHE["entries"] = entries
    return entries


def _load_local_url_feed() -> Dict[str, Dict[str, str]]:
    path = os.environ.get("SECA_URL_FEED", "").strip()
    if not path:
        generated_path = os.path.join(os.path.dirname(__file__), "generated_kaggle_url_feed.txt")
        curated_path = os.path.join(os.path.dirname(__file__), "local_threat_urls.txt")
        path = generated_path if os.path.exists(generated_path) else curated_path
    if not os.path.exists(path):
        return {"exact": {}, "domains": {}}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {"exact": {}, "domains": {}}
    if _URL_FEED_CACHE["path"] == path and _URL_FEED_CACHE["mtime"] == mtime:
        return {"exact": _URL_FEED_CACHE["exact"], "domains": _URL_FEED_CACHE["domains"]}

    exact_entries: Dict[str, str] = {}
    domain_entries: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [part.strip() for part in line.split(",", 2)]
                candidate = parts[0]
                threat_type = parts[1] if len(parts) > 1 and parts[1] else "malicious-url"
                if candidate.lower().startswith("domain:"):
                    domain = candidate.split(":", 1)[1].strip().lower().strip(".")
                    if domain:
                        domain_entries[domain] = threat_type
                    continue
                normalized = _normalize_scan_url(candidate)
                if not normalized:
                    continue
                exact_entries[normalized] = threat_type
    except Exception as exc:
        logger.warning("Failed to load local URL feed from %s: %s", path, exc)
        exact_entries = {}
        domain_entries = {}

    _URL_FEED_CACHE["path"] = path
    _URL_FEED_CACHE["mtime"] = mtime
    _URL_FEED_CACHE["exact"] = exact_entries
    _URL_FEED_CACHE["domains"] = domain_entries
    return {"exact": exact_entries, "domains": domain_entries}


def _get_cached_reputation(db: Session, provider: str, lookup_key: str) -> Optional[Dict[str, Any]]:
    now = datetime.utcnow()
    row = (
        db.query(ExternalReputationCache)
        .filter(
            ExternalReputationCache.provider == provider,
            ExternalReputationCache.lookup_key == lookup_key,
            ExternalReputationCache.expires_at > now,
        )
        .order_by(ExternalReputationCache.updated_at.desc())
        .first()
    )
    if not row:
        return None
    payload = None
    if row.payload:
        try:
            payload = json.loads(row.payload)
        except Exception:
            payload = None
    return {
        "status": row.status,
        "payload": payload,
    }


def _set_cached_reputation(
    db: Session,
    provider: str,
    lookup_key: str,
    status: str,
    payload: Optional[Dict[str, Any]],
    ttl_seconds: int,
) -> None:
    expires_at = datetime.utcnow() + timedelta(seconds=max(60, ttl_seconds))
    row = (
        db.query(ExternalReputationCache)
        .filter(
            ExternalReputationCache.provider == provider,
            ExternalReputationCache.lookup_key == lookup_key,
        )
        .first()
    )
    encoded_payload = json.dumps(payload) if payload is not None else None
    if row is None:
        row = ExternalReputationCache(
            provider=provider,
            lookup_key=lookup_key,
            status=status,
            payload=encoded_payload,
            expires_at=expires_at,
        )
        db.add(row)
    else:
        row.status = status
        row.payload = encoded_payload
        row.expires_at = expires_at
    try:
        db.flush()
    except Exception:
        db.rollback()


def _lookup_malwarebazaar_cached(db: Session, hash_value: str) -> Optional[Dict[str, Any]]:
    normalized = (hash_value or "").strip().lower()
    cache_key = normalized
    cached = _get_cached_reputation(db, "malwarebazaar", cache_key)
    if cached:
        if cached["status"] == "hit":
            return cached["payload"] or {"found": True}
        if cached["status"] == "miss":
            return {"found": False}
        return None

    result = _lookup_malwarebazaar(normalized)
    ttl = 86400 if result and result.get("found") else 21600
    if result is not None:
        _set_cached_reputation(db, "malwarebazaar", cache_key, "hit" if result.get("found") else "miss", result, ttl)
    return result


def _lookup_circl_hashlookup_cached(db: Session, hash_value: str, hash_type: str) -> Optional[Dict[str, Any]]:
    normalized = (hash_value or "").strip().lower()
    cache_key = f"{hash_type}:{normalized}"
    cached = _get_cached_reputation(db, "circl-hashlookup", cache_key)
    if cached:
        if cached["status"] == "hit":
            return cached["payload"] or {"found": True}
        if cached["status"] == "miss":
            return {"found": False}
        return None

    result = _lookup_circl_hashlookup(normalized, hash_type)
    ttl = 604800 if result and result.get("found") else 86400
    if result is not None:
        _set_cached_reputation(db, "circl-hashlookup", cache_key, "hit" if result.get("found") else "miss", result, ttl)
    return result


def _collect_yara_rule_files(rule_dir: str) -> List[str]:
    collected: List[str] = []
    if not rule_dir or not os.path.isdir(rule_dir):
        return collected
    for root, _, files in os.walk(rule_dir):
        for filename in files:
            lower_name = filename.lower()
            if not (lower_name.endswith(".yar") or lower_name.endswith(".yara")):
                continue
            if lower_name in YARA_EXT_VAR_EXCLUDED_FILES:
                continue
            collected.append(os.path.join(root, filename))
    return sorted(set(collected))


def _http_json_request(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 4.0,
) -> Optional[Any]:
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=request_headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "ignore").strip()
    return json.loads(raw) if raw else None


def _normalize_hash_type(hash_value: str) -> Optional[str]:
    normalized = (hash_value or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", normalized):
        return "md5"
    if re.fullmatch(r"[a-f0-9]{40}", normalized):
        return "sha1"
    if re.fullmatch(r"[a-f0-9]{64}", normalized):
        return "sha256"
    return None


def _lookup_malwarebazaar(hash_value: str) -> Optional[Dict[str, Any]]:
    if not SECA_MALWAREBAZAAR_ENABLED:
        return None
    if not SECA_MALWAREBAZAAR_API_KEY:
        return None
    normalized = (hash_value or "").strip().lower()
    if _normalize_hash_type(normalized) is None:
        return None

    payload = urlencode({
        "query": "get_info",
        "hash": normalized,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "SECA/1.0",
    }
    if SECA_MALWAREBAZAAR_API_KEY:
        headers["Auth-Key"] = SECA_MALWAREBAZAAR_API_KEY

    try:
        req = urllib.request.Request(
            SECA_MALWAREBAZAAR_API_URL,
            data=payload,
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=SECA_MALWAREBAZAAR_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", "ignore").strip()
        parsed = json.loads(raw) if raw else {}
    except Exception as exc:
        logger.warning("MalwareBazaar lookup failed for %s: %s", normalized[:16], exc)
        return None

    if not isinstance(parsed, dict):
        return None

    query_status = str(parsed.get("query_status") or "").lower()
    data = parsed.get("data")
    if query_status in {"hash_not_found", "no_results", "illegal_hash"}:
        return {"found": False, "queryStatus": query_status}
    if not isinstance(data, list) or not data:
        return {"found": False, "queryStatus": query_status or "empty"}

    item = next((entry for entry in data if isinstance(entry, dict)), None)
    if item is None:
        return {"found": False, "queryStatus": query_status or "empty"}

    signature = str(item.get("signature") or "").strip() or None
    file_name = str(item.get("file_name") or "").strip() or None
    tags = [str(tag).strip() for tag in (item.get("tags") or []) if str(tag).strip()]
    return {
        "found": True,
        "queryStatus": query_status or "ok",
        "sha256": str(item.get("sha256_hash") or item.get("sha256") or "").strip().lower() or None,
        "sha1": str(item.get("sha1_hash") or item.get("sha1") or "").strip().lower() or None,
        "md5": str(item.get("md5_hash") or item.get("md5") or "").strip().lower() or None,
        "signature": signature,
        "firstSeen": str(item.get("first_seen") or "").strip() or None,
        "fileName": file_name,
        "fileType": str(item.get("file_type") or item.get("file_type_mime") or "").strip() or None,
        "deliveryMethod": str(item.get("delivery_method") or "").strip() or None,
        "tags": tags,
    }


def _lookup_circl_hashlookup(hash_value: str, hash_type: str) -> Optional[Dict[str, Any]]:
    if not SECA_HASHLOOKUP_ENABLED:
        return None
    normalized = (hash_value or "").strip().lower()
    if hash_type not in {"md5", "sha1", "sha256"}:
        return None
    try:
        payload = _http_json_request(
            f"{SECA_HASHLOOKUP_API_URL}/lookup/{hash_type}/{normalized}",
            headers={"Accept": "application/json", "User-Agent": "SECA/1.0"},
            timeout=SECA_HASHLOOKUP_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"found": False}
        logger.warning("CIRCL hashlookup failed for %s (%s): %s", normalized[:16], hash_type, exc)
        return None
    except Exception as exc:
        logger.warning("CIRCL hashlookup failed for %s (%s): %s", normalized[:16], hash_type, exc)
        return None

    if not isinstance(payload, dict):
        return {"found": False}
    product = payload.get("ProductCode") if isinstance(payload.get("ProductCode"), dict) else {}
    op_system = payload.get("OpSystemCode") if isinstance(payload.get("OpSystemCode"), dict) else {}
    return {
        "found": True,
        "db": str(payload.get("db") or "").strip() or None,
        "fileName": str(payload.get("FileName") or "").strip() or None,
        "fileSize": str(payload.get("FileSize") or "").strip() or None,
        "md5": str(payload.get("MD5") or "").strip().lower() or None,
        "sha1": str(payload.get("SHA-1") or "").strip().lower() or None,
        "productName": str(product.get("ProductName") or "").strip() or None,
        "productVersion": str(product.get("ProductVersion") or "").strip() or None,
        "applicationType": str(product.get("ApplicationType") or "").strip() or None,
        "osName": str(op_system.get("OpSystemName") or "").strip() or None,
    }


def _verify_windows_authenticode(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    result = {
        "checked": False,
        "available": False,
        "isSigned": False,
        "status": None,
        "statusMessage": None,
        "subject": None,
        "issuer": None,
        "thumbprint": None,
        "notBefore": None,
        "notAfter": None,
        "isOSBinary": False,
        "error": None,
    }
    if not SECA_AUTHENTICODE_ENABLED or os.name != "nt":
        return result

    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi"} and not file_bytes.startswith(b"MZ"):
        return result

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext or ".bin") as handle:
            handle.write(file_bytes)
            temp_path = handle.name

        escaped_path = temp_path.replace("'", "''")
        ps_script = (
            f"$sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
            "$cert = $sig.SignerCertificate; "
            "[pscustomobject]@{"
            "Status = [string]$sig.Status; "
            "StatusMessage = [string]$sig.StatusMessage; "
            "IsOSBinary = [bool]$sig.IsOSBinary; "
            "SignerCertificate = if ($cert) { [pscustomobject]@{ "
            "Subject = [string]$cert.Subject; "
            "Issuer = [string]$cert.Issuer; "
            "Thumbprint = [string]$cert.Thumbprint; "
            "NotBefore = if ($cert.NotBefore) { $cert.NotBefore.ToString('o') } else { '' }; "
            "NotAfter = if ($cert.NotAfter) { $cert.NotAfter.ToString('o') } else { '' } "
            "} } else { $null } "
            "} | ConvertTo-Json -Compress -Depth 4"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=SECA_AUTHENTICODE_TIMEOUT_SECONDS,
            check=False,
        )
        if completed.returncode != 0:
            result["error"] = (completed.stderr or completed.stdout or "PowerShell signature check failed").strip()[:240]
            return result

        raw = (completed.stdout or "").strip()
        if not raw:
            result["error"] = "Empty Authenticode response"
            return result

        parsed = json.loads(raw)
        cert = parsed.get("SignerCertificate") if isinstance(parsed, dict) else None
        result.update({
            "checked": True,
            "available": True,
            "status": str(parsed.get("Status") or "").strip() or None,
            "statusMessage": str(parsed.get("StatusMessage") or "").strip() or None,
            "isOSBinary": bool(parsed.get("IsOSBinary")),
        })
        if isinstance(cert, dict):
            result.update({
                "isSigned": True,
                "subject": str(cert.get("Subject") or "").strip() or None,
                "issuer": str(cert.get("Issuer") or "").strip() or None,
                "thumbprint": str(cert.get("Thumbprint") or "").strip() or None,
                "notBefore": str(cert.get("NotBefore") or "").strip() or None,
                "notAfter": str(cert.get("NotAfter") or "").strip() or None,
            })
        return result
    except Exception as exc:
        result["error"] = str(exc)[:240]
        return result
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _clamav_scan_via_clamscan(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    ext = os.path.splitext(filename or "")[1]
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext or ".bin") as handle:
            handle.write(file_bytes)
            temp_path = handle.name

        command = [SECA_CLAMSCAN_PATH, "--stdout", "--no-summary"]
        if SECA_CLAMAV_DETECT_PUA:
            command.append("--detect-pua=yes")
        command.append(temp_path)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SECA_CLAMAV_TIMEOUT_SECONDS,
            check=False,
        )
        output = "\n".join(part for part in [completed.stdout, completed.stderr] if part).strip()
        if completed.returncode == 0:
            return {
                "checked": True,
                "available": True,
                "engine": "clamscan",
                "found": False,
                "signature": None,
                "rawResult": output or "OK",
                "error": None,
            }
        if completed.returncode == 1:
            match = re.search(r":\s*(.+?)\s+FOUND", output)
            signature = match.group(1).strip() if match else "FOUND"
            return {
                "checked": True,
                "available": True,
                "engine": "clamscan",
                "found": True,
                "signature": signature,
                "rawResult": output,
                "error": None,
            }
        return {
            "checked": False,
            "available": False,
            "engine": "clamscan",
            "found": False,
            "signature": None,
            "rawResult": output,
            "error": output[:240] if output else f"clamscan failed with code {completed.returncode}",
        }
    except FileNotFoundError:
        return {
            "checked": False,
            "available": False,
            "engine": "clamscan",
            "found": False,
            "signature": None,
            "rawResult": None,
            "error": f"clamscan not found at {SECA_CLAMSCAN_PATH}",
        }
    except Exception as exc:
        return {
            "checked": False,
            "available": False,
            "engine": "clamscan",
            "found": False,
            "signature": None,
            "rawResult": None,
            "error": str(exc)[:240],
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _clamav_scan_via_clamd(file_bytes: bytes) -> Dict[str, Any]:
    try:
        with socket.create_connection((SECA_CLAMD_HOST, SECA_CLAMD_PORT), timeout=SECA_CLAMAV_TIMEOUT_SECONDS) as sock:
            sock.settimeout(SECA_CLAMAV_TIMEOUT_SECONDS)
            sock.sendall(b"zINSTREAM\0")
            chunk_size = 16384
            for index in range(0, len(file_bytes), chunk_size):
                chunk = file_bytes[index:index + chunk_size]
                sock.sendall(len(chunk).to_bytes(4, byteorder="big"))
                sock.sendall(chunk)
            sock.sendall((0).to_bytes(4, byteorder="big"))
            response = sock.recv(4096).decode("utf-8", "ignore").strip()
        if response.endswith("OK"):
            return {
                "checked": True,
                "available": True,
                "engine": "clamd",
                "found": False,
                "signature": None,
                "rawResult": response,
                "error": None,
            }
        match = re.search(r":\s*(.+?)\s+FOUND", response)
        if match:
            return {
                "checked": True,
                "available": True,
                "engine": "clamd",
                "found": True,
                "signature": match.group(1).strip(),
                "rawResult": response,
                "error": None,
            }
        return {
            "checked": False,
            "available": False,
            "engine": "clamd",
            "found": False,
            "signature": None,
            "rawResult": response,
            "error": response[:240] if response else "clamd returned no response",
        }
    except Exception as exc:
        return {
            "checked": False,
            "available": False,
            "engine": "clamd",
            "found": False,
            "signature": None,
            "rawResult": None,
            "error": str(exc)[:240],
        }


def _run_clamav_scan(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    result = {
        "checked": False,
        "available": False,
        "engine": None,
        "found": False,
        "signature": None,
        "rawResult": None,
        "error": None,
    }
    if not SECA_CLAMAV_ENABLED:
        return result

    modes = [SECA_CLAMAV_MODE]
    if SECA_CLAMAV_MODE == "auto":
        modes = ["clamd", "clamscan"]

    last_error = None
    for mode in modes:
        if mode == "clamd":
            current = _clamav_scan_via_clamd(file_bytes)
        elif mode == "clamscan":
            current = _clamav_scan_via_clamscan(file_bytes, filename)
        else:
            continue
        if current.get("checked") or current.get("available"):
            return current
        last_error = current.get("error")

    result["error"] = last_error or "No ClamAV engine available"
    return result


def _hash_reputation_lookup(db: Session, md5_hex: str, sha1_hex: str, sha256_hex_value: str) -> Dict[str, Any]:
    detections = 0
    engines = 0
    malware_family = None
    evidence: List[str] = []
    sources: List[str] = []
    provider_details: Dict[str, Any] = {}
    checked_hashes = [hash_value.lower() for hash_value in [md5_hex, sha1_hex, sha256_hex_value] if hash_value]

    local_feed = _load_local_hash_feed()
    local_match = None
    for h in checked_hashes:
        if h in local_feed:
            local_match = h
            malware_family = local_feed[h]
            break
    if local_match:
        detections += 1
        engines += 1
        sources.append("local-hash-feed")
        evidence.append(f"Hash matched local feed ({local_match[:12]}...)")

    historical_hits = 0
    if checked_hashes:
        historical_hits = (
            db.query(Scan)
            .filter(
                Scan.scan_type == "hash",
                Scan.target.in_(checked_hashes),
                Scan.status.in_(["malicious", "suspicious"]),
            )
            .count()
        )
    if historical_hits:
        detections += min(25, historical_hits)
        engines += min(10, max(1, historical_hits))
        sources.append("historical-hash-scans")
        evidence.append(f"Hash seen in {historical_hits} previous hash scan(s)")

    file_scan_hits = 0
    file_hash_clauses = [Scan.details.ilike(f"%{hash_value}%") for hash_value in checked_hashes]
    if file_hash_clauses:
        file_scan_hits = (
            db.query(Scan)
            .filter(
                Scan.scan_type == "file",
                Scan.status.in_(["malicious", "suspicious"]),
                or_(*file_hash_clauses),
            )
            .count()
        )
    if file_scan_hits:
        detections += min(15, file_scan_hits)
        engines += min(8, max(1, file_scan_hits // 2 + 1))
        sources.append("historical-file-scans")
        evidence.append(f"Hash fingerprint seen in {file_scan_hits} previous file scan(s)")

    if sha256_hex_value and db.query(ThreatUrl).filter(ThreatUrl.url_hash == sha256_hex_value.lower()).first():
        detections += 1
        engines += 1
        sources.append("threat-feed-collision")
        evidence.append("SHA-256 collides with an existing threat-feed hash entry")

    malware_bazaar_hit = None
    for candidate in checked_hashes:
        malware_bazaar_hit = _lookup_malwarebazaar_cached(db, candidate)
        if malware_bazaar_hit and malware_bazaar_hit.get("found"):
            break
    if malware_bazaar_hit and malware_bazaar_hit.get("found"):
        provider_details["malwareBazaar"] = malware_bazaar_hit
        detections += 1
        engines += 1
        sources.append("malwarebazaar")
        malware_family = malware_family or malware_bazaar_hit.get("signature") or malware_family
        family_label = malware_bazaar_hit.get("signature") or "unknown family"
        first_seen = malware_bazaar_hit.get("firstSeen")
        evidence_line = f"MalwareBazaar matched hash as {family_label}"
        if first_seen:
            evidence_line += f" (first seen {first_seen})"
        evidence.append(evidence_line)

    circl_hit = None
    for candidate in checked_hashes:
        hash_type = _normalize_hash_type(candidate)
        if not hash_type:
            continue
        lookup = _lookup_circl_hashlookup_cached(db, candidate, hash_type)
        if lookup and lookup.get("found"):
            circl_hit = lookup
            break
    if circl_hit and circl_hit.get("found"):
        provider_details["circlHashlookup"] = circl_hit
        sources.append("circl-hashlookup")
        file_name = circl_hit.get("fileName") or "known software file"
        evidence.append(f"CIRCL hashlookup matched known file {file_name}")

    database_match = detections > 0
    if database_match and malware_family is None:
        malware_family = "unknown"
    return {
        "databaseMatch": database_match,
        "detections": detections,
        "engines": max(1, engines) if database_match else 0,
        "malwareFamily": malware_family,
        "sources": sorted(set(sources)),
        "evidence": evidence,
        "knownGoodMatch": bool(circl_hit and circl_hit.get("found")),
        "knownGoodName": circl_hit.get("fileName") if circl_hit else None,
        "knownGoodProduct": circl_hit.get("productName") if circl_hit else None,
        "providerDetails": provider_details,
        "firstSeen": malware_bazaar_hit.get("firstSeen") if malware_bazaar_hit and malware_bazaar_hit.get("found") else None,
    }


def _default_yara_rules() -> str:
    return r"""
rule SECA_High_Encoded_PowerShell
{
    strings:
        $a = "powershell -enc" nocase ascii wide
        $b = "frombase64string" nocase ascii wide
    condition:
        any of them
}

rule SECA_Medium_Script_Execution
{
    strings:
        $a = "cmd.exe /c" nocase ascii wide
        $b = "wscript.exe" nocase ascii wide
        $c = "cscript.exe" nocase ascii wide
        $d = "mshta.exe" nocase ascii wide
    condition:
        1 of them
}

rule SECA_High_Process_Injection
{
    strings:
        $a = "CreateRemoteThread" nocase ascii wide
        $b = "WriteProcessMemory" nocase ascii wide
        $c = "VirtualAllocEx" nocase ascii wide
    condition:
        2 of them
}
"""


def _get_compiled_yara_rules() -> Tuple[Optional[Any], str, Optional[str]]:
    if yara is None:
        return None, "disabled", "yara-python is not installed"

    custom_path = os.environ.get("SECA_YARA_RULES_PATH", "").strip()
    if custom_path and os.path.exists(custom_path):
        cache_key = f"path:{custom_path}:{os.path.getmtime(custom_path)}"
        source_label = f"custom:{custom_path}"
        if os.path.isdir(custom_path):
            filepaths = {
                f"rule_{index}": path
                for index, path in enumerate(_collect_yara_rule_files(custom_path), start=1)
            }
            rule_source = None
        else:
            with open(custom_path, "r", encoding="utf-8") as handle:
                rule_source = handle.read()
            filepaths = None
    elif SECA_YARA_RULES_DIR and os.path.isdir(SECA_YARA_RULES_DIR):
        rule_files = _collect_yara_rule_files(SECA_YARA_RULES_DIR)
        filepaths = {
            f"rule_{index}": path
            for index, path in enumerate(rule_files, start=1)
        }
        mtime_sum = 0.0
        for path in rule_files:
            try:
                mtime_sum += os.path.getmtime(path)
            except OSError:
                continue
        cache_key = f"dir:{SECA_YARA_RULES_DIR}:{len(rule_files)}:{mtime_sum}"
        source_label = f"curated:{SECA_YARA_RULES_DIR}"
        rule_source = None
    else:
        rule_source = _default_yara_rules()
        cache_key = f"default:{hashlib.sha256(rule_source.encode('utf-8')).hexdigest()}"
        source_label = "builtin"
        filepaths = None

    if _YARA_CACHE["key"] == cache_key and _YARA_CACHE["rules"] is not None:
        return _YARA_CACHE["rules"], source_label, None

    try:
        if filepaths:
            compiled = yara.compile(filepaths=filepaths, externals=YARA_EXTERNAL_VARIABLE_DEFAULTS)
        else:
            compiled = yara.compile(source=rule_source)
        _YARA_CACHE["key"] = cache_key
        _YARA_CACHE["rules"] = compiled
        _YARA_CACHE["source"] = source_label
        _YARA_CACHE["error"] = None
        return compiled, source_label, None
    except Exception as exc:
        _YARA_CACHE["key"] = cache_key
        _YARA_CACHE["rules"] = None
        _YARA_CACHE["source"] = source_label
        _YARA_CACHE["error"] = str(exc)
        return None, source_label, str(exc)


def _build_yara_externals(file_bytes: bytes, filename: Optional[str] = None, content_type: Optional[str] = None) -> Dict[str, Any]:
    ext = os.path.splitext(filename or "")[1].lower()
    values = dict(YARA_EXTERNAL_VARIABLE_DEFAULTS)
    values["filename"] = os.path.basename(filename or "")
    values["filepath"] = values["filename"]
    values["extension"] = ext
    values["filetype"] = (content_type or "").lower() or ("pe" if file_bytes.startswith(b"MZ") else "")
    values["md5"] = hashlib.md5(file_bytes).hexdigest()
    values["magic"] = file_bytes[:4].hex() if file_bytes else ""
    if pefile is not None and file_bytes.startswith(b"MZ"):
        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            values["imphash"] = pe.get_imphash() or ""
            values["internal_filename"] = (
                getattr(getattr(pe, "FileInfo", [{}])[0], "StringTable", [{}])[0].entries.get(b"InternalName", b"").decode(errors="ignore")
                if hasattr(pe, "FileInfo") and pe.FileInfo
                else ""
            )
        except Exception:
            pass
    return values


def _run_yara_scan(file_bytes: bytes, filename: Optional[str] = None, content_type: Optional[str] = None) -> Dict[str, Any]:
    rules, source_label, err = _get_compiled_yara_rules()
    if rules is not None:
        try:
            matches = rules.match(
                data=file_bytes,
                timeout=15,
                externals=_build_yara_externals(file_bytes, filename=filename, content_type=content_type),
            )
            names = sorted({m.rule for m in matches})
            return {
                "enabled": True,
                "source": source_label,
                "matches": names,
                "error": None,
            }
        except Exception as exc:
            err = str(exc)

    # Fallback matcher so the hook still returns deterministic signal.
    lowered = file_bytes.lower()
    fallback_rules = {
        "SECA_Fallback_Encoded_PowerShell": [b"powershell -enc", b"frombase64string"],
        "SECA_Fallback_Script_Exec": [b"cmd.exe /c", b"wscript.exe", b"cscript.exe", b"mshta.exe"],
        "SECA_Fallback_Process_Injection": [b"createremotethread", b"writeprocessmemory", b"virtualallocex"],
    }
    fallback_matches: List[str] = []
    for rule_name, patterns in fallback_rules.items():
        if any(pattern in lowered for pattern in patterns):
            fallback_matches.append(rule_name)
    return {
        "enabled": False,
        "source": source_label,
        "matches": fallback_matches,
        "error": err or "yara-python unavailable; using fallback matcher",
    }


def _analyze_pe_metadata(file_bytes: bytes) -> Dict[str, Any]:
    result = {
        "is_pe": file_bytes.startswith(b"MZ"),
        "score": 0,
        "imports": [],
        "anomalies": [],
        "packer_detected": None,
        "high_entropy_sections": 0,
    }
    if not result["is_pe"]:
        return result
    if pefile is None:
        result["anomalies"].append("PE header detected but pefile module is unavailable")
        result["score"] += 4
        return result

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )
        section_count = len(pe.sections or [])
        if section_count >= 8:
            result["anomalies"].append(f"High section count ({section_count})")
            result["score"] += 6

        imports: List[str] = []
        suspicious_import_hits: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (entry.dll or b"").decode(errors="ignore").lower()
                if dll_name:
                    imports.append(dll_name)
                    if dll_name in SUSPICIOUS_DLL_IMPORTS:
                        suspicious_import_hits.append(dll_name)
                for imported in entry.imports:
                    if not imported.name:
                        continue
                    api = imported.name.decode(errors="ignore").lower()
                    imports.append(api)
                    if api in SUSPICIOUS_API_IMPORTS:
                        suspicious_import_hits.append(api)

        imports = sorted(set(imports))
        result["imports"] = imports[:60]
        if suspicious_import_hits:
            unique_hits = sorted(set(suspicious_import_hits))
            result["anomalies"].append(f"Suspicious imports: {', '.join(unique_hits[:8])}")
            result["score"] += min(20, 4 + len(unique_hits) * 2)

        packed_section_names = []
        for section in pe.sections:
            sec_name = (section.Name or b"").decode(errors="ignore").strip("\x00").lower()
            sec_entropy = float(section.get_entropy() or 0.0)
            if sec_entropy >= 7.2:
                result["high_entropy_sections"] += 1
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writable = bool(section.Characteristics & 0x80000000)
            if is_executable and is_writable:
                result["anomalies"].append(f"RWX section detected: {sec_name or 'unnamed'}")
                result["score"] += 8
            if sec_name in {".upx0", ".upx1", ".upx2", "upx0", "upx1"}:
                packed_section_names.append(sec_name)

        if result["high_entropy_sections"] >= 2:
            result["anomalies"].append(f"{result['high_entropy_sections']} high-entropy PE sections")
            result["score"] += min(20, 6 + result["high_entropy_sections"] * 3)
        if packed_section_names:
            result["packer_detected"] = "UPX or UPX-like section layout"
            result["score"] += 10

    except Exception as exc:
        result["anomalies"].append(f"PE parse error: {str(exc)[:120]}")
        result["score"] += 5

    result["score"] = min(40, int(result["score"]))
    return result


def _build_file_scan_result(filename: str, content_type: Optional[str], file_bytes: bytes, db: Session) -> Dict[str, Any]:
    file_size = len(file_bytes)
    ext = os.path.splitext(filename or "")[1].lower()
    risk_category, base_risk = _classify_file_category(filename, content_type)

    sample = _sample_bytes(file_bytes, 2 * 1024 * 1024)
    entropy = round(_calculate_entropy(sample), 2)
    strings_sample = _sample_bytes(file_bytes, 1024 * 1024)
    ascii_strings = _extract_ascii_strings(strings_sample, min_len=4, limit=5000)
    lowered_strings = [s.lower() for s in ascii_strings]

    md5_hex = hashlib.md5(file_bytes).hexdigest()
    sha1_hex = hashlib.sha1(file_bytes).hexdigest()
    sha256_hex_value = hashlib.sha256(file_bytes).hexdigest()

    hash_info = _hash_reputation_lookup(db, md5_hex, sha1_hex, sha256_hex_value)
    yara_info = _run_yara_scan(file_bytes, filename=filename, content_type=content_type)
    pe_info = _analyze_pe_metadata(file_bytes)
    signature_info = _verify_windows_authenticode(file_bytes, filename)
    clamav_info = _run_clamav_scan(file_bytes, filename)

    suspicious_strings = sorted(
        {
            pattern
            for pattern in SUSPICIOUS_STRING_PATTERNS
            if any(pattern in extracted for extracted in lowered_strings)
        }
    )[:12]

    threats: List[Dict[str, str]] = []
    score_breakdown: List[Dict[str, Any]] = []
    score = base_risk
    score_breakdown.append({"label": "file-category", "weight": base_risk, "reason": risk_category})

    if hash_info["databaseMatch"]:
        hash_weight = 78 if any(source in {"local-hash-feed", "malwarebazaar"} for source in hash_info.get("sources", [])) else 48
        score += hash_weight
        score_breakdown.append({"label": "malicious-hash-reputation", "weight": hash_weight, "reason": ", ".join(hash_info.get("sources", []))})
        threats.append(
            {
                "name": "Known.Hash.Reputation",
                "severity": "high",
                "description": "; ".join(hash_info["evidence"])[:200] or "Hash matched known malicious reputation data",
            }
        )
    elif hash_info.get("knownGoodMatch"):
        good_weight = -12
        score += good_weight
        score_breakdown.append({"label": "known-good-reference", "weight": good_weight, "reason": hash_info.get("knownGoodName") or "known software"})

    if yara_info["matches"]:
        high_match = any("High" in rule for rule in yara_info["matches"])
        yara_weight = min(34, (14 if high_match else 8) + len(yara_info["matches"]) * (6 if high_match else 4))
        score += yara_weight
        score_breakdown.append({"label": "yara-matches", "weight": yara_weight, "reason": ", ".join(yara_info["matches"][:4])})
        threats.append(
            {
                "name": "YARA.Rule.Match",
                "severity": "high" if high_match else "medium",
                "description": f"Matched rules: {', '.join(yara_info['matches'][:4])}",
            }
        )
    if clamav_info["found"]:
        clam_signature = str(clamav_info.get("signature") or "FOUND")
        is_pua = clam_signature.upper().startswith("PUA.")
        clam_weight = 28 if is_pua else 82
        score += clam_weight
        score_breakdown.append({"label": "clamav-signature", "weight": clam_weight, "reason": clam_signature})
        threats.append(
            {
                "name": "ClamAV.Signature.Match",
                "severity": "medium" if is_pua else "high",
                "description": clam_signature,
            }
        )
    if suspicious_strings:
        strings_weight = min(18, len(suspicious_strings) * (3 if risk_category in {"executable", "script"} else 2))
        score += strings_weight
        score_breakdown.append({"label": "suspicious-strings", "weight": strings_weight, "reason": ", ".join(suspicious_strings[:4])})
        threats.append(
            {
                "name": "Suspicious.String.Patterns",
                "severity": "medium",
                "description": f"Detected string patterns: {', '.join(suspicious_strings[:4])}",
            }
        )
    if pe_info["score"] > 0:
        pe_weight = min(26, int(pe_info["score"]))
        score += pe_weight
        score_breakdown.append({"label": "pe-anomalies", "weight": pe_weight, "reason": "; ".join(pe_info["anomalies"][:2]) or "pe metadata"})
        threats.append(
            {
                "name": "PE.Metadata.Anomaly",
                "severity": "high" if pe_weight >= 18 else "medium",
                "description": "; ".join(pe_info["anomalies"][:3]) or "Potentially suspicious PE metadata",
            }
        )
    if signature_info["checked"] and signature_info["status"] not in {None, "Valid", "NotSigned"}:
        signature_weight = 16 if signature_info["status"] in {"HashMismatch", "NotTrusted"} else 10
        score += signature_weight
        score_breakdown.append({"label": "invalid-signature", "weight": signature_weight, "reason": signature_info["status"]})
        threats.append(
            {
                "name": "Code.Signature.Invalid",
                "severity": "high" if signature_info["status"] in {"HashMismatch", "NotTrusted"} else "medium",
                "description": signature_info["statusMessage"] or f"Authenticode status: {signature_info['status']}",
            }
        )
    elif signature_info["checked"] and signature_info["status"] == "Valid":
        valid_signature_weight = -8 if not hash_info["databaseMatch"] else -3
        if signature_info.get("isOSBinary"):
            valid_signature_weight -= 4
        score += valid_signature_weight
        score_breakdown.append({
            "label": "trusted-signature",
            "weight": valid_signature_weight,
            "reason": signature_info.get("subject") or "valid authenticode",
        })
    if clamav_info.get("checked") and not clamav_info.get("found"):
        score_breakdown.append({
            "label": "clamav-clean-scan",
            "weight": 0,
            "reason": clamav_info.get("engine") or "clamav",
        })

    if entropy > 7.4 and risk_category in {"executable", "script"}:
        entropy_weight = 14 if entropy >= 7.8 else 8
        score += entropy_weight
        score_breakdown.append({"label": "high-entropy", "weight": entropy_weight, "reason": f"entropy={entropy}"})
        threats.append(
            {
                "name": "High.Entropy.Content",
                "severity": "medium",
                "description": f"File entropy is high ({entropy}) and may indicate packing/obfuscation",
            }
        )

    score = max(0, min(100, int(score)))
    high_severity_count = sum(1 for threat in threats if threat.get("severity") == "high")
    if hash_info["databaseMatch"] and any(source in {"local-hash-feed", "malwarebazaar"} for source in hash_info.get("sources", [])):
        status = "malicious"
    elif score >= 75 or (score >= 60 and high_severity_count >= 2):
        status = "malicious"
    elif score >= 38 or high_severity_count >= 1 or (len(threats) >= 2 and score >= 28):
        status = "suspicious"
    else:
        status = "clean"

    layer2_hashes = {
        "md5": md5_hex,
        "sha1": sha1_hex,
        "sha256": sha256_hex_value,
        "databaseMatch": bool(hash_info["databaseMatch"]),
        "detections": int(hash_info["detections"]),
        "engines": int(hash_info["engines"]),
        "malwareFamily": hash_info.get("malwareFamily"),
        "sources": hash_info.get("sources", []),
        "evidence": hash_info.get("evidence", []),
        "knownGoodMatch": bool(hash_info.get("knownGoodMatch")),
        "knownGoodName": hash_info.get("knownGoodName"),
        "knownGoodProduct": hash_info.get("knownGoodProduct"),
        "firstSeen": hash_info.get("firstSeen"),
        "providerDetails": hash_info.get("providerDetails", {}),
    }
    analysis_warnings: List[str] = []
    if yara_info["error"]:
        analysis_warnings.append(f"YARA unavailable: {yara_info['error']}")

    is_code_like = risk_category in {"executable", "script"}
    obfuscated_flag = bool((entropy > 7.4 and is_code_like) or pe_info["high_entropy_sections"] >= 2)

    layer4_code = {
        "suspiciousStrings": suspicious_strings,
        "packerDetected": pe_info["packer_detected"],
        "obfuscated": obfuscated_flag,
        "imports": pe_info["imports"],
        "anomalies": pe_info["anomalies"],
        "yaraMatches": yara_info["matches"],
        "yaraEnabled": yara_info["enabled"],
        "yaraSource": yara_info["source"],
        "signature": signature_info,
        "clamav": clamav_info,
    }
    details = {
        "fileName": filename,
        "fileSize": file_size,
        "fileType": content_type or "application/octet-stream",
        "layers": {
            "layer1_info": {
                "fileName": filename,
                "fileSize": file_size,
                "fileType": content_type or "application/octet-stream",
                "entropy": entropy,
                "extension": ext,
                "riskCategory": risk_category,
            },
            "layer2_hashes": layer2_hashes,
            "layer3_threats": {
                "threats": threats,
                "totalScore": min(100, score),
            },
            "layer4_code": layer4_code,
        },
        "analysisMeta": {
            "scanner": "backend-static-v2",
            "timestamp": datetime.utcnow().isoformat(),
            "hashEvidence": hash_info.get("evidence", []),
            "analysisWarnings": analysis_warnings,
            "scoreBreakdown": score_breakdown,
        },
    }
    return {"status": status, "threat_score": score, "details": details}


# ============= STANDARD ENDPOINTS =============

@app.get("/")
async def root():
    return {
        "message": "Security Analyzer API",
        "status": "running",
        "version": "2.0.0",
        "database": "connected",
        "features": ["4-layer URL scanning", "PhishTank integration", "Admin access control"]
    }


@app.post("/scan")
async def scan_file(
        file: UploadFile = File(...),
        scan_type: str = Form("file"),
        status: Optional[str] = Form(None),
        threat_score: Optional[str] = Form(None),
        details: Optional[str] = Form(None),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        file_bytes = await file.read()
        computed = _build_file_scan_result(
            filename=file.filename or "uploaded.bin",
            content_type=file.content_type,
            file_bytes=file_bytes,
            db=db,
        )
        final_status = computed["status"]
        final_score = int(computed["threat_score"])
        final_details = computed["details"]

        scan = Scan(
            user_id=current_user.id,
            scan_type=scan_type,
            target=file.filename,
            status=final_status,
            threat_score=final_score,
            details=json.dumps(final_details)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        create_audit_log(db, current_user.id, "File Scan", f"Scanned {file.filename}")
        return {
            "success": True,
            "scan_id": scan.id,
            "status": final_status,
            "threat_score": final_score,
            "details": final_details,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/url-scan")
async def scan_url(
        scan_type: str = Form(...),
        target: str = Form(...),
        status: str = Form(...),
        threat_score: int = Form(...),
        details: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        scan = Scan(
            user_id=current_user.id,
            scan_type=scan_type,
            target=target,
            status=status,
            threat_score=threat_score,
            details=details
        )
        db.add(scan)
        db.commit()
        create_audit_log(db, current_user.id, "URL Scan", f"Scanned {target}")
        return {"success": True, "scan_id": scan.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/hash-scan")
async def scan_hash(
        scan_type: str = Form(...),
        target: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        normalized_target = (target or "").strip().lower()
        hash_type = _normalize_hash_type(normalized_target)
        if hash_type is None:
            raise HTTPException(status_code=400, detail="Unsupported hash format. Use MD5, SHA-1, or SHA-256.")

        hash_info = _hash_reputation_lookup(
            db,
            normalized_target if hash_type == "md5" else "",
            normalized_target if hash_type == "sha1" else "",
            normalized_target if hash_type == "sha256" else "",
        )

        threat_score = 0
        status = "clean"
        strong_malicious_sources = {"local-hash-feed", "malwarebazaar", "threat-feed-collision"}
        matched_sources = set(hash_info.get("sources", []))
        if hash_info["databaseMatch"] and matched_sources.intersection(strong_malicious_sources):
            threat_score = min(100, 78 + min(18, hash_info["detections"] * 4))
            status = "malicious"
        elif hash_info["databaseMatch"]:
            threat_score = min(100, 42 + min(25, hash_info["detections"] * 4))
            status = "suspicious"
        elif hash_info.get("knownGoodMatch"):
            threat_score = 0
            status = "clean"

        details_payload = {
            "hash": normalized_target,
            "hashType": hash_type.upper(),
            "found": bool(hash_info["databaseMatch"]),
            "detections": int(hash_info["detections"]),
            "engines": int(hash_info["engines"]),
            "malwareFamily": hash_info.get("malwareFamily") or "None",
            "firstSeen": hash_info.get("firstSeen"),
            "sources": hash_info.get("sources", []),
            "evidence": hash_info.get("evidence", []),
            "knownGoodMatch": bool(hash_info.get("knownGoodMatch")),
            "knownGoodName": hash_info.get("knownGoodName"),
            "knownGoodProduct": hash_info.get("knownGoodProduct"),
            "providerDetails": hash_info.get("providerDetails", {}),
        }

        scan = Scan(
            user_id=current_user.id,
            scan_type=scan_type,
            target=normalized_target,
            status=status,
            threat_score=threat_score,
            details=json.dumps(details_payload)
        )
        db.add(scan)
        db.commit()
        create_audit_log(db, current_user.id, "Hash Check", f"Checked {normalized_target[:16]}...")
        return {
            "success": True,
            "scan_id": scan.id,
            "status": status,
            "threat_score": threat_score,
            "details": details_payload,
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans")
async def get_scans(
        current_user: User = Depends(get_current_user),
        scan_type: Optional[str] = Query(None),
        status: Optional[str] = Query(None),
        limit: int = Query(100, le=500),
        include_details: bool = Query(False),
        db: Session = Depends(get_db)
):
    try:
        query = db.query(Scan)

        # Non-admins see only their own scans; admins see all
        if not current_user.is_admin:
            query = query.filter(Scan.user_id == current_user.id)

        if scan_type:
            query = query.filter(Scan.scan_type == scan_type)
        if status:
            query = query.filter(Scan.status == status)

        scans = query.order_by(Scan.created_at.desc()).limit(limit).all()

        response = []
        for s in scans:
            row = {
                "id": s.id,
                "user_id": s.user_id,
                "scan_type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "threat_score": s.threat_score,
                "created_at": s.created_at.isoformat(),
            }
            if include_details:
                row["details"] = s.details
            response.append(row)

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/stats")
async def get_scan_stats(
        current_user: User = Depends(get_current_user),
        scan_type: Optional[str] = Query(None),
        db: Session = Depends(get_db)
):
    try:
        base_query = db.query(Scan)

        # Non-admin users only see their own stats
        if not current_user.is_admin:
            base_query = base_query.filter(Scan.user_id == current_user.id)

        if scan_type:
            base_query = base_query.filter(Scan.scan_type == scan_type)

        total = base_query.count()
        clean = base_query.filter(Scan.status == "clean").count()
        malicious = base_query.filter(Scan.status == "malicious").count()
        suspicious = base_query.filter(Scan.status == "suspicious").count()

        return {
            "total": total,
            "clean": clean,
            "malicious": malicious,
            "suspicious": suspicious,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans/{scan_id}")
async def get_scan_by_id(
        scan_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        query = db.query(Scan).filter(Scan.id == scan_id)
        if not current_user.is_admin:
            query = query.filter(Scan.user_id == current_user.id)

        scan = query.first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status,
            "threat_score": scan.threat_score,
            "details": scan.details,
            "created_at": scan.created_at.isoformat(),
            "user_id": scan.user_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/log")
async def gateway_log_ingest(
        event: Dict[str, Any],
        x_gateway_token: Optional[str] = Header(None, alias="X-Gateway-Token"),
        db: Session = Depends(get_db)
):
    """Ingest proxy events (allow/block) from the gateway proxy."""
    _require_gateway_ingest_token(x_gateway_token)

    try:
        normalized = _record_gateway_event_sync(event, db=db)
    except Exception as exc:
        logger.exception("Failed to persist gateway audit event: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to persist gateway event")

    return {"ok": True, "event": normalized}


@app.get("/gateway/api/history")
async def gateway_api_history(
        limit: int = Query(200, ge=1, le=1000),
        current_user: User = Depends(require_admin)
):
    admin_department = str(current_user.department or "").strip()
    admin_group = str(current_user.group_name or "").strip()
    rows = list(gateway_history)
    if admin_department and admin_group:
        rows = [
            row for row in rows
            if str(row.get("department") or "").strip() == admin_department
            and str(row.get("group_name") or "").strip() == admin_group
        ]
    return rows[:limit]


def _gateway_history_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text_value = str(value).strip()
    if not text_value:
        return None
    try:
        return datetime.fromisoformat(text_value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _gateway_history_host(row: Dict[str, Any]) -> str:
    direct_host = str(row.get("host") or "").strip().lower()
    if direct_host:
        return direct_host

    for candidate in (row.get("scan_url"), row.get("target")):
        candidate_text = str(candidate or "").strip()
        if not candidate_text:
            continue

        if "://" in candidate_text:
            parsed = urlparse(candidate_text)
            if parsed.hostname:
                return parsed.hostname.strip().lower()

        trimmed = candidate_text.split("/", 1)[0]
        if ":" in trimmed:
            trimmed = trimmed.split(":", 1)[0]
        trimmed = trimmed.strip().lower()
        if trimmed:
            return trimmed

    return "unknown-host"


@app.get("/monitoring/proxy-usage-stats")
async def monitoring_proxy_usage_stats(
        period: str = Query("week"),
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db),
):
    period_windows = {
        "day": 1,
        "3days": 3,
        "week": 7,
        "month": 30,
    }
    if period not in period_windows:
        raise HTTPException(status_code=400, detail="Invalid monitoring period")

    admin_department = str(current_user.department or "").strip()
    admin_group = str(current_user.group_name or "").strip()
    if not admin_department or not admin_group:
        return {
            "period": period,
            "days": period_windows[period],
            "generated_at": datetime.utcnow().isoformat(),
            "group_summary": {
                "department": admin_department,
                "group_name": admin_group,
                "request_count": 0,
                "blocked_count": 0,
                "allowed_count": 0,
                "unique_sites": 0,
                "unique_members": 0,
            },
            "top_sites": [],
            "member_stats": [],
            "group_stats": [],
            "daily_stats": [],
        }

    cutoff = datetime.utcnow() - timedelta(days=period_windows[period])
    department_rows = [
        row for row in list(gateway_history)
        if str(row.get("department") or "").strip() == admin_department
    ]
    scoped_rows = []
    scoped_department_rows = []
    for row in department_rows:
        row_ts = _gateway_history_timestamp(row.get("timestamp"))
        if not row_ts or row_ts < cutoff:
            continue
        scoped_department_rows.append(row)
        if str(row.get("group_name") or "").strip() == admin_group:
            scoped_rows.append(row)

    members = (
        db.query(User)
        .filter(
            User.department == admin_department,
            User.group_name == admin_group,
            User.is_admin.is_(False),
        )
        .order_by(User.first_name.asc(), User.last_name.asc(), User.email.asc())
        .all()
    )

    member_stats_map: Dict[str, Dict[str, Any]] = {}
    top_sites_counter: Counter[str] = Counter()
    top_sites_blocked: Counter[str] = Counter()
    top_sites_allowed: Counter[str] = Counter()
    top_sites_members: Dict[str, set] = defaultdict(set)
    top_sites_last_seen: Dict[str, str] = {}
    group_stats_map: Dict[str, Dict[str, Any]] = {}
    daily_bucket_map: Dict[str, Dict[str, Any]] = {}

    for member in members:
        member_name = _desktop_user_display_name(member)
        member_stats_map[f"user:{member.id}"] = {
            "user_id": member.id,
            "email": member.email,
            "name": member_name,
            "request_count": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "unique_sites": set(),
            "top_sites": Counter(),
            "last_seen": None,
        }

    for row in scoped_department_rows:
        host = _gateway_history_host(row)
        blocked = bool(row.get("blocked"))
        timestamp = _gateway_history_timestamp(row.get("timestamp"))
        timestamp_text = timestamp.isoformat() if timestamp else None
        user_id = row.get("user_id")
        user_email = str(row.get("user_email") or "").strip() or None
        user_name = str(row.get("user_name") or "").strip() or user_email or "Unassigned"
        group_name = str(row.get("group_name") or "").strip() or "Unassigned group"

        group_bucket = group_stats_map.setdefault(
            group_name,
            {
                "group_name": group_name,
                "department": admin_department,
                "request_count": 0,
                "blocked_count": 0,
                "allowed_count": 0,
                "unique_sites": set(),
                "unique_members": set(),
                "top_sites": Counter(),
                "last_seen": None,
            },
        )
        group_bucket["request_count"] += 1
        if blocked:
            group_bucket["blocked_count"] += 1
        else:
            group_bucket["allowed_count"] += 1
        group_bucket["unique_sites"].add(host)
        group_bucket["top_sites"][host] += 1
        if user_id is not None or user_email or user_name:
            group_bucket["unique_members"].add(
                f"user:{user_id}" if user_id is not None else f"email:{(user_email or user_name).lower()}"
            )
        if timestamp_text and (not group_bucket["last_seen"] or str(group_bucket["last_seen"]) < timestamp_text):
            group_bucket["last_seen"] = timestamp_text

        if group_name == admin_group:
            member_key = f"user:{user_id}" if user_id is not None else f"email:{(user_email or user_name).lower()}"
            if member_key not in member_stats_map:
                member_stats_map[member_key] = {
                    "user_id": user_id,
                    "email": user_email,
                    "name": user_name,
                    "request_count": 0,
                    "blocked_count": 0,
                    "allowed_count": 0,
                    "unique_sites": set(),
                    "top_sites": Counter(),
                    "last_seen": None,
                }

            member_row = member_stats_map[member_key]
            member_row["request_count"] += 1
            if blocked:
                member_row["blocked_count"] += 1
            else:
                member_row["allowed_count"] += 1
            member_row["top_sites"][host] += 1
            member_row["unique_sites"].add(host)
            if timestamp_text:
                if not member_row["last_seen"] or str(member_row["last_seen"]) < timestamp_text:
                    member_row["last_seen"] = timestamp_text

            top_sites_counter[host] += 1
            if blocked:
                top_sites_blocked[host] += 1
            else:
                top_sites_allowed[host] += 1
            top_sites_members[host].add(member_key)
            if timestamp_text and (host not in top_sites_last_seen or top_sites_last_seen[host] < timestamp_text):
                top_sites_last_seen[host] = timestamp_text

            if timestamp:
                bucket_key = timestamp.strftime("%Y-%m-%d")
                bucket = daily_bucket_map.setdefault(
                    bucket_key,
                    {
                        "date": bucket_key,
                        "request_count": 0,
                        "blocked_count": 0,
                        "allowed_count": 0,
                        "unique_sites": set(),
                        "unique_members": set(),
                    },
                )
                bucket["request_count"] += 1
                if blocked:
                    bucket["blocked_count"] += 1
                else:
                    bucket["allowed_count"] += 1
                bucket["unique_sites"].add(host)
                bucket["unique_members"].add(member_key)

    top_sites = [
        {
            "host": host,
            "request_count": count,
            "blocked_count": int(top_sites_blocked.get(host, 0)),
            "allowed_count": int(top_sites_allowed.get(host, 0)),
            "unique_members": len(top_sites_members.get(host, set())),
            "last_seen": top_sites_last_seen.get(host),
        }
        for host, count in top_sites_counter.most_common(15)
    ]

    member_stats = []
    for data in member_stats_map.values():
        top_member_sites = [
            {
                "host": host,
                "request_count": count,
            }
            for host, count in data["top_sites"].most_common(8)
        ]
        member_stats.append(
            {
                "user_id": data["user_id"],
                "email": data["email"],
                "name": data["name"],
                "request_count": int(data["request_count"]),
                "blocked_count": int(data["blocked_count"]),
                "allowed_count": int(data["allowed_count"]),
                "unique_sites": len(data["unique_sites"]),
                "last_seen": data["last_seen"],
                "top_sites": top_member_sites,
            }
        )

    member_stats.sort(
        key=lambda item: (
            -int(item["request_count"]),
            str(item["name"]).lower(),
        )
    )

    daily_stats = []
    for key in sorted(daily_bucket_map.keys()):
        bucket = daily_bucket_map[key]
        daily_stats.append(
            {
                "date": bucket["date"],
                "request_count": int(bucket["request_count"]),
                "blocked_count": int(bucket["blocked_count"]),
                "allowed_count": int(bucket["allowed_count"]),
                "unique_sites": len(bucket["unique_sites"]),
                "unique_members": len(bucket["unique_members"]),
            }
        )

    group_stats = []
    for data in group_stats_map.values():
        group_stats.append(
            {
                "group_name": data["group_name"],
                "department": data["department"],
                "request_count": int(data["request_count"]),
                "blocked_count": int(data["blocked_count"]),
                "allowed_count": int(data["allowed_count"]),
                "unique_sites": len(data["unique_sites"]),
                "unique_members": len(data["unique_members"]),
                "last_seen": data["last_seen"],
                "top_sites": [
                    {"host": host, "request_count": count}
                    for host, count in data["top_sites"].most_common(12)
                ],
            }
        )

    group_stats.sort(
        key=lambda item: (
            -int(item["request_count"]),
            str(item["group_name"]).lower(),
        )
    )

    return {
        "period": period,
        "days": period_windows[period],
        "generated_at": datetime.utcnow().isoformat(),
        "group_summary": {
            "department": admin_department,
            "group_name": admin_group,
            "request_count": sum(int(item["request_count"]) for item in member_stats),
            "blocked_count": sum(int(item["blocked_count"]) for item in member_stats),
            "allowed_count": sum(int(item["allowed_count"]) for item in member_stats),
            "unique_sites": len(top_sites_counter),
            "unique_members": len([item for item in member_stats if int(item["request_count"]) > 0]),
        },
        "top_sites": top_sites,
        "member_stats": member_stats,
        "group_stats": group_stats,
        "daily_stats": daily_stats,
    }


@app.get("/gateway/api/stats")
async def gateway_api_stats(current_user: User = Depends(require_admin)):
    del current_user
    with gateway_state_lock:
        requests_by_ip = dict(gateway_clients)
        methods = dict(gateway_method_counts)
        total_events = len(gateway_history)
        unique_clients = len(gateway_devices)
        blocked = gateway_blocked_count
        allowed = gateway_allowed_count
    return {
        "total_events": total_events,
        "unique_clients": unique_clients,
        "blocked_requests": blocked,
        "allowed_requests": allowed,
        "methods": methods,
        "requests_by_ip": requests_by_ip,
    }


@app.get("/gateway/api/devices")
async def gateway_api_devices(current_user: User = Depends(require_admin)):
    del current_user
    with gateway_state_lock:
        now_ts = time.time()
        all_ips = set(gateway_devices.keys()) | set(gateway_client_last_activity.keys()) | set(gateway_active_connections.keys())
        devices = []
        for ip in all_ips:
            device = dict(gateway_devices.get(ip, {"client_ip": ip, "device_name": _get_or_create_device_alias(ip)}))
            connected = _is_client_online_locked(ip, now_ts)
            activity_online = _is_client_activity_online_locked(ip, now_ts)
            device["connected"] = connected
            device["activity_online"] = activity_online
            device["activity_offline"] = not activity_online
            device["activity_timeout_seconds"] = SECA_PROXY_ACTIVE_WINDOW_SECONDS
            device["active_connections"] = gateway_active_connections.get(ip, 0)
            last_activity = gateway_client_last_activity.get(ip, 0.0)
            device["seconds_since_last_activity"] = int(max(0.0, now_ts - last_activity)) if last_activity > 0 else None
            session = _active_desktop_session_for_client_ip(ip)
            if session:
                device["desktop_session_id"] = session.get("session_id")
                device["user_id"] = session.get("user_id")
                device["user_name"] = session.get("user_name")
                device["user_email"] = session.get("email")
                device["department"] = session.get("department")
                device["group_name"] = session.get("group_name")
                device["hostname"] = session.get("hostname")
                assignment = _group_proxy_assignment_for_scope(session.get("department"), session.get("group_name"))
                if assignment:
                    device["assigned_proxy_host"] = assignment.proxy_host
                    device["assigned_proxy_port"] = assignment.proxy_port
            devices.append(device)
    devices.sort(key=lambda d: (not bool(d.get("connected")), -(int(d.get("total_requests", 0) or 0))), reverse=False)
    return devices


@app.get("/gateway/api/device-logs/{client_ip}")
async def gateway_api_device_logs(
        client_ip: str,
        current_user: User = Depends(require_admin),
        limit: int = Query(300, ge=1, le=1000),
        db: Session = Depends(get_db)
):
    del current_user
    query = (
        db.query(AuditLog)
        .filter(
            or_(
                AuditLog.details.ilike(f"%client={client_ip}%"),
                AuditLog.details.ilike(f"%({client_ip})%"),
            )
        )
        .order_by(AuditLog.timestamp.desc())
    )
    logs = query.limit(limit).all()

    return [{
        "id": l.id,
        "user_id": l.user_id,
        "action": l.action,
        "details": l.details,
        "timestamp": l.timestamp.isoformat() if l.timestamp else None,
    } for l in logs]


def _gateway_proxy_health_payload() -> Dict[str, Any]:
    sockets = proxy_server.sockets if proxy_server else None
    running = bool(sockets)
    if not running:
        probe_host = SECA_PROXY_LISTEN_HOST
        if probe_host in {"0.0.0.0", "::", ""}:
            probe_host = "127.0.0.1"
        try:
            with socket.create_connection((probe_host, SECA_PROXY_LISTEN_PORT), timeout=0.25):
                running = True
        except OSError:
            running = False
    with gateway_state_lock:
        connected_devices = len(_connected_client_ips_locked())
        total_events = len(gateway_history)
    return {
        "running": running,
        "autostart": SECA_PROXY_AUTOSTART,
        "listen_host": SECA_PROXY_LISTEN_HOST,
        "listen_port": SECA_PROXY_LISTEN_PORT,
        "static_scan_delay_ms": SECA_PROXY_STATIC_SCAN_DELAY_MS,
        "static_audit_sync": SECA_PROXY_STATIC_AUDIT_SYNC,
        "tls_intercept_enabled": SECA_PROXY_TLS_INTERCEPT,
        "tls_intercept_ready": _proxy_tls_intercept_ready(),
        "connected_devices": connected_devices,
        "total_events": total_events,
        "started_at": gateway_started_at.isoformat(),
        "uptime_seconds": int((datetime.utcnow() - gateway_started_at).total_seconds()),
    }


@app.post("/gateway/proxy/start")
async def gateway_proxy_start(current_user: User = Depends(require_admin)):
    del current_user

    task = getattr(app.state, "proxy_task", None)
    if task is None or task.done():
        app.state.proxy_task = asyncio.create_task(start_embedded_proxy())

    # Give asyncio a brief moment to bind and expose sockets.
    await asyncio.sleep(0.2)

    health = _gateway_proxy_health_payload()
    if not health["running"]:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Proxy failed to start on {SECA_PROXY_LISTEN_HOST}:{SECA_PROXY_LISTEN_PORT}. "
                "Check whether the port is already in use."
            ),
        )
    return health


@app.post("/gateway/proxy/stop")
async def gateway_proxy_stop(current_user: User = Depends(require_admin)):
    global proxy_server
    del current_user

    task = getattr(app.state, "proxy_task", None)
    if proxy_server is not None:
        proxy_server.close()
        await proxy_server.wait_closed()
        proxy_server = None

    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Proxy task ended with error during stop: %s", exc)

    app.state.proxy_task = None
    return _gateway_proxy_health_payload()


@app.get("/gateway/proxy/health")
async def gateway_proxy_health(current_user: User = Depends(require_admin)):
    del current_user
    return _gateway_proxy_health_payload()


@app.get("/gateway/stream")
async def gateway_stream(current_user: User = Depends(require_admin)):
    del current_user

    async def event_gen():
        last_seen = -1
        while True:
            if len(gateway_history) and len(gateway_history) != last_seen:
                last_seen = len(gateway_history)
                payload = json.dumps(gateway_history[0])
                yield f"data: {payload}\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/gateway/blocklist/effective")
async def gateway_effective_blocklist(
        x_gateway_token: Optional[str] = Header(None, alias="X-Gateway-Token"),
        db: Session = Depends(get_db)
):
    _require_gateway_ingest_token(x_gateway_token)
    return {"patterns": _effective_blocklist(db)}


@app.get("/gateway/blocklist")
async def gateway_blocklist_list(
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    del current_user
    rows = db.query(ProxyBlockRule).order_by(ProxyBlockRule.created_at.desc()).all()
    return [{
        "id": r.id,
        "pattern": r.pattern,
        "enabled": r.enabled,
        "note": r.note,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    } for r in rows]


@app.get("/gateway/blocklist/suggest")
async def gateway_blocklist_suggest(
        q: str = Query("", min_length=0),
        current_user: User = Depends(require_admin)
):
    del current_user
    return _build_proxy_blocklist_suggestions(q)


@app.post("/gateway/blocklist/suggest/reindex")
async def gateway_blocklist_suggest_reindex(
        current_user: User = Depends(require_admin)
):
    del current_user
    if not _meili_enabled():
        raise HTTPException(status_code=400, detail="Meilisearch suggestion engine is not enabled")
    try:
        return _seed_meili_index()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to seed Meilisearch index: {exc}")


@app.post("/gateway/blocklist")
async def gateway_blocklist_create(
        payload: GatewayBlockRuleCreate,
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    pattern = _normalize_proxy_block_pattern(payload.pattern)
    pattern_identity = _proxy_rule_identity(pattern)

    existing = db.query(ProxyBlockRule).filter(ProxyBlockRule.pattern == pattern).first()
    if existing:
        existing.enabled = payload.enabled
        existing.note = (payload.note or "").strip() or existing.note
        db.commit()
        db.refresh(existing)
        _invalidate_proxy_blocklist_cache()
        await _reset_active_proxy_connections()
        create_audit_log(db, current_user.id, "Gateway Blocklist Re-enable", f"Updated existing rule {existing.pattern} (id={existing.id})")
        return {
            "id": existing.id,
            "pattern": existing.pattern,
            "enabled": existing.enabled,
            "note": existing.note,
            "created_at": existing.created_at.isoformat() if existing.created_at else None,
            "updated_at": existing.updated_at.isoformat() if existing.updated_at else None,
        }

    semantic_existing = next(
        (
            row for row in db.query(ProxyBlockRule).order_by(ProxyBlockRule.id.asc()).all()
            if _proxy_rule_identity(row.pattern) == pattern_identity
        ),
        None,
    )
    if semantic_existing:
        semantic_existing.pattern = pattern
        semantic_existing.enabled = payload.enabled
        semantic_existing.note = (payload.note or "").strip() or semantic_existing.note
        db.commit()
        db.refresh(semantic_existing)
        _invalidate_proxy_blocklist_cache()
        await _reset_active_proxy_connections()
        create_audit_log(
            db,
            current_user.id,
            "Gateway Blocklist Canonicalize",
            f"Updated rule family {pattern} (id={semantic_existing.id})",
        )
        return {
            "id": semantic_existing.id,
            "pattern": semantic_existing.pattern,
            "enabled": semantic_existing.enabled,
            "note": semantic_existing.note,
            "created_at": semantic_existing.created_at.isoformat() if semantic_existing.created_at else None,
            "updated_at": semantic_existing.updated_at.isoformat() if semantic_existing.updated_at else None,
        }

    row = ProxyBlockRule(pattern=pattern, note=(payload.note or "").strip() or None, enabled=payload.enabled)
    db.add(row)
    db.commit()
    db.refresh(row)
    _invalidate_proxy_blocklist_cache()
    await _reset_active_proxy_connections()

    create_audit_log(db, current_user.id, "Gateway Blocklist Add", f"Added rule {pattern}")
    return {
        "id": row.id,
        "pattern": row.pattern,
        "enabled": row.enabled,
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.patch("/gateway/blocklist/{rule_id}")
async def gateway_blocklist_update(
        rule_id: int,
        payload: GatewayBlockRuleUpdate,
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    row = db.query(ProxyBlockRule).filter(ProxyBlockRule.id == rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")

    if payload.pattern is not None:
        pattern = _normalize_proxy_block_pattern(payload.pattern)
        pattern_identity = _proxy_rule_identity(pattern)
        semantic_dupe = next(
            (
                other for other in db.query(ProxyBlockRule).filter(ProxyBlockRule.id != rule_id).order_by(ProxyBlockRule.id.asc()).all()
                if _proxy_rule_identity(other.pattern) == pattern_identity
            ),
            None,
        )
        if semantic_dupe:
            raise HTTPException(status_code=400, detail="Pattern already exists")
        row.pattern = pattern

    if payload.note is not None:
        row.note = payload.note.strip() or None

    if payload.enabled is not None:
        row.enabled = payload.enabled

    db.commit()
    db.refresh(row)
    _invalidate_proxy_blocklist_cache()
    await _reset_active_proxy_connections()
    create_audit_log(db, current_user.id, "Gateway Blocklist Update", f"Updated rule {row.pattern} (id={row.id})")

    return {
        "id": row.id,
        "pattern": row.pattern,
        "enabled": row.enabled,
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@app.delete("/gateway/blocklist/{rule_id}")
async def gateway_blocklist_delete(
        rule_id: int,
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    row = db.query(ProxyBlockRule).filter(ProxyBlockRule.id == rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")

    pattern = row.pattern
    db.delete(row)
    db.commit()
    _invalidate_proxy_blocklist_cache()
    await _reset_active_proxy_connections()
    create_audit_log(db, current_user.id, "Gateway Blocklist Delete", f"Deleted rule {pattern} (id={rule_id})")
    return {"ok": True}


@app.get("/audit")
async def get_audit_logs(
        current_user: User = Depends(get_current_user),
        target_user_id: Optional[int] = Query(None, description="Filter by user ID (admin only)"),
        sort_by: str = Query("date", pattern="^(date|action|user)$"),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        action_filter: Optional[str] = Query(None),
        start_date: Optional[str] = Query(None),
        end_date: Optional[str] = Query(None),
        limit: int = Query(100, le=500),
        db: Session = Depends(get_db)
):
    """Get audit logs with role-based access control"""
    try:
        query = db.query(AuditLog)

        # Apply user filter based on role
        if current_user.is_admin:
            if target_user_id is not None:
                query = query.filter(AuditLog.user_id == target_user_id)
        else:
            # Non-admin sees only their own logs
            query = query.filter(AuditLog.user_id == current_user.id)

        # Apply other filters
        if action_filter:
            query = query.filter(AuditLog.action == action_filter)

        if start_date:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp >= start)

        if end_date:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp <= end)

        # Apply sorting
        if sort_by == "date":
            sort_column = AuditLog.timestamp
        elif sort_by == "action":
            sort_column = AuditLog.action
        elif sort_by == "user":
            sort_column = AuditLog.user_id
        else:
            sort_column = AuditLog.timestamp

        if order == "desc":
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        logs = query.limit(limit).all()
        user_ids = sorted({l.user_id for l in logs if l.user_id is not None})
        user_email_map: Dict[int, str] = {}
        if user_ids:
            users = db.query(User.id, User.email).filter(User.id.in_(user_ids)).all()
            user_email_map = {u.id: u.email for u in users}

        response = []
        for l in logs:
            user_email = user_email_map.get(l.user_id)
            if user_email:
                user_name = user_email.split("@", 1)[0]
            elif l.user_id is None:
                user_name = "System"
            else:
                user_name = f"User #{l.user_id}"
            response.append({
                "id": l.id,
                "user_id": l.user_id,
                "user_email": user_email,
                "user_name": user_name,
                "action": l.action,
                "details": l.details,
                "timestamp": l.timestamp.isoformat()
            })

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users")
async def get_users(
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    """Get all users (admin only)"""
    users = db.query(User).all()
    return [{
        "id": u.id,
        "email": u.email,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "sex": u.sex,
        "department": u.department,
        "group_name": u.group_name,
        "role": u.role,
        "is_admin": u.is_admin,
        "created_at": u.created_at.isoformat()
    } for u in users]


@app.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info"""
    logger.info("/me endpoint called")
    return {
        "id": current_user.id,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "sex": current_user.sex,
        "department": current_user.department,
        "group_name": current_user.group_name,
        "role": current_user.role,
        "is_admin": current_user.is_admin
    }


@app.get("/desktop/session/config")
async def get_desktop_session_config(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    assignment = None
    if bool(current_user.is_admin):
        assignment = _group_proxy_assignment_for_scope(current_user.department, current_user.group_name, db=db)
    return {
        "heartbeat_interval_seconds": SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS,
        "heartbeat_timeout_seconds": SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS,
        "retention_seconds": SECA_DESKTOP_SESSION_RETENTION_SECONDS,
        "user_id": current_user.id,
        "department": current_user.department,
        "group_name": current_user.group_name,
        "proxy_assignment": {
            "proxy_host": assignment.proxy_host,
            "proxy_port": assignment.proxy_port,
            "enabled": assignment.enabled,
        } if assignment else None,
    }


@app.get("/desktop/proxy-assignment")
async def get_current_group_proxy_assignment(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    if not bool(current_user.is_admin):
        return {"assignment": None}
    assignment = _group_proxy_assignment_for_scope(current_user.department, current_user.group_name, db=db)
    if not assignment:
        return {"assignment": None}
    return {
        "assignment": {
            "department": assignment.department,
            "group_name": assignment.group_name,
            "proxy_host": assignment.proxy_host,
            "proxy_port": assignment.proxy_port,
            "enabled": assignment.enabled,
            "note": assignment.note,
        }
    }


@app.post("/desktop/session/heartbeat")
async def desktop_session_heartbeat(
        payload: DesktopSessionHeartbeat,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    assignment = None
    if bool(current_user.is_admin):
        assignment = _group_proxy_assignment_for_scope(current_user.department, current_user.group_name, db=db)
    client_host = request.client.host if request.client else None
    session, created = await asyncio.to_thread(_touch_desktop_session, current_user, payload, client_host)
    return {
        "ok": True,
        "created": created,
        "session": session,
        "heartbeat_interval_seconds": SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS,
        "heartbeat_timeout_seconds": SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS,
        "proxy_assignment": {
            "proxy_host": assignment.proxy_host,
            "proxy_port": assignment.proxy_port,
            "enabled": assignment.enabled,
        } if assignment else None,
    }


@app.post("/desktop/session/stop")
async def desktop_session_stop(
        payload: DesktopSessionStop,
        current_user: User = Depends(get_current_user)
):
    session = await asyncio.to_thread(_stop_desktop_session, current_user, payload)
    return {
        "ok": True,
        "session": session,
    }


@app.get("/monitoring/desktop/sessions")
async def monitoring_desktop_sessions(
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    return {
        "sessions": _collect_persisted_desktop_sessions_for_admin(current_user, db),
        "heartbeat_interval_seconds": SECA_DESKTOP_HEARTBEAT_INTERVAL_SECONDS,
        "heartbeat_timeout_seconds": SECA_DESKTOP_HEARTBEAT_TIMEOUT_SECONDS,
    }


@app.get("/monitoring/group-proxy-assignment")
async def monitoring_group_proxy_assignment(
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    assignment = _group_proxy_assignment_for_scope(current_user.department, current_user.group_name, db=db)
    if not assignment:
        return {"assignment": None}
    return {
        "assignment": {
            "department": assignment.department,
            "group_name": assignment.group_name,
            "proxy_host": assignment.proxy_host,
            "proxy_port": assignment.proxy_port,
            "enabled": assignment.enabled,
            "note": assignment.note,
        }
    }


@app.get("/test")
async def test():
    return {"message": "ok"}


@app.get("/phishtank/check")
async def check_phishtank(
        url: str,
        db: Session = Depends(get_db)
):
    """Check URL against imported threat feed and PhishTank table."""
    try:
        normalized_url = url.strip()
        url_hash = sha256_hex(normalized_url)

        threat_entry = db.query(ThreatUrl).filter(ThreatUrl.url_hash == url_hash).first()
        if threat_entry:
            return {
                "found": True,
                "source": threat_entry.source or "threat-feed",
                "verified": bool(threat_entry.verified),
                "threat_type": threat_entry.threat_type,
            }

        entry = db.query(PhishTankEntry).filter(PhishTankEntry.url == normalized_url).first()
        if entry:
            return {
                "found": True,
                "verified": entry.verified,
                "phish_id": entry.phish_id,
                "submission_time": entry.submission_time.isoformat() if entry.submission_time else None
            }
        return {"found": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-feed/stats")
async def threat_feed_stats(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Return threat-feed and scan counters for UI insights."""
    try:
        total_threat_urls = db.query(ThreatUrl).count()
        verified_threat_urls = db.query(ThreatUrl).filter(ThreatUrl.verified.is_(True)).count()
        unique_domains = db.query(ThreatUrl.domain).filter(ThreatUrl.domain.isnot(None)).distinct().count()
        phishtank_entries = db.query(PhishTankEntry).count()

        total_scans = db.query(Scan).count()
        malicious_scans = db.query(Scan).filter(Scan.status == "malicious").count()
        suspicious_scans = db.query(Scan).filter(Scan.status == "suspicious").count()
        clean_scans = db.query(Scan).filter(Scan.status == "clean").count()

        return {
            "total_threat_urls": total_threat_urls,
            "verified_threat_urls": verified_threat_urls,
            "unique_domains": unique_domains,
            "phishtank_entries": phishtank_entries,
            "scan_totals": {
                "total": total_scans,
                "malicious": malicious_scans,
                "suspicious": suspicious_scans,
                "clean": clean_scans,
            },
            "viewer": {
                "user_id": current_user.id,
                "is_admin": bool(current_user.is_admin),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/make-admin")
async def make_admin(
        email: str,
        current_user: User = Depends(require_admin),
        db: Session = Depends(get_db)
):
    """Make a user admin (requires existing admin)"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_admin = True
    user.role = "admin"
    db.commit()

    create_audit_log(db, current_user.id, "Admin Privilege Grant", f"Granted admin to {email}")

    return {"success": True, "message": f"{email} is now an admin"}


# ============= DYNAMIC ANALYSIS WITH WINDOWS SANDBOX =============


# ============= DYNAMIC ANALYSIS WITH WINDOWS SANDBOX =============

SANDBOX_SHARE = "C:\\sandbox_share"
os.makedirs(SANDBOX_SHARE, exist_ok=True)
KEEP_SANDBOX_OPEN = os.environ.get("SECA_KEEP_SANDBOX_OPEN", "0").strip().lower() in {
    "1", "true", "yes", "on"
}
REUSE_SANDBOX_SESSION = os.environ.get("SECA_REUSE_SANDBOX_SESSION", "0").strip().lower() in {
    "1", "true", "yes", "on"
}
AUTO_CLOSE_SANDBOX = os.environ.get("SECA_AUTO_CLOSE_SANDBOX", "1").strip().lower() in {
    "1", "true", "yes", "on"
}
if KEEP_SANDBOX_OPEN and AUTO_CLOSE_SANDBOX:
    logger.warning(
        "SECA_KEEP_SANDBOX_OPEN and SECA_AUTO_CLOSE_SANDBOX are both enabled; "
        "auto-close takes precedence."
    )
    KEEP_SANDBOX_OPEN = False
DYNAMIC_DURATION_EXEC_SECONDS = max(20, int(os.environ.get("SECA_DYNAMIC_EXEC_DURATION_SECONDS", "45")))
DYNAMIC_DURATION_SCRIPT_SECONDS = max(15, int(os.environ.get("SECA_DYNAMIC_SCRIPT_DURATION_SECONDS", "35")))
DYNAMIC_DURATION_DOC_SECONDS = max(10, int(os.environ.get("SECA_DYNAMIC_DOC_DURATION_SECONDS", "20")))
DYNAMIC_DURATION_DEFAULT_SECONDS = max(15, int(os.environ.get("SECA_DYNAMIC_DEFAULT_DURATION_SECONDS", "30")))
DYNAMIC_DONE_GRACE_SECONDS = max(20, int(os.environ.get("SECA_DYNAMIC_DONE_GRACE_SECONDS", "45")))
MONITOR_HEARTBEAT_SECONDS = max(5, int(os.environ.get("SECA_MONITOR_HEARTBEAT_SECONDS", "8")))
URL_DYNAMIC_OBSERVATION_SECONDS = min(
    90,
    max(12, int(os.environ.get("SECA_URL_DYNAMIC_OBSERVATION_SECONDS", "25"))),
)
URL_DYNAMIC_ALLOWED_DOMAINS = {
    d.strip().lower()
    for d in os.environ.get("SECA_URL_DYNAMIC_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
}
BROWSER_DYNAMIC_WAIT_MS = min(
    15000,
    max(2000, int(os.environ.get("SECA_BROWSER_DYNAMIC_WAIT_MS", "6000"))),
)
BROWSER_DYNAMIC_MAX_REQUESTS = max(
    20,
    int(os.environ.get("SECA_BROWSER_DYNAMIC_MAX_REQUESTS", "120")),
)
BROWSER_DYNAMIC_MAX_RESPONSES = max(
    20,
    int(os.environ.get("SECA_BROWSER_DYNAMIC_MAX_RESPONSES", "120")),
)
logger.info(
    "Sandbox config: reuse=%s auto_close=%s keep_open=%s heartbeat=%ss url_observation=%ss browser_wait_ms=%s allowlist_size=%s",
    REUSE_SANDBOX_SESSION,
    AUTO_CLOSE_SANDBOX,
    KEEP_SANDBOX_OPEN,
    MONITOR_HEARTBEAT_SECONDS,
    URL_DYNAMIC_OBSERVATION_SECONDS,
    BROWSER_DYNAMIC_WAIT_MS,
    len(URL_DYNAMIC_ALLOWED_DOMAINS),
)

# Job tracking: {job_id: {status, step, progress, result, error}}
_sandbox_jobs: Dict[str, Dict[str, Any]] = {}
_executor = ThreadPoolExecutor(max_workers=1)
_browser_dynamic_jobs: Dict[str, Dict[str, Any]] = {}
_browser_dynamic_executor = ThreadPoolExecutor(max_workers=1)
DYNAMIC_JOB_RETENTION_SECONDS = max(
    60,
    int(os.environ.get("SECA_DYNAMIC_JOB_RETENTION_SECONDS", "900"))
)
DYNAMIC_JOB_MAX_TRACKED = max(
    20,
    int(os.environ.get("SECA_DYNAMIC_JOB_MAX_TRACKED", "250"))
)
SANDBOX_PROCESS_NAMES = (
    "WindowsSandbox",
    "WindowsSandboxClient",
    "WindowsSandboxRemoteSession",
    "WindowsSandboxServer",
    "codex-windows-sandbox",
)
SANDBOX_ACTIVE_PROCESS_NAMES = (
    "WindowsSandbox",
    "WindowsSandboxClient",
    "WindowsSandboxRemoteSession",
    "WindowsSandboxServer",
    "codex-windows-sandbox",
)
SANDBOX_AUXILIARY_PROCESS_NAMES = (
    "vmmemWindowsSandbox",
)


def _parse_iso8601(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _cleanup_terminal_sandbox_jobs() -> None:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=DYNAMIC_JOB_RETENTION_SECONDS)

    for jid, job in list(_sandbox_jobs.items()):
        if job.get("status") not in {"done", "error"}:
            continue
        finished_at = _parse_iso8601(job.get("finished_at")) or _parse_iso8601(job.get("started_at"))
        if finished_at and finished_at < cutoff:
            _sandbox_jobs.pop(jid, None)

    if len(_sandbox_jobs) <= DYNAMIC_JOB_MAX_TRACKED:
        return

    terminal_jobs: List[tuple] = []
    for jid, job in _sandbox_jobs.items():
        if job.get("status") not in {"done", "error"}:
            continue
        finished_at = _parse_iso8601(job.get("finished_at")) or _parse_iso8601(job.get("started_at")) or datetime.min
        terminal_jobs.append((finished_at, jid))

    terminal_jobs.sort(key=lambda item: item[0])
    for _, jid in terminal_jobs:
        if len(_sandbox_jobs) <= DYNAMIC_JOB_MAX_TRACKED:
            break
        _sandbox_jobs.pop(jid, None)


def _cleanup_terminal_browser_dynamic_jobs() -> None:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=DYNAMIC_JOB_RETENTION_SECONDS)

    for jid, job in list(_browser_dynamic_jobs.items()):
        if job.get("status") not in {"done", "error"}:
            continue
        finished_at = _parse_iso8601(job.get("finished_at")) or _parse_iso8601(job.get("started_at"))
        if finished_at and finished_at < cutoff:
            _browser_dynamic_jobs.pop(jid, None)

    if len(_browser_dynamic_jobs) <= DYNAMIC_JOB_MAX_TRACKED:
        return

    terminal_jobs: List[tuple] = []
    for jid, job in _browser_dynamic_jobs.items():
        if job.get("status") not in {"done", "error"}:
            continue
        finished_at = _parse_iso8601(job.get("finished_at")) or _parse_iso8601(job.get("started_at")) or datetime.min
        terminal_jobs.append((finished_at, jid))

    terminal_jobs.sort(key=lambda item: item[0])
    for _, jid in terminal_jobs:
        if len(_browser_dynamic_jobs) <= DYNAMIC_JOB_MAX_TRACKED:
            break
        _browser_dynamic_jobs.pop(jid, None)


def clean_sandbox_share():
    """Delete all files in the sandbox share folder for a clean state."""
    for entry in os.listdir(SANDBOX_SHARE):
        path = os.path.join(SANDBOX_SHARE, entry)
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            logger.error(f"Error cleaning {path}: {e}")


def _sandbox_process_name_candidates(proc_name: str) -> List[str]:
    base = proc_name.strip()
    if base.lower().endswith(".exe"):
        base = base[:-4]
    candidates = [base, f"{base}.exe"]
    unique: List[str] = []
    for name in candidates:
        if name and name not in unique:
            unique.append(name)
    return unique


def _sandbox_process_running(proc_name: str) -> bool:
    try:
        for candidate in _sandbox_process_name_candidates(proc_name):
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {candidate}"],
                capture_output=True,
                text=True,
                check=False,
            )
            output = (result.stdout or "").lower()
            if "no tasks are running" in output:
                continue
            if candidate.lower() in output:
                return True
        return False
    except Exception:
        return False


def _sandbox_alive(include_auxiliary: bool = False) -> bool:
    if include_auxiliary:
        names = SANDBOX_ACTIVE_PROCESS_NAMES + SANDBOX_AUXILIARY_PROCESS_NAMES
    else:
        names = SANDBOX_ACTIVE_PROCESS_NAMES
    return any(_sandbox_process_running(name) for name in names)


def _kill_sandbox_processes_once() -> None:
    process_names = SANDBOX_PROCESS_NAMES + SANDBOX_AUXILIARY_PROCESS_NAMES
    for proc_name in process_names:
        for candidate in _sandbox_process_name_candidates(proc_name):
            subprocess.run(
                ["taskkill", "/IM", candidate, "/F", "/T"],
                capture_output=True,
                text=True,
                check=False,
            )
    # Fallback kill path for renamed/host-specific process wrappers.
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "$names=@('WindowsSandbox','WindowsSandboxClient','WindowsSandboxRemoteSession',"
                    "'WindowsSandboxServer','codex-windows-sandbox','vmmemWindowsSandbox'); "
                    "Get-Process -ErrorAction SilentlyContinue | "
                    "Where-Object { $names -contains $_.ProcessName } | "
                    "Stop-Process -Force -ErrorAction SilentlyContinue"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        # taskkill path above is primary; powershell path is best-effort.
        pass


def close_windows_sandbox(wait_timeout_seconds: int = 25) -> bool:
    """Terminate any running Windows Sandbox process and wait until fully stopped."""
    try:
        if not _sandbox_alive(include_auxiliary=True):
            return True

        total_timeout = max(12, int(wait_timeout_seconds))
        primary_deadline = time.time() + max(8, int(total_timeout * 0.6))
        auxiliary_deadline = time.time() + total_timeout

        attempts = 3
        for attempt in range(1, attempts + 1):
            _kill_sandbox_processes_once()

            while time.time() < primary_deadline:
                if not _sandbox_alive(include_auxiliary=False):
                    break
                time.sleep(0.5)

            if not _sandbox_alive(include_auxiliary=False):
                while time.time() < auxiliary_deadline:
                    if not _sandbox_alive(include_auxiliary=True):
                        return True
                    time.sleep(0.5)
                if not _sandbox_alive(include_auxiliary=True):
                    return True
                logger.info(
                    "Sandbox guest closed but auxiliary VM memory process is still draining. "
                    "Final cleanup will continue in the background."
                )
                return False

            logger.warning("Sandbox primary processes still running after close attempt %s/%s", attempt, attempts)

        return not _sandbox_alive(include_auxiliary=True)
    except Exception as e:
        logger.error(f"Error closing sandbox: {e}")
        return False


def get_file_extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def _dynamic_observation_seconds(filename: str) -> int:
    ext = get_file_extension(filename)
    executable_exts = {".exe", ".dll", ".com", ".scr", ".pif", ".msi"}
    script_exts = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"}
    document_exts = {
        ".pdf", ".txt", ".rtf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".csv", ".json", ".xml", ".ini", ".cfg", ".log",
    }
    if ext in executable_exts:
        return DYNAMIC_DURATION_EXEC_SECONDS
    if ext in script_exts:
        return DYNAMIC_DURATION_SCRIPT_SECONDS
    if ext in document_exts:
        return DYNAMIC_DURATION_DOC_SECONDS
    return DYNAMIC_DURATION_DEFAULT_SECONDS


def _is_private_or_local_target_url(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
    except Exception:
        return True

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return True

    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    if host.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        # Hostname (non-IP): permit unless explicitly local-only style.
        return False


def _validate_dynamic_url_target(target_url: str) -> tuple[bool, str]:
    raw = (target_url or "").strip()
    if not raw:
        return False, "URL is required for dynamic analysis."

    try:
        parsed = urlparse(raw)
    except Exception:
        return False, "Invalid URL."

    if parsed.scheme not in {"http", "https"}:
        return False, "Only http:// and https:// URLs are allowed for sandbox URL analysis."

    if _is_private_or_local_target_url(raw):
        return False, "Refusing to analyze local/private network targets in sandbox URL mode."

    host = (parsed.hostname or "").strip().lower()
    if URL_DYNAMIC_ALLOWED_DOMAINS:
        host_allowed = any(
            host == allowed or host.endswith(f".{allowed}")
            for allowed in URL_DYNAMIC_ALLOWED_DOMAINS
        )
        if not host_allowed:
            return False, "URL host is not in SECA_URL_DYNAMIC_ALLOWED_DOMAINS allowlist."

    return True, ""


def _ready_marker_available(max_age_seconds: int = 3600) -> bool:
    marker = os.path.join(SANDBOX_SHARE, "sandbox_ready.txt")
    if not os.path.exists(marker):
        return False
    try:
        age = time.time() - os.path.getmtime(marker)
        return age <= max(60, max_age_seconds)
    except OSError:
        return False


def _monitor_heartbeat_recent(max_age_seconds: int = MONITOR_HEARTBEAT_SECONDS) -> bool:
    debug_log = os.path.join(SANDBOX_SHARE, "monitor_debug.txt")
    if not os.path.exists(debug_log):
        return False
    try:
        age = time.time() - os.path.getmtime(debug_log)
        return age <= max(5, max_age_seconds)
    except OSError:
        return False


DYNAMIC_PROCESS_BACKGROUND_NAMES = {
    "backgroundtaskhost", "cexecsvc", "csrss", "ctfmon", "dllhost", "dwm",
    "explorer", "fontdrvhost", "idle", "logonui", "lsaiso", "lsass",
    "memory compression", "rdpclip", "registry", "runtimebroker", "searchhost",
    "secure system", "services", "shellhost", "sihost", "smartscreen", "smss",
    "spoolsv", "startmenuexperiencehost", "svchost", "system", "taskhostw",
    "tiworker", "trustedinstaller", "vmcomputeagent", "wininit", "winlogon",
    "wmiprvse",
}
DYNAMIC_PROCESS_HIGH_RISK_NAMES = {
    "rundll32", "regsvr32", "wscript", "cscript", "mshta", "certutil",
    "bitsadmin", "wmic", "msbuild", "installutil",
}
DYNAMIC_PROCESS_CONTEXTUAL_NAMES = {"powershell", "pwsh", "cmd"}
DYNAMIC_NETWORK_WEB_PORTS = {80, 443, 8080, 8443}
DYNAMIC_NETWORK_HIGH_RISK_PORTS = {
    21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 445,
    1433, 1521, 3306, 3389, 4444, 5432, 5900, 5985, 5986,
}
DYNAMIC_DOCUMENT_EXTENSIONS = {
    ".pdf", ".txt", ".rtf", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".csv", ".json", ".xml", ".ini", ".cfg", ".log",
}


def _is_public_ip_address(value: str) -> bool:
    raw = (value or "").strip()
    if not raw:
        return False
    # Windows can emit IPv6 zone index (example: fe80::1%12).
    host = raw.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname: treat as external unless proven otherwise.
        return True
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return True


def _normalise_processes(raw) -> tuple[list, int]:
    """Convert PowerShell Get-Process JSON to frontend format."""
    results = []
    filtered_background = 0
    if not raw:
        return results, filtered_background
    if isinstance(raw, dict):
        raw = [raw]
    seen = set()
    for p in raw:
        if not isinstance(p, dict):
            continue
        name = p.get("ProcessName") or p.get("Name") or "unknown"
        base_name = str(name).lower().split(".")[0]
        if base_name in DYNAMIC_PROCESS_BACKGROUND_NAMES:
            filtered_background += 1
            continue
        pid = p.get("Id") or p.get("pid") or 0
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = 0
        dedupe_key = (pid, base_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        cpu = p.get("CPU") or 0
        action = f"Running â€” CPU: {round(float(cpu), 2)}s" if cpu else "Running"
        if base_name in DYNAMIC_PROCESS_HIGH_RISK_NAMES:
            risk_level = "high"
        elif base_name in DYNAMIC_PROCESS_CONTEXTUAL_NAMES:
            risk_level = "contextual"
            action = f"{action} (contextual shell activity)"
        else:
            risk_level = "low"
        suspicious = risk_level == "high"
        results.append(
            {
                "pid": pid,
                "name": name,
                "action": action,
                "suspicious": suspicious,
                "riskLevel": risk_level,
            }
        )
    return results, filtered_background


def _normalise_network(raw) -> tuple[list, int]:
    """Convert PowerShell Get-NetTCPConnection JSON to frontend format."""
    results = []
    filtered_background = 0
    if not raw:
        return results, filtered_background
    if isinstance(raw, dict):
        raw = [raw]
    seen = set()
    for n in raw:
        if not isinstance(n, dict):
            continue
        remote = str(n.get("RemoteAddress") or n.get("destination") or "").strip()
        if not remote or remote in {"0.0.0.0", "::", "::1", "127.0.0.1"}:
            filtered_background += 1
            continue
        port = n.get("RemotePort") or n.get("port") or 0
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 0
        proto = n.get("protocol") or "TCP"
        dedupe_key = (proto, remote, port)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        if not _is_public_ip_address(remote):
            filtered_background += 1
            continue
        is_web = port in DYNAMIC_NETWORK_WEB_PORTS
        classification = "public-web" if is_web else "public-nonweb"
        if is_web:
            network_risk = "low"
        elif port in DYNAMIC_NETWORK_HIGH_RISK_PORTS:
            network_risk = "high"
        else:
            network_risk = "medium"
        suspicious = network_risk in {"medium", "high"}
        results.append(
            {
                "protocol": proto,
                "destination": remote,
                "port": port,
                "suspicious": suspicious,
                "classification": classification,
                "networkRisk": network_risk,
            }
        )
    return results, filtered_background


def _normalise_files(raw) -> list:
    """Convert PowerShell Get-ChildItem diff JSON to frontend format."""
    results = []
    if not raw:
        return results
    if isinstance(raw, dict):
        raw = [raw]
    sensitive_dirs = ("system32", "syswow64", "startup", "appdata\\roaming", "programdata")
    for f in raw:
        if not isinstance(f, dict):
            continue
        path = f.get("FullName") or f.get("path") or ""
        action = f.get("action") or "created"
        suspicious = any(d in path.lower() for d in sensitive_dirs)
        results.append({"path": path, "action": action, "suspicious": suspicious})
    return results


def _normalise_registry(raw) -> list:
    """Convert registry change list to frontend format."""
    results = []
    if not raw:
        return results
    if isinstance(raw, dict):
        raw = [raw]
    suspicious_keys = ("\\run", "\\services", "winlogon", "\\policies", "startup")
    for r in raw:
        if not isinstance(r, dict):
            continue
        key = r.get("key") or r.get("Key") or ""
        action = r.get("action") or r.get("Action") or "write"
        suspicious = any(k in key.lower() for k in suspicious_keys)
        results.append({"key": key, "action": action, "suspicious": suspicious})
    return results


def _compute_verdict(
    processes,
    network,
    files,
    registry,
    open_action: Optional[str] = None,
    open_success: Optional[bool] = None,
    target_filename: Optional[str] = None,
    scan_mode: str = "file",
) -> tuple:
    """Weighted heuristic scoring on normalised sandbox telemetry."""
    findings = []
    action = (open_action or "").lower()
    mode = (scan_mode or "file").lower()
    is_url_mode = mode == "url"
    ext = get_file_extension(target_filename or "")
    is_document_open = action in {"msedge-pdf", "notepad", "invoke-item"} or ext in DYNAMIC_DOCUMENT_EXTENSIONS
    executable_like_actions = {"execute", "shell-open", "test"}
    executable_like_exts = {".exe", ".dll", ".com", ".scr", ".pif", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"}

    file_score = 0
    registry_score = 0
    process_score = 0
    network_score = 0
    context_score = 0
    modifier_score = 0

    # Suspicious file writes and registry activity.
    susp_files = [f for f in files if f.get("suspicious")]
    local_file_changes = [f for f in files if str(f.get("path") or "").strip()]
    susp_reg = [r for r in registry if r.get("suspicious")]
    if susp_files:
        file_score += min(22, 8 + len(susp_files) * 7)
        findings.append(f"{len(susp_files)} suspicious file system change(s)")
    elif local_file_changes and not is_url_mode:
        if action in executable_like_actions or ext in executable_like_exts:
            file_score += min(10, 4 + len(local_file_changes) * 2)
            findings.append(f"{len(local_file_changes)} local file change(s) observed during executable run")
        else:
            findings.append(f"{len(local_file_changes)} local file change(s) observed")
    if susp_reg:
        registry_score += min(34, 18 + len(susp_reg) * 8)
        findings.append(f"{len(susp_reg)} suspicious registry write(s) - possible persistence")

    high_risk_procs = [p for p in processes if p.get("riskLevel") == "high" or p.get("suspicious")]
    observed_userland_processes = [p for p in processes if str(p.get("name") or "").strip()]
    contextual_shell = [
        p
        for p in processes
        if str(p.get("name", "")).lower().split(".")[0] in DYNAMIC_PROCESS_CONTEXTUAL_NAMES
    ]
    non_web_net = [n for n in network if n.get("classification") == "public-nonweb"]
    web_net = [n for n in network if n.get("classification") == "public-web"]
    high_risk_non_web = [n for n in non_web_net if n.get("networkRisk") == "high"]

    if high_risk_procs:
        process_score += min(36, 18 + len(high_risk_procs) * 8)
        findings.append(
            f"{len(high_risk_procs)} high-risk process(es) observed: "
            + ", ".join(p["name"] for p in high_risk_procs[:8])
        )

    if (
        not is_url_mode
        and open_success is True
        and (action in executable_like_actions or ext in executable_like_exts)
    ):
        if observed_userland_processes:
            process_score += min(14, 6 + len(observed_userland_processes))
            findings.append(
                f"{len(observed_userland_processes)} runtime process(es) captured during sample execution"
            )
        else:
            process_score += 4
            findings.append(
                "Sample launch succeeded but only minimal runtime telemetry was captured"
            )

    if contextual_shell:
        if high_risk_procs or susp_files or susp_reg or non_web_net:
            context_score += min(10, 4 + len(contextual_shell) * 2)
            findings.append(f"{len(contextual_shell)} shell process(es) correlated with other suspicious indicators")
        else:
            findings.append("Contextual shell activity observed but treated as low-confidence monitor noise")

    # External network connections.
    if non_web_net:
        network_score += min(38, (26 if high_risk_non_web else 16) + len(non_web_net) * 4)
        if high_risk_non_web:
            findings.append(f"{len(high_risk_non_web)} high-risk non-web external connection(s) made")
        findings.append(f"{len(non_web_net)} non-web external connection(s) made")
        for n in non_web_net[:8]:
            findings.append(f"   -> {n['protocol']} {n['destination']}:{n['port']}")
    elif web_net:
        has_other_categories = bool(high_risk_procs or susp_files or susp_reg)
        if is_url_mode:
            findings.append(f"{len(web_net)} outbound web connection(s) observed while browsing target URL")
        elif is_document_open:
            findings.append(f"{len(web_net)} outbound web connection(s) observed during document open (filtered as likely background)")
        elif open_success is False and not has_other_categories:
            findings.append("Launch failed; outbound web traffic treated as background baseline")
        elif has_other_categories:
            network_score += min(10, 4 + len(web_net))
            findings.append(f"{len(web_net)} outbound web connection(s) alongside local suspicious indicators")
        elif action in {"execute", "test"}:
            network_score += min(8, 3 + len(web_net))
            findings.append(f"{len(web_net)} outbound web connection(s) during executable/script run")
        else:
            findings.append(f"{len(web_net)} outbound web connection(s) observed (low-confidence)")

    score = file_score + registry_score + process_score + network_score + context_score + modifier_score

    if open_success is False and not (high_risk_procs or susp_files or susp_reg or non_web_net):
        score = min(score, 8)
        findings.append("Sample launch was not successful; verdict confidence reduced")

    if is_document_open and not (high_risk_procs or susp_files or susp_reg or non_web_net):
        if open_success is False:
            findings = ["Document launch failed; no malicious behaviour observed in sandbox"]
        else:
            findings = ["Only expected document-open activity observed in sandbox"]

    if not findings:
        findings.append("No suspicious behaviour detected during sandbox execution")

    active_components = sum(
        1 for value in (file_score, registry_score, process_score, network_score, context_score) if value > 0
    )

    if susp_reg or high_risk_non_web or len(high_risk_procs) >= 2 or (high_risk_procs and susp_files):
        confidence = "high"
    elif active_components >= 2 or (high_risk_procs and web_net):
        confidence = "medium"
    else:
        confidence = "low"

    findings.insert(
        0,
        "Score breakdown: "
        f"process={process_score}, network={network_score}, filesystem={file_score}, "
        f"registry={registry_score}, context={context_score}",
    )

    if confidence == "high":
        findings.append("Signal confidence: high")
    elif confidence == "medium":
        findings.append("Signal confidence: medium")
    else:
        findings.append("Signal confidence: low")

    score = min(100, score)
    verdict = "clean"
    if score >= 72 or (confidence == "high" and score >= 58):
        verdict = "malicious"
    elif score >= 32 or (confidence == "medium" and score >= 24):
        verdict = "suspicious"
    return verdict, score, findings


def _run_sandbox_blocking(job_id: str, file_content: bytes, filename: str):
    """
    Runs entirely in a thread pool and updates _sandbox_jobs[job_id].
    Uses sandbox_runner.py trigger/inbox flow so API and direct tests share one path.
    """
    job = _sandbox_jobs[job_id]
    start_time = time.time()
    session_id = str(job.get("session_id") or job_id.replace("-", ""))

    def update(step: str, progress: int):
        job["step"] = step
        job["progress"] = progress
        logger.info(f"[job {job_id[:8]}] {step}")

    def read_json_file(path: str) -> list:
        try:
            with open(path, "rb") as handle:
                payload = handle.read()
            if not payload:
                return []
            decoded: Optional[str] = None
            for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-8"):
                try:
                    text = payload.decode(encoding).strip()
                    decoded = text
                    break
                except UnicodeDecodeError:
                    continue
            if decoded is None or not decoded:
                return []
            parsed = json.loads(decoded)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception as exc:
            logger.error(f"Failed to parse JSON file {path}: {exc}")
            return []

    sandbox_closed_in_try = False
    try:
        update("Preparing sandbox environment...", 5)
        scan_duration = _dynamic_observation_seconds(filename)
        update(f"Using observation window: {scan_duration}s", 6)
        active_monitor = _monitor_heartbeat_recent()
        reuse_existing_monitor = (
            REUSE_SANDBOX_SESSION
            and active_monitor
            and _ready_marker_available()
        )
        if reuse_existing_monitor:
            update("Reusing active sandbox session...", 8)
        elif _sandbox_alive(include_auxiliary=True):
            if not close_windows_sandbox():
                logger.warning(
                    "Could not fully stop previous Windows Sandbox session. "
                    "Will still try launching a fresh visible sandbox window."
                )

        update("Launching sandbox job...", 15)
        def is_cancel_requested() -> bool:
            return bool(job.get("cancel_requested"))

        max_attempts = 2
        retryable_reasons = {
            "sandbox-not-ready",
            "sandbox-launch-failed",
            "sandbox-exited",
            "monitor-unresponsive",
        }
        run_result: Dict[str, Any] = {}
        last_reason: Optional[str] = None
        last_diagnostics: Optional[Dict[str, Any]] = None

        for attempt in range(1, max_attempts + 1):
            attempt_session_id = session_id if attempt == 1 else f"{session_id}_retry{attempt - 1}"
            if attempt > 1:
                update("Sandbox session ended unexpectedly. Retrying with a fresh VM...", 18)
                close_windows_sandbox(wait_timeout_seconds=30)
                reuse_existing_monitor = False

            if reuse_existing_monitor:
                update("Reusing active sandbox monitor...", 20)
            else:
                update("Launching visible Windows Sandbox window...", 20)

            run_result = sandbox_run_dynamic_scan(
                file_bytes=file_content,
                filename=filename,
                duration=scan_duration,
                done_grace=DYNAMIC_DONE_GRACE_SECONDS,
                launch_wsb_file=not reuse_existing_monitor,
                allow_existing_monitor=reuse_existing_monitor,
                shutdown_after_done=not reuse_existing_monitor,
                on_progress=update,
                session_id=attempt_session_id,
                abort_if=is_cancel_requested,
            )

            if run_result.get("status") == "done":
                break

            last_reason = str(run_result.get("reason", "unknown-error"))
            raw_diagnostics = run_result.get("diagnostics")
            if isinstance(raw_diagnostics, dict):
                last_diagnostics = raw_diagnostics
            else:
                last_diagnostics = None

            if last_reason == "cancelled":
                job["status"] = "error"
                job["error"] = "Scan cancelled by user."
                job["finished_at"] = datetime.utcnow().isoformat()
                update("Scan cancelled.", max(0, job.get("progress", 0)))
                return

            if last_reason in retryable_reasons and attempt < max_attempts:
                logger.warning(
                    "Sandbox attempt %s/%s failed with reason=%s. Retrying once with fresh launch.",
                    attempt,
                    max_attempts,
                    last_reason,
                )
                continue
            break

        if run_result.get("status") != "done":
            reason = last_reason or str(run_result.get("reason", "unknown-error"))
            diagnostics = last_diagnostics if last_diagnostics is not None else run_result.get("diagnostics")
            if reason == "sandbox-not-ready":
                message = "Sandbox started but monitor did not become ready. Check C:\\sandbox_share\\monitor_debug.txt."
            elif reason == "sandbox-launch-failed":
                message = (
                    "Windows Sandbox did not launch successfully. "
                    "Verify virtualization is enabled and no stale Sandbox window is still closing."
                )
            elif reason == "sandbox-exited":
                message = (
                    "Sandbox session closed unexpectedly before artifacts were collected. "
                    "This can happen if the sample triggers logoff/shutdown."
                )
            elif reason == "scan-timeout":
                message = "Sandbox execution timed out before completion."
            elif reason == "monitor-unresponsive":
                message = "Reused sandbox monitor did not consume trigger. Retried with fresh sandbox launch."
            elif reason == "monitor-missing":
                message = "Sandbox monitor script is missing at C:\\sandbox_share\\monitor.ps1."
            else:
                message = f"Sandbox runner failed: {reason}"
            if diagnostics:
                message = f"{message} | diagnostics={json.dumps(diagnostics)}"
            raise RuntimeError(message)

        update("Reading sandbox logs...", 80)
        session = run_result.get("session")
        out_dir = run_result.get("out_dir")
        if not session or not out_dir:
            raise RuntimeError(f"Sandbox runner returned invalid output: {run_result}")

        processes_raw = read_json_file(os.path.join(out_dir, f"processes_{session}.json"))
        network_raw = read_json_file(os.path.join(out_dir, f"network_{session}.json"))
        done_raw = read_json_file(os.path.join(out_dir, f"done_{session}.json"))
        done_info = done_raw[0] if done_raw and isinstance(done_raw[0], dict) else {}

        files_raw = read_json_file(os.path.join(out_dir, f"files_{session}.json"))
        registry_raw = []

        update("Analyzing collected behaviour...", 90)
        processes, filtered_processes = _normalise_processes(processes_raw)
        network, filtered_network = _normalise_network(network_raw)
        files = _normalise_files(files_raw)
        registry = _normalise_registry(registry_raw)

        open_action = done_info.get("open_action")
        open_success = done_info.get("open_success")
        open_error = done_info.get("open_error")
        file_extension = str(done_info.get("file_extension") or "").strip().lower()
        file_category = str(done_info.get("file_category") or "").strip().lower()
        launch_process_id = done_info.get("launch_process_id")
        launch_process_name = str(done_info.get("launch_process_name") or "").strip()
        verdict, threat_score, summary = _compute_verdict(
            processes,
            network,
            files,
            registry,
            open_action=open_action,
            open_success=open_success,
            target_filename=filename,
            scan_mode="file",
        )
        processes_for_ui = processes
        network_for_ui = network
        files_for_ui = files
        registry_for_ui = registry
        if verdict == "clean":
            processes_for_ui = [p for p in processes if p.get("suspicious") or p.get("riskLevel") == "high"]
            network_for_ui = [n for n in network if n.get("suspicious") or n.get("classification") == "public-nonweb"]
            files_for_ui = [f for f in files if f.get("suspicious")]
            registry_for_ui = [r for r in registry if r.get("suspicious")]
            hidden_count = (
                max(0, len(processes) - len(processes_for_ui))
                + max(0, len(network) - len(network_for_ui))
                + max(0, len(files) - len(files_for_ui))
                + max(0, len(registry) - len(registry_for_ui))
            )
            if hidden_count > 0:
                summary.append(
                    f"Suppressed {hidden_count} low-risk telemetry event(s) from UI because verdict is clean"
                )
        if filtered_processes:
            summary.append(f"Filtered {filtered_processes} background process entries from sandbox telemetry")
        if filtered_network:
            summary.append(f"Filtered {filtered_network} local/background network entries from sandbox telemetry")
        if open_action:
            launch_state = "success" if open_success is True else "failed" if open_success is False else "unknown"
            summary.insert(0, f"Launch action: {open_action} ({launch_state})")
        if launch_process_name:
            pid_label = ""
            try:
                launch_pid_int = int(launch_process_id or 0)
                if launch_pid_int > 0:
                    pid_label = f" pid={launch_pid_int}"
            except (TypeError, ValueError):
                pid_label = ""
            summary.insert(1, f"Launched process: {launch_process_name}{pid_label}")
        if file_category:
            ext_label = file_extension or get_file_extension(filename)
            if ext_label:
                summary.insert(2, f"Sandbox opened file as {file_category} ({ext_label})")
            else:
                summary.insert(2, f"Sandbox opened file as {file_category}")
        if open_error:
            summary.append(f"Launch error: {str(open_error)[:220]}")
        duration = int(time.time() - start_time)

        if AUTO_CLOSE_SANDBOX:
            update("Shutting down sandbox VM...", 97)
            sandbox_closed_in_try = close_windows_sandbox(wait_timeout_seconds=35)
            if not sandbox_closed_in_try and _sandbox_alive(include_auxiliary=False):
                summary.append("Warning: sandbox VM did not fully close; backend will retry cleanup")

        update("Analysis complete.", 100)
        job["status"] = "done"
        job["finished_at"] = datetime.utcnow().isoformat()
        job["result"] = {
            "verdict": verdict,
            "threatScore": threat_score,
            "duration": duration,
            "openAction": open_action,
            "fileCategory": file_category,
            "fileExtension": file_extension,
            "processes": processes_for_ui,
            "network": network_for_ui,
            "files": files_for_ui,
            "registry": registry_for_ui,
            "summary": summary,
        }

    except Exception as e:
        logger.error(f"Sandbox job {job_id} failed: {e}", exc_info=True)
        job["status"] = "error"
        job["error"] = str(e)
        job["finished_at"] = datetime.utcnow().isoformat()

    finally:
        if AUTO_CLOSE_SANDBOX and not sandbox_closed_in_try:
            if not close_windows_sandbox(wait_timeout_seconds=20):
                logger.warning(
                    "Auto-close requested but sandbox processes are still running. "
                    "Manual cleanup may be required."
                )
        elif KEEP_SANDBOX_OPEN:
            logger.info("Leaving Windows Sandbox running for reuse.")


def _run_url_sandbox_blocking(job_id: str, target_url: str):
    """
    Run dynamic URL analysis in sandbox (Edge InPrivate) with strict backend policy gating.
    """
    job = _sandbox_jobs[job_id]
    start_time = time.time()
    session_id = str(job.get("session_id") or job_id.replace("-", ""))

    def update(step: str, progress: int):
        job["step"] = step
        job["progress"] = progress
        logger.info(f"[job {job_id[:8]}][url] {step}")

    def read_json_file(path: str) -> list:
        try:
            with open(path, "rb") as handle:
                payload = handle.read()
            if not payload:
                return []
            decoded: Optional[str] = None
            for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-8"):
                try:
                    text = payload.decode(encoding).strip()
                    decoded = text
                    break
                except UnicodeDecodeError:
                    continue
            if decoded is None or not decoded:
                return []
            parsed = json.loads(decoded)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception as exc:
            logger.error(f"Failed to parse JSON file {path}: {exc}")
            return []

    sandbox_closed_in_try = False
    try:
        update("Preparing URL sandbox environment...", 5)
        scan_duration = URL_DYNAMIC_OBSERVATION_SECONDS
        update(f"Using restricted URL observation window: {scan_duration}s", 8)

        # URL dynamic scans always launch a fresh visible sandbox VM.
        # This avoids stale-monitor races and guarantees deterministic URL execution.
        reuse_existing_monitor = False
        if _sandbox_alive(include_auxiliary=True):
            if not close_windows_sandbox():
                logger.warning("Could not fully stop previous Sandbox session before URL run.")

        update("Launching URL sandbox job...", 16)

        def is_cancel_requested() -> bool:
            return bool(job.get("cancel_requested"))

        max_attempts = 2
        retryable_reasons = {
            "sandbox-not-ready",
            "sandbox-launch-failed",
            "sandbox-exited",
            "monitor-unresponsive",
        }
        run_result: Dict[str, Any] = {}
        last_reason: Optional[str] = None
        last_diagnostics: Optional[Dict[str, Any]] = None

        for attempt in range(1, max_attempts + 1):
            attempt_session_id = session_id if attempt == 1 else f"{session_id}_retry{attempt - 1}"
            if attempt > 1:
                update("Retrying URL sandbox with fresh VM...", 18)
                close_windows_sandbox(wait_timeout_seconds=30)
                reuse_existing_monitor = False

            run_result = sandbox_run_dynamic_scan(
                file_bytes=b"",
                filename="url_target.txt",
                duration=scan_duration,
                done_grace=DYNAMIC_DONE_GRACE_SECONDS,
                launch_wsb_file=True,
                allow_existing_monitor=False,
                shutdown_after_done=True,
                on_progress=update,
                session_id=attempt_session_id,
                abort_if=is_cancel_requested,
                scan_mode="url",
                target_url=target_url,
            )

            if run_result.get("status") == "done":
                break

            last_reason = str(run_result.get("reason", "unknown-error"))
            raw_diagnostics = run_result.get("diagnostics")
            if isinstance(raw_diagnostics, dict):
                last_diagnostics = raw_diagnostics
            else:
                last_diagnostics = None

            if last_reason == "cancelled":
                job["status"] = "error"
                job["error"] = "URL sandbox scan cancelled by user."
                job["finished_at"] = datetime.utcnow().isoformat()
                update("URL sandbox scan cancelled.", max(0, job.get("progress", 0)))
                return

            if last_reason in retryable_reasons and attempt < max_attempts:
                logger.warning(
                    "URL sandbox attempt %s/%s failed with reason=%s. Retrying.",
                    attempt,
                    max_attempts,
                    last_reason,
                )
                continue
            break

        if run_result.get("status") != "done":
            reason = last_reason or str(run_result.get("reason", "unknown-error"))
            diagnostics = last_diagnostics if last_diagnostics is not None else run_result.get("diagnostics")
            if reason == "sandbox-not-ready":
                message = "Sandbox started but URL monitor did not become ready."
            elif reason == "sandbox-launch-failed":
                message = "Windows Sandbox did not launch successfully for URL dynamic analysis."
            elif reason == "sandbox-exited":
                message = "Sandbox session exited before URL telemetry was collected."
            elif reason == "scan-timeout":
                message = "URL dynamic analysis timed out before completion."
            elif reason == "monitor-unresponsive":
                message = "Sandbox monitor did not consume URL trigger in time."
            else:
                message = f"URL dynamic runner failed: {reason}"
            if diagnostics:
                message = f"{message} | diagnostics={json.dumps(diagnostics)}"
            raise RuntimeError(message)

        update("Reading sandbox URL telemetry...", 80)
        session = run_result.get("session")
        out_dir = run_result.get("out_dir")
        if not session or not out_dir:
            raise RuntimeError(f"Sandbox runner returned invalid output: {run_result}")

        processes_raw = read_json_file(os.path.join(out_dir, f"processes_{session}.json"))
        network_raw = read_json_file(os.path.join(out_dir, f"network_{session}.json"))
        done_raw = read_json_file(os.path.join(out_dir, f"done_{session}.json"))
        done_info = done_raw[0] if done_raw and isinstance(done_raw[0], dict) else {}

        files_raw = []
        registry_raw = []

        update("Analyzing URL telemetry...", 90)
        processes, filtered_processes = _normalise_processes(processes_raw)
        network, filtered_network = _normalise_network(network_raw)
        files = _normalise_files(files_raw)
        registry = _normalise_registry(registry_raw)

        open_action = done_info.get("open_action")
        open_success = done_info.get("open_success")
        open_error = done_info.get("open_error")
        verdict, threat_score, summary = _compute_verdict(
            processes,
            network,
            files,
            registry,
            open_action=open_action,
            open_success=open_success,
            target_filename=None,
            scan_mode="url",
        )

        if filtered_processes:
            summary.append(f"Filtered {filtered_processes} background process entries from sandbox telemetry")
        if filtered_network:
            summary.append(f"Filtered {filtered_network} local/background network entries from sandbox telemetry")
        summary.insert(0, "Restricted mode: external HTTP(S) target only; private/local addresses blocked by policy")
        if open_action:
            launch_state = "success" if open_success is True else "failed" if open_success is False else "unknown"
            summary.insert(1, f"Launch action: {open_action} ({launch_state})")
        if open_error:
            summary.append(f"Launch error: {str(open_error)[:220]}")

        duration = int(time.time() - start_time)

        if AUTO_CLOSE_SANDBOX:
            update("Shutting down sandbox VM...", 97)
            sandbox_closed_in_try = close_windows_sandbox(wait_timeout_seconds=35)
            if not sandbox_closed_in_try and _sandbox_alive(include_auxiliary=False):
                summary.append("Warning: sandbox VM did not fully close; backend will retry cleanup")

        update("URL dynamic analysis complete.", 100)
        job["status"] = "done"
        job["finished_at"] = datetime.utcnow().isoformat()
        job["result"] = {
            "verdict": verdict,
            "threatScore": threat_score,
            "duration": duration,
            "processes": processes,
            "network": network,
            "files": files,
            "registry": registry,
            "summary": summary,
            "targetUrl": target_url,
            "scanMode": "url",
        }

    except Exception as e:
        logger.error(f"URL sandbox job {job_id} failed: {e}", exc_info=True)
        job["status"] = "error"
        job["error"] = str(e)
        job["finished_at"] = datetime.utcnow().isoformat()

    finally:
        if AUTO_CLOSE_SANDBOX and not sandbox_closed_in_try:
            if not close_windows_sandbox(wait_timeout_seconds=20):
                logger.warning(
                    "Auto-close requested but sandbox processes are still running after URL scan. "
                    "Manual cleanup may be required."
                )
        elif KEEP_SANDBOX_OPEN:
            logger.info("Leaving Windows Sandbox running for reuse.")


@app.post("/analyze/dynamic")
async def start_dynamic_analysis(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Read the file, register a job, return job_id INSTANTLY.
    All blocking work (sandbox launch, monitoring) runs in a background thread.
    Poll GET /analyze/dynamic/status/{job_id} every 2s for real progress.
    """
    sandbox_exe = "C:\\Windows\\System32\\WindowsSandbox.exe"
    if not os.path.exists(sandbox_exe):
        raise HTTPException(
            status_code=500,
            detail="Windows Sandbox is not installed or not enabled. "
                   "Enable it via: Turn Windows features on/off -> Windows Sandbox"
        )

    # Read file content async (non-blocking) â€” the ONLY thing we do before returning
    content = await file.read()
    original_filename = file.filename or "uploaded_file"

    _cleanup_terminal_sandbox_jobs()
    active = [jid for jid, j in _sandbox_jobs.items() if j.get("status") == "running"]
    if active:
        raise HTTPException(
            status_code=409,
            detail="Another dynamic analysis is already running. Cancel or wait for it to finish."
        )

    job_id = str(uuid.uuid4())
    session_id = job_id.replace("-", "")

    # Register job immediately â€” worker thread will update step/progress in real time
    _sandbox_jobs[job_id] = {
        "status": "running",
        "step": "Preparing sandbox environment...",
        "progress": 3,
        "result": None,
        "error": None,
        "filename": original_filename,
        "session_id": session_id,
        "cancel_requested": False,
        "user_id": current_user.id,
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
    }

    # Launch background thread â€” returns immediately, doesn't block the event loop
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_sandbox_blocking,
        job_id,
        content,          # pass raw bytes â€” no disk write before returning
        original_filename
    )

    logger.info(f"Job {job_id[:8]} created for {original_filename} â€” returning to client immediately")
    return {"job_id": job_id, "status": "running"}


@app.post("/analyze/url/dynamic")
async def start_url_dynamic_analysis(
    url: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Dynamic URL analysis in sandbox.
    Security policy:
    - Run static URL analysis first.
    - If static verdict is malicious => do not execute in sandbox.
    - Only external http(s) targets allowed (no localhost/private ranges).
    """
    sandbox_exe = "C:\\Windows\\System32\\WindowsSandbox.exe"
    if not os.path.exists(sandbox_exe):
        raise HTTPException(
            status_code=500,
            detail="Windows Sandbox is not installed or not enabled. "
                   "Enable it via: Turn Windows features on/off -> Windows Sandbox"
        )

    static_eval = _evaluate_url_static(url, db)
    static_status = str(static_eval.get("status", "clean"))
    static_score = int(static_eval.get("threat_score", 0))

    if static_status == "malicious":
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Dynamic URL analysis blocked by policy: static verdict is malicious.",
                "static_status": static_status,
                "static_threat_score": static_score,
            },
        )

    allowed, reason = _validate_dynamic_url_target(url)
    if not allowed:
        raise HTTPException(status_code=422, detail=reason)

    _cleanup_terminal_sandbox_jobs()
    active = [jid for jid, j in _sandbox_jobs.items() if j.get("status") == "running"]
    if active:
        raise HTTPException(
            status_code=409,
            detail="Another dynamic analysis is already running. Cancel or wait for it to finish."
        )

    job_id = str(uuid.uuid4())
    session_id = job_id.replace("-", "")

    _sandbox_jobs[job_id] = {
        "status": "running",
        "step": "Preparing URL sandbox environment...",
        "progress": 3,
        "result": None,
        "error": None,
        "filename": url,
        "session_id": session_id,
        "cancel_requested": False,
        "user_id": current_user.id,
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "scan_mode": "url",
        "target_url": url,
        "static_status": static_status,
        "static_threat_score": static_score,
    }

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_url_sandbox_blocking,
        job_id,
        url,
    )

    logger.info(f"URL dynamic job {job_id[:8]} created for {url} - returning to client immediately")
    return {
        "job_id": job_id,
        "status": "running",
        "static_status": static_status,
        "static_threat_score": static_score,
    }


@app.post("/analyze/url/browser-dynamic")
async def start_browser_dynamic_analysis(
    url: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Fast browser-instrumented URL analysis using Playwright.
    This complements sandbox execution with richer browser-level telemetry.
    """
    static_eval = _evaluate_url_static(url, db)
    static_status = str(static_eval.get("status", "clean"))
    static_score = int(static_eval.get("threat_score", 0))

    if static_status == "malicious":
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Fast browser dynamic analysis blocked by policy: static verdict is malicious.",
                "static_status": static_status,
                "static_threat_score": static_score,
            },
        )

    allowed, reason = _validate_dynamic_url_target(url)
    if not allowed:
        raise HTTPException(status_code=422, detail=reason)

    _cleanup_terminal_browser_dynamic_jobs()
    active = [jid for jid, j in _browser_dynamic_jobs.items() if j.get("status") == "running"]
    if active:
        raise HTTPException(
            status_code=409,
            detail="Another fast browser dynamic analysis is already running. Cancel or wait for completion."
        )

    job_id = str(uuid.uuid4())
    _browser_dynamic_jobs[job_id] = {
        "status": "running",
        "step": "Launching browser instrumentation...",
        "progress": 3,
        "result": None,
        "error": None,
        "filename": url,
        "user_id": current_user.id,
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "scan_mode": "browser-url",
        "target_url": url,
        "static_status": static_status,
        "static_threat_score": static_score,
        "cancel_requested": False,
    }

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _browser_dynamic_executor,
        _run_browser_dynamic_blocking,
        job_id,
        url,
    )

    logger.info("Browser dynamic job %s created for %s", job_id[:8], url)
    return {
        "job_id": job_id,
        "status": "running",
        "static_status": static_status,
        "static_threat_score": static_score,
    }


def _cancel_browser_dynamic_job_for_user(job_id: str, current_user: User) -> Dict[str, Any]:
    job = _browser_dynamic_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("status") != "running":
        return {"job_id": job_id, "status": job.get("status"), "message": "Job is not running"}
    if job.get("user_id") != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to cancel this job")

    job["cancel_requested"] = True
    job["step"] = "Cancellation requested..."
    return {"job_id": job_id, "status": "cancelling"}


def _get_browser_dynamic_job_status_for_user(job_id: str, current_user: User) -> Dict[str, Any]:
    _cleanup_terminal_browser_dynamic_jobs()
    job = _browser_dynamic_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("user_id") != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to read this job")

    response = {
        "job_id": job_id,
        "status": job["status"],
        "step": job.get("step", ""),
        "progress": job.get("progress", 0),
        "filename": job.get("filename", ""),
        "finished_at": job.get("finished_at"),
        "scan_mode": job.get("scan_mode", "browser-url"),
        "target_url": job.get("target_url"),
        "static_status": job.get("static_status"),
        "static_threat_score": job.get("static_threat_score"),
    }
    if job["status"] == "done":
        response["result"] = job["result"]
    elif job["status"] == "error":
        response["error"] = job.get("error", "Unknown error")
    return response


def _cancel_dynamic_job_for_user(job_id: str, current_user: User) -> Dict[str, Any]:
    """Shared cancel helper for file + URL sandbox jobs."""
    job = _sandbox_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("status") != "running":
        return {"job_id": job_id, "status": job.get("status"), "message": "Job is not running"}

    if job.get("user_id") != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to cancel this job")

    job["cancel_requested"] = True
    job["step"] = "Cancelling sandbox job..."

    session_id = str(job.get("session_id") or "")
    if session_id:
        for suffix in (".scan.json", ".scan.tmp"):
            trigger = os.path.join(SANDBOX_SHARE, "inbox", f"{session_id}{suffix}")
            try:
                if os.path.exists(trigger):
                    os.remove(trigger)
            except OSError:
                pass

    close_windows_sandbox(wait_timeout_seconds=35)
    return {"job_id": job_id, "status": "cancelling"}


def _get_dynamic_job_status_for_user(job_id: str, current_user: User) -> Dict[str, Any]:
    """Shared status helper for file + URL sandbox jobs."""
    _cleanup_terminal_sandbox_jobs()
    job = _sandbox_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("user_id") != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to read this job")

    response = {
        "job_id": job_id,
        "status": job["status"],
        "step": job.get("step", ""),
        "progress": job.get("progress", 0),
        "filename": job.get("filename", ""),
        "finished_at": job.get("finished_at"),
        "scan_mode": job.get("scan_mode", "file"),
        "target_url": job.get("target_url"),
        "static_status": job.get("static_status"),
        "static_threat_score": job.get("static_threat_score"),
    }

    if job["status"] == "done":
        response["result"] = job["result"]
    elif job["status"] == "error":
        response["error"] = job.get("error", "Unknown error")

    return response


@app.post("/analyze/dynamic/cancel/{job_id}")
async def cancel_dynamic_analysis(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    """Request cancellation for a running sandbox job."""
    return _cancel_dynamic_job_for_user(job_id, current_user)


@app.post("/analyze/url/dynamic/cancel/{job_id}")
async def cancel_url_dynamic_analysis(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    """Request cancellation for a running URL sandbox job."""
    return _cancel_dynamic_job_for_user(job_id, current_user)


@app.post("/analyze/url/browser-dynamic/cancel/{job_id}")
async def cancel_browser_dynamic_analysis(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    """Request cancellation for a running fast browser dynamic URL job."""
    return _cancel_browser_dynamic_job_for_user(job_id, current_user)


@app.get("/analyze/dynamic/status/{job_id}")
async def get_dynamic_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Poll this endpoint every 2s to get sandbox progress and results."""
    return _get_dynamic_job_status_for_user(job_id, current_user)


@app.get("/analyze/url/dynamic/status/{job_id}")
async def get_url_dynamic_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Poll this endpoint every 2s to get URL sandbox progress and results."""
    return _get_dynamic_job_status_for_user(job_id, current_user)


@app.get("/analyze/url/browser-dynamic/status/{job_id}")
async def get_browser_dynamic_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Poll this endpoint every 2s to get fast browser dynamic URL progress and results."""
    return _get_browser_dynamic_job_status_for_user(job_id, current_user)


if __name__ == "__main__":
    import uvicorn
    reload_enabled = os.environ.get("SECA_BACKEND_RELOAD", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=reload_enabled)
