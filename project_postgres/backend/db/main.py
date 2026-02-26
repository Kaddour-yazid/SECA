from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List, Tuple
import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
import json
import ipaddress
import hashlib
import math
import re
import os
import shutil
import subprocess
import time
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta

from database import get_db, engine, Base
from models import User, Scan, AuditLog, PhishTankEntry, ThreatUrl
import schemas
from auth import get_current_user, require_admin, create_access_token, router as auth_router
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Security Analyzer API")

@app.middleware("http")
async def log_requests(request, call_next):
    logger.info(f"âž¡ï¸ Incoming request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"â¬…ï¸ Response status: {response.status_code}")
    return response

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
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


# ============= URL SCANNER - 4 LAYER SYSTEM =============

def layer1_format_validation(url: str) -> Dict[str, Any]:
    """Layer 1: Format Validation"""
    try:
        parsed = urlparse(url)

        issues = []
        suspicious = False

        # Check protocol
        if parsed.scheme not in ['http', 'https']:
            issues.append("Invalid protocol")
            suspicious = True

        # Check for suspicious characters
        suspicious_chars = ['@', '..', '///', '%00']
        if any(char in url for char in suspicious_chars):
            issues.append("Suspicious characters detected")
            suspicious = True

        # Check URL length (phishing URLs are often very long)
        if len(url) > 200:
            issues.append("Unusually long URL")
            suspicious = True

        # Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, parsed.netloc):
            issues.append("Uses IP address instead of domain")
            suspicious = True

        return {
            "passed": not suspicious,
            "issues": issues,
            "protocol": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path
        }
    except Exception as e:
        return {
            "passed": False,
            "issues": ["Invalid URL format"],
            "error": str(e)
        }


def layer2_phishtank_check(url: str, db: Session) -> Dict[str, Any]:
    """Layer 2: Malicious URL Database Check (75K+ URLs)"""
    normalized_url = url.strip()
    domain = urlparse(normalized_url).netloc.lower()

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
                "message": f"URL found in imported threat feed ({source})",
            }

        if domain:
            domain_matches = db.query(ThreatUrl).filter(ThreatUrl.domain == domain).count()
            if domain_matches > 0:
                logger.info(f"DOMAIN MATCH: {domain} appears in {domain_matches} threat feed entries")
                return {
                    "found": True,
                    "verified": False,
                    "domain_matches": domain_matches,
                    "threat_level": "medium",
                    "message": f"Domain appears in {domain_matches} imported threat feed entries",
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
            "message": "URL found in PhishTank database"
        }

    return {
        "found": False,
        "threat_level": "low",
        "message": "URL not found in threat databases (75K+ URLs checked)"
    }


def layer3_domain_reputation(url: str) -> Dict[str, Any]:
    """Layer 3: Domain Reputation Check"""
    parsed = urlparse(url)
    domain = parsed.netloc

    # Simulate domain reputation checks
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    is_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)

    # Check for suspicious patterns in domain
    suspicious_keywords = ['secure', 'account', 'verify', 'login', 'bank', 'paypal', 'update']
    has_suspicious_keywords = any(keyword in domain.lower() for keyword in suspicious_keywords)

    # Check for subdomain tricks (e.g., paypal.malicious.com)
    subdomain_count = domain.count('.')
    suspicious_subdomain = subdomain_count > 2

    issues = []
    reputation_score = 100

    if is_suspicious_tld:
        issues.append("Suspicious top-level domain")
        reputation_score -= 30

    if has_suspicious_keywords:
        issues.append("Domain contains suspicious keywords")
        reputation_score -= 20

    if suspicious_subdomain:
        issues.append("Multiple subdomains detected")
        reputation_score -= 15

    # Check for homograph attacks (IDN)
    if any(ord(char) > 127 for char in domain):
        issues.append("Contains non-ASCII characters (possible homograph attack)")
        reputation_score -= 25

    return {
        "domain": domain,
        "reputation_score": max(0, reputation_score),
        "suspicious_tld": is_suspicious_tld,
        "suspicious_keywords": has_suspicious_keywords,
        "issues": issues,
        "threat_level": "high" if reputation_score < 50 else "medium" if reputation_score < 75 else "low"
    }


def layer4_content_analysis(url: str) -> Dict[str, Any]:
    """Layer 4: Content Analysis (simulated)"""
    parsed = urlparse(url)

    indicators = []
    threat_score = 0

    # Check for common phishing patterns
    if 'verify' in url.lower() or 'confirm' in url.lower():
        indicators.append("URL contains verification/confirmation language")
        threat_score += 15

    if 'suspended' in url.lower() or 'locked' in url.lower():
        indicators.append("URL suggests account suspension/lock")
        threat_score += 20

    # Check for URL shorteners (often used in phishing)
    shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl']
    if any(shortener in parsed.netloc for shortener in shorteners):
        indicators.append("URL shortener detected")
        threat_score += 10

    # Check for suspicious query parameters
    if 'token' in url.lower() or 'session' in url.lower():
        indicators.append("Contains authentication parameters")
        threat_score += 10

    return {
        "indicators": indicators,
        "threat_score": threat_score,
        "ssl_expected": parsed.scheme == 'https',
        "analysis_complete": True
    }


@app.post("/url-scan-advanced")
async def url_scan_advanced(
        url: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Advanced 4-layer URL scanning (authenticated)"""
    try:
        user_id = current_user.id

        # Layer 1: Format Validation
        layer1 = layer1_format_validation(url)

        # Layer 2: PhishTank Check
        layer2 = layer2_phishtank_check(url, db)

        # Layer 3: Domain Reputation
        layer3 = layer3_domain_reputation(url)

        # Layer 4: Content Analysis
        layer4 = layer4_content_analysis(url)

        # Calculate overall threat score
        threat_score = 0
        status = "clean"

        # Layer 1: Format validation issues
        if not layer1["passed"]:
            threat_score += 20

        # Layer 2: Database check (MOST IMPORTANT)
        if layer2["found"]:
            if layer2.get("verified"):
                threat_score += 60  # Verified threat = HIGH
            else:
                threat_score += 40  # Unverified but found = MEDIUM

        # Layer 3: Domain reputation
        layer3_score = 100 - layer3["reputation_score"]
        threat_score += int(layer3_score * 0.25)

        # Layer 4: Content analysis
        threat_score += layer4["threat_score"]

        # Determine status - FIXED THRESHOLDS
        if threat_score >= 60 or layer2.get("found"):  # Database hit = auto malicious
            status = "malicious"
        elif threat_score >= 35:
            status = "suspicious"
        else:
            status = "clean"

        # Prepare detailed results
        scan_details = {
            "url": url,
            "layers": {
                "layer1_format": layer1,
                "layer2_phishtank": layer2,
                "layer3_reputation": layer3,
                "layer4_content": layer4
            },
            "overall_threat_score": min(100, threat_score),
            "status": status,
            "scan_timestamp": datetime.utcnow().isoformat()
        }

        # Save scan to database
        scan = Scan(
            user_id=user_id,
            scan_type="url_advanced",
            target=url,
            status=status,
            threat_score=min(100, threat_score),
            details=json.dumps(scan_details)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Create audit log
        create_audit_log(db, user_id, "Advanced URL Scan", f"Scanned {url[:50]}...")

        return {
            "success": True,
            "scan_id": scan.id,
            "status": status,
            "threat_score": min(100, threat_score),
            "details": scan_details
        }

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
_YARA_CACHE: Dict[str, Any] = {"key": None, "rules": None, "source": "disabled", "error": None}


def _classify_file_category(filename: str, content_type: Optional[str]) -> Tuple[str, int]:
    ext = os.path.splitext(filename or "")[1].lower()
    mime = (content_type or "").lower()
    if ext in STATIC_EXECUTABLE_EXTENSIONS or "x-msdownload" in mime or "executable" in mime:
        return "executable", 35
    if ext in STATIC_SCRIPT_EXTENSIONS or "javascript" in mime or "x-sh" in mime:
        return "script", 24
    if ext in STATIC_ARCHIVE_EXTENSIONS or "zip" in mime or "compressed" in mime:
        return "archive", 12
    if ext in STATIC_DOCUMENT_EXTENSIONS or "pdf" in mime or "document" in mime or "spreadsheet" in mime:
        return "document", 6
    if ext in STATIC_MEDIA_EXTENSIONS or mime.startswith("image/") or mime.startswith("audio/") or mime.startswith("video/"):
        return "media", 2
    return "unknown", 14


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


def _hash_reputation_lookup(db: Session, md5_hex: str, sha1_hex: str, sha256_hex_value: str) -> Dict[str, Any]:
    detections = 0
    engines = 0
    malware_family = None
    evidence: List[str] = []
    sources: List[str] = []
    checked_hashes = [md5_hex.lower(), sha1_hex.lower(), sha256_hex_value.lower()]

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

    file_scan_hits = (
        db.query(Scan)
        .filter(
            Scan.scan_type == "file",
            Scan.status.in_(["malicious", "suspicious"]),
            or_(
                Scan.details.ilike(f"%{sha256_hex_value}%"),
                Scan.details.ilike(f"%{sha1_hex}%"),
                Scan.details.ilike(f"%{md5_hex}%"),
            ),
        )
        .count()
    )
    if file_scan_hits:
        detections += min(15, file_scan_hits)
        engines += min(8, max(1, file_scan_hits // 2 + 1))
        sources.append("historical-file-scans")
        evidence.append(f"Hash fingerprint seen in {file_scan_hits} previous file scan(s)")

    if db.query(ThreatUrl).filter(ThreatUrl.url_hash == sha256_hex_value.lower()).first():
        detections += 1
        engines += 1
        sources.append("threat-feed-collision")
        evidence.append("SHA-256 collides with an existing threat-feed hash entry")

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
        with open(custom_path, "r", encoding="utf-8") as handle:
            rule_source = handle.read()
    else:
        rule_source = _default_yara_rules()
        cache_key = f"default:{hashlib.sha256(rule_source.encode('utf-8')).hexdigest()}"
        source_label = "builtin"

    if _YARA_CACHE["key"] == cache_key and _YARA_CACHE["rules"] is not None:
        return _YARA_CACHE["rules"], source_label, None

    try:
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


def _run_yara_scan(file_bytes: bytes) -> Dict[str, Any]:
    rules, source_label, err = _get_compiled_yara_rules()
    if rules is not None:
        try:
            matches = rules.match(data=file_bytes, timeout=10)
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
    yara_info = _run_yara_scan(file_bytes)
    pe_info = _analyze_pe_metadata(file_bytes)

    suspicious_strings = sorted(
        {
            pattern
            for pattern in SUSPICIOUS_STRING_PATTERNS
            if any(pattern in extracted for extracted in lowered_strings)
        }
    )[:12]

    threats: List[Dict[str, str]] = []
    score = base_risk

    if hash_info["databaseMatch"]:
        score += 60
        threats.append(
            {
                "name": "Known.Hash.Reputation",
                "severity": "high",
                "description": "; ".join(hash_info["evidence"])[:200] or "Hash matched known malicious reputation data",
            }
        )
    if yara_info["matches"]:
        score += min(30, 10 + len(yara_info["matches"]) * 4)
        threats.append(
            {
                "name": "YARA.Rule.Match",
                "severity": "high" if any("High" in rule for rule in yara_info["matches"]) else "medium",
                "description": f"Matched rules: {', '.join(yara_info['matches'][:4])}",
            }
        )
    if suspicious_strings:
        score += min(22, len(suspicious_strings) * 4)
        threats.append(
            {
                "name": "Suspicious.String.Patterns",
                "severity": "medium",
                "description": f"Detected string patterns: {', '.join(suspicious_strings[:4])}",
            }
        )
    if pe_info["score"] > 0:
        score += pe_info["score"]
        threats.append(
            {
                "name": "PE.Metadata.Anomaly",
                "severity": "high" if pe_info["score"] >= 18 else "medium",
                "description": "; ".join(pe_info["anomalies"][:3]) or "Potentially suspicious PE metadata",
            }
        )

    if entropy > 7.4 and risk_category in {"executable", "script"}:
        score += 12
        threats.append(
            {
                "name": "High.Entropy.Content",
                "severity": "medium",
                "description": f"File entropy is high ({entropy}) and may indicate packing/obfuscation",
            }
        )

    score = min(100, int(score))
    if score >= 70:
        status = "malicious"
    elif score >= 35:
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
        create_audit_log(db, current_user.id, "Hash Check", f"Checked {target[:16]}...")
        return {"success": True, "scan_id": scan.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans")
async def get_scans(
        current_user: User = Depends(get_current_user),
        scan_type: Optional[str] = Query(None),
        status: Optional[str] = Query(None),
        limit: int = Query(100, le=500),
        db: Session = Depends(get_db)
):
    try:
        query = db.query(Scan)

        # Nonâ€‘admins see only their own scans; admins see all
        if not current_user.is_admin:
            query = query.filter(Scan.user_id == current_user.id)

        if scan_type:
            query = query.filter(Scan.scan_type == scan_type)
        if status:
            query = query.filter(Scan.status == status)

        scans = query.order_by(Scan.created_at.desc()).limit(limit).all()

        return [{
            "id": s.id,
            "scan_type": s.scan_type,
            "target": s.target,
            "status": s.status,
            "threat_score": s.threat_score,
            "created_at": s.created_at.isoformat()
        } for s in scans]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
            user_name = (user_email.split("@", 1)[0] if user_email else f"User #{l.user_id}")
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
        "is_admin": u.is_admin,
        "created_at": u.created_at.isoformat()
    } for u in users]


@app.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info"""
    logger.info("âœ… /me endpoint called")
    return {
        "id": current_user.id,
        "email": current_user.email,
        "is_admin": current_user.is_admin
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
logger.info(
    "Sandbox config: reuse=%s auto_close=%s keep_open=%s heartbeat=%ss",
    REUSE_SANDBOX_SESSION,
    AUTO_CLOSE_SANDBOX,
    KEEP_SANDBOX_OPEN,
    MONITOR_HEARTBEAT_SECONDS,
)

# Job tracking: {job_id: {status, step, progress, result, error}}
_sandbox_jobs: Dict[str, Dict[str, Any]] = {}
_executor = ThreadPoolExecutor(max_workers=1)
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
        attempts = 3
        per_attempt_wait = max(4, int(wait_timeout_seconds // attempts))
        for attempt in range(1, attempts + 1):
            _kill_sandbox_processes_once()
            deadline = time.time() + per_attempt_wait
            while time.time() < deadline:
                if not _sandbox_alive(include_auxiliary=True):
                    return True
                time.sleep(0.5)
            logger.warning(
                "Sandbox processes still running after close attempt %s/%s",
                attempt,
                attempts,
            )
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
) -> tuple:
    """Heuristic scoring on normalised data."""
    score = 0
    findings = []
    action = (open_action or "").lower()
    ext = get_file_extension(target_filename or "")
    is_document_open = action in {"msedge-pdf", "notepad", "invoke-item"} or ext in DYNAMIC_DOCUMENT_EXTENSIONS

    # Suspicious file writes and registry activity.
    susp_files = [f for f in files if f.get("suspicious")]
    susp_reg = [r for r in registry if r.get("suspicious")]
    if susp_files:
        score += 20
        findings.append(f"{len(susp_files)} suspicious file system change(s)")
    if susp_reg:
        score += 30
        findings.append(f"{len(susp_reg)} suspicious registry write(s) - possible persistence")

    high_risk_procs = [p for p in processes if p.get("riskLevel") == "high" or p.get("suspicious")]
    contextual_shell = [
        p
        for p in processes
        if str(p.get("name", "")).lower().split(".")[0] in DYNAMIC_PROCESS_CONTEXTUAL_NAMES
    ]
    non_web_net = [n for n in network if n.get("classification") == "public-nonweb"]
    web_net = [n for n in network if n.get("classification") == "public-web"]
    high_risk_non_web = [n for n in non_web_net if n.get("networkRisk") == "high"]

    if high_risk_procs:
        score += 35
        findings.append(
            f"{len(high_risk_procs)} high-risk process(es) observed: "
            + ", ".join(p["name"] for p in high_risk_procs[:8])
        )

    if contextual_shell:
        if high_risk_procs or susp_files or susp_reg or non_web_net:
            score += 12
            findings.append(f"{len(contextual_shell)} shell process(es) correlated with other suspicious indicators")
        else:
            findings.append("Contextual shell activity observed but treated as low-confidence monitor noise")

    # External network connections.
    if non_web_net:
        score += 30 if high_risk_non_web else 20
        if high_risk_non_web:
            findings.append(f"{len(high_risk_non_web)} high-risk non-web external connection(s) made")
        findings.append(f"{len(non_web_net)} non-web external connection(s) made")
        for n in non_web_net[:8]:
            findings.append(f"   -> {n['protocol']} {n['destination']}:{n['port']}")
    elif web_net:
        has_other_categories = bool(high_risk_procs or susp_files or susp_reg)
        if is_document_open:
            findings.append(f"{len(web_net)} outbound web connection(s) observed during document open (filtered as likely background)")
        elif open_success is False and not has_other_categories:
            findings.append("Launch failed; outbound web traffic treated as background baseline")
        elif has_other_categories:
            score += 10
            findings.append(f"{len(web_net)} outbound web connection(s) alongside local suspicious indicators")
        elif action in {"execute", "test"}:
            score += 8
            findings.append(f"{len(web_net)} outbound web connection(s) during executable/script run")
        else:
            score += 4
            findings.append(f"{len(web_net)} outbound web connection(s) observed (low-confidence)")

    if open_success is False and not (high_risk_procs or susp_files or susp_reg or non_web_net):
        score = min(score, 10)
        findings.append("Sample launch was not successful; verdict confidence reduced")

    if is_document_open and not (high_risk_procs or susp_files or susp_reg or non_web_net):
        if open_success is False:
            findings = ["Document launch failed; no malicious behaviour observed in sandbox"]
        else:
            findings = ["Only expected document-open activity observed in sandbox"]

    if not findings:
        findings.append("No suspicious behaviour detected during sandbox execution")

    if high_risk_procs or susp_reg or non_web_net:
        findings.append("Signal confidence: high")
    elif susp_files or (web_net and contextual_shell and action in {"execute", "test"}):
        findings.append("Signal confidence: medium")
    else:
        findings.append("Signal confidence: low")

    score = min(100, score)
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 25 else "clean"
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

        # Current monitor writes process+network snapshots only.
        files_raw = []
        registry_raw = []

        update("Analyzing collected behaviour...", 90)
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
            target_filename=filename,
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
        if open_error:
            summary.append(f"Launch error: {str(open_error)[:220]}")
        duration = int(time.time() - start_time)

        if AUTO_CLOSE_SANDBOX:
            update("Shutting down sandbox VM...", 97)
            sandbox_closed_in_try = close_windows_sandbox(wait_timeout_seconds=35)
            if not sandbox_closed_in_try:
                summary.append("Warning: sandbox VM did not fully close; backend will retry cleanup")

        update("Analysis complete.", 100)
        job["status"] = "done"
        job["finished_at"] = datetime.utcnow().isoformat()
        job["result"] = {
            "verdict": verdict,
            "threatScore": threat_score,
            "duration": duration,
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


@app.post("/analyze/dynamic/cancel/{job_id}")
async def cancel_dynamic_analysis(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    """Request cancellation for a running sandbox job."""
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


@app.get("/analyze/dynamic/status/{job_id}")
async def get_dynamic_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Poll this endpoint every 2s to get sandbox progress and results."""
    _cleanup_terminal_sandbox_jobs()
    job = _sandbox_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("user_id") != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to read this job")

    response = {
        "job_id": job_id,
        "status": job["status"],   # "running" | "done" | "error"
        "step": job.get("step", ""),
        "progress": job.get("progress", 0),
        "filename": job.get("filename", ""),
        "finished_at": job.get("finished_at"),
    }

    if job["status"] == "done":
        response["result"] = job["result"]
    elif job["status"] == "error":
        response["error"] = job.get("error", "Unknown error")

    return response


if __name__ == "__main__":
    import uvicorn
    reload_enabled = os.environ.get("SECA_BACKEND_RELOAD", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=reload_enabled)
