from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
import json
import re
import sqlite3
import os
import shutil
import subprocess
import time
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta
import hashlib

from database import get_db, engine, Base
from models import User, Scan, AuditLog, PhishTankEntry
import schemas
from auth import get_current_user, require_admin, create_access_token, router as auth_router
from sandbox_runner import run_dynamic_scan as sandbox_run_dynamic_scan

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
    # Check our comprehensive malicious URL database
    try:
        # Use absolute path to security_analyzer.db
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_analyzer.db')

        if not os.path.exists(db_path):
            logger.warning(f"security_analyzer.db not found at {db_path}")
            # Continue to PhishTank fallback
        else:
            threat_db = sqlite3.connect(db_path)
            cursor = threat_db.cursor()

            # Direct URL match
            cursor.execute(
                "SELECT url, domain, threat_type, source FROM malicious_urls WHERE url = ?",
                (url,)
            )
            result = cursor.fetchone()

            if result:
                threat_db.close()
                logger.info(f"âœ“ FOUND IN DATABASE: {url} - {result[3]} - {result[2]}")
                return {
                    "found": True,
                    "verified": True,
                    "threat_type": result[2],
                    "source": result[3],
                    "threat_level": "high",
                    "message": f"URL found in {result[3]} database - {result[2]}"
                }

            # Domain-level match
            domain = urlparse(url).netloc
            cursor.execute(
                "SELECT COUNT(*) FROM malicious_urls WHERE domain = ?",
                (domain,)
            )
            domain_matches = cursor.fetchone()[0]

            threat_db.close()

            if domain_matches > 0:
                logger.info(f"âš  DOMAIN MATCH: {domain} appears in {domain_matches} entries")
                return {
                    "found": True,
                    "verified": False,
                    "domain_matches": domain_matches,
                    "threat_level": "medium",
                    "message": f"Domain appears in {domain_matches} malicious URL entries"
                }

    except Exception as e:
        logger.error(f"Error checking threat database: {e}")
        import traceback
        traceback.print_exc()

    # Also check PhishTank table as fallback
    phish_entry = db.query(PhishTankEntry).filter(
        PhishTankEntry.url == url
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
        scan_type: str = Form(...),
        status: str = Form(...),
        threat_score: str = Form(...),
        details: str = Form(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        scan = Scan(
            user_id=current_user.id,
            scan_type=scan_type,
            target=file.filename,
            status=status,
            threat_score=int(threat_score),
            details=details
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        create_audit_log(db, current_user.id, "File Scan", f"Scanned {file.filename}")
        return {"success": True, "scan_id": scan.id}
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

        return [{
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "details": l.details,
            "timestamp": l.timestamp.isoformat()
        } for l in logs]
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
    """Check URL against PhishTank database (public, no auth required)"""
    try:
        entry = db.query(PhishTankEntry).filter(PhishTankEntry.url == url).first()
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

# Job tracking: {job_id: {status, step, progress, result, error}}
_sandbox_jobs: Dict[str, Dict[str, Any]] = {}
_executor = ThreadPoolExecutor(max_workers=1)


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


def close_windows_sandbox():
    """Terminate any running Windows Sandbox process."""
    try:
        for proc_name in (
            "WindowsSandbox.exe",
            "WindowsSandboxRemoteSession.exe",
            "WindowsSandboxServer.exe",
        ):
            subprocess.run(
                ["taskkill", "/IM", proc_name, "/F"],
                capture_output=True,
                text=True,
            )
        # Best effort only; this may fail depending on privileges.
        subprocess.run(
            ["taskkill", "/IM", "vmmemWindowsSandbox.exe", "/F"],
            capture_output=True,
            text=True,
        )
        time.sleep(1)
    except Exception as e:
        logger.error(f"Error closing sandbox: {e}")


def get_file_extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower()


def _normalise_processes(raw) -> list:
    """Convert PowerShell Get-Process JSON to frontend format."""
    results = []
    if not raw:
        return results
    if isinstance(raw, dict):
        raw = [raw]
    suspicious_names = {"cmd", "powershell", "rundll32", "regsvr32", "wscript",
                        "cscript", "mshta", "certutil", "bitsadmin"}
    for p in raw:
        if not isinstance(p, dict):
            continue
        name = p.get("ProcessName") or p.get("Name") or "unknown"
        pid = p.get("Id") or p.get("pid") or 0
        cpu = p.get("CPU") or 0
        action = f"Running â€” CPU: {round(float(cpu), 2)}s" if cpu else "Running"
        suspicious = name.lower().split(".")[0] in suspicious_names
        results.append({"pid": int(pid), "name": name, "action": action, "suspicious": suspicious})
    return results


def _normalise_network(raw) -> list:
    """Convert PowerShell Get-NetTCPConnection JSON to frontend format."""
    results = []
    if not raw:
        return results
    if isinstance(raw, dict):
        raw = [raw]
    local_prefixes = ("127.", "0.0.0.0", "::1", "::")
    for n in raw:
        if not isinstance(n, dict):
            continue
        remote = n.get("RemoteAddress") or n.get("destination") or ""
        port = n.get("RemotePort") or n.get("port") or 0
        proto = n.get("protocol") or "TCP"
        suspicious = not any(remote.startswith(p) for p in local_prefixes) and remote not in ("", "0.0.0.0")
        results.append({"protocol": proto, "destination": remote, "port": int(port), "suspicious": suspicious})
    return [r for r in results if r["destination"] not in ("", "0.0.0.0")]


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


def _compute_verdict(processes, network, files, registry) -> tuple:
    """Heuristic scoring on normalised data."""
    score = 0
    findings = []

    # Suspicious processes
    susp_procs = [p for p in processes if p.get("suspicious")]
    if susp_procs:
        score += 25
        findings.append(f"{len(susp_procs)} suspicious process(es) spawned: {', '.join(p['name'] for p in susp_procs)}")

    # External network connections
    ext_net = [n for n in network if n.get("suspicious")]
    if ext_net:
        score += 30
        findings.append(f"{len(ext_net)} external network connection(s) made")
        for n in ext_net:
            findings.append(f"   -> {n['protocol']} {n['destination']}:{n['port']}")

    # Suspicious file writes
    susp_files = [f for f in files if f.get("suspicious")]
    if susp_files:
        score += 20
        findings.append(f"{len(susp_files)} suspicious file system change(s)")

    # Registry persistence keys
    susp_reg = [r for r in registry if r.get("suspicious")]
    if susp_reg:
        score += 30
        findings.append(f"{len(susp_reg)} suspicious registry write(s) - possible persistence")

    if not findings:
        findings.append("No suspicious behaviour detected during sandbox execution")

    score = min(100, score)
    verdict = "malicious" if score >= 50 else "suspicious" if score >= 20 else "clean"
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
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
            if not raw:
                return []
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception as exc:
            logger.error(f"Failed to parse JSON file {path}: {exc}")
            return []

    try:
        update("Preparing sandbox environment...", 5)
        close_windows_sandbox()

        update("Launching sandbox job...", 15)
        def is_cancel_requested() -> bool:
            return bool(job.get("cancel_requested"))

        run_result = sandbox_run_dynamic_scan(
            file_bytes=file_content,
            filename=filename,
            duration=60,
            launch_wsb_file=True,
            on_progress=update,
            session_id=session_id,
            abort_if=is_cancel_requested,
        )

        if run_result.get("status") != "done":
            reason = run_result.get("reason", "unknown-error")
            diagnostics = run_result.get("diagnostics")
            if reason == "sandbox-not-ready":
                message = "Sandbox started but monitor did not become ready. Check C:\\sandbox_share\\monitor_debug.txt."
            elif reason == "sandbox-exited":
                message = "Sandbox session closed unexpectedly during execution. This can happen if the sample forces logoff/shutdown."
            elif reason == "scan-timeout":
                message = "Sandbox execution timed out before completion."
            elif reason == "monitor-missing":
                message = "Sandbox monitor script is missing at C:\\sandbox_share\\monitor.ps1."
            elif reason == "cancelled":
                job["status"] = "error"
                job["error"] = "Scan cancelled by user."
                update("Scan cancelled.", max(0, job.get("progress", 0)))
                return
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
        processes = _normalise_processes(processes_raw)
        network = _normalise_network(network_raw)
        files = _normalise_files(files_raw)
        registry = _normalise_registry(registry_raw)

        verdict, threat_score, summary = _compute_verdict(processes, network, files, registry)
        open_action = done_info.get("open_action")
        open_success = done_info.get("open_success")
        open_error = done_info.get("open_error")
        if open_action:
            launch_state = "success" if open_success is True else "failed" if open_success is False else "unknown"
            summary.insert(0, f"Launch action: {open_action} ({launch_state})")
        if open_error:
            summary.append(f"Launch error: {str(open_error)[:220]}")
        duration = int(time.time() - start_time)

        update("Analysis complete.", 100)
        job["status"] = "done"
        job["result"] = {
            "verdict": verdict,
            "threatScore": threat_score,
            "duration": duration,
            "processes": processes,
            "network": network,
            "files": files,
            "registry": registry,
            "summary": summary,
        }

    except Exception as e:
        logger.error(f"Sandbox job {job_id} failed: {e}", exc_info=True)
        job["status"] = "error"
        job["error"] = str(e)

    finally:
        if KEEP_SANDBOX_OPEN:
            logger.info("SECA_KEEP_SANDBOX_OPEN is enabled; leaving Windows Sandbox running.")
        else:
            close_windows_sandbox()


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

    close_windows_sandbox()
    return {"job_id": job_id, "status": "cancelling"}


@app.get("/analyze/dynamic/status/{job_id}")
async def get_dynamic_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Poll this endpoint every 2s to get sandbox progress and results."""
    job = _sandbox_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    response = {
        "job_id": job_id,
        "status": job["status"],   # "running" | "done" | "error"
        "step": job.get("step", ""),
        "progress": job.get("progress", 0),
        "filename": job.get("filename", ""),
    }

    if job["status"] == "done":
        response["result"] = job["result"]
        # Clean up job after retrieval
        _sandbox_jobs.pop(job_id, None)
    elif job["status"] == "error":
        response["error"] = job.get("error", "Unknown error")
        _sandbox_jobs.pop(job_id, None)

    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
