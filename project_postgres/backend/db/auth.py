from email.message import EmailMessage
from datetime import datetime, timedelta
from typing import Optional

import hashlib
import hmac
import os
import secrets
import smtplib

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from database import get_db
import models
import schemas
from security_utils import hash_password, verify_password

print("Loading auth.py")

SECRET_KEY = "yazid22t"  # Change in production
ALGORITHM = "HS256"


def _get_token_expiry_minutes() -> int:
    raw = os.environ.get("SECA_ACCESS_TOKEN_EXPIRE_MINUTES", "720").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 720
    return max(5, value)


def _get_otp_expiry_minutes() -> int:
    raw = os.environ.get("SECA_OTP_EXPIRE_MINUTES", "10").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 10
    return max(3, min(30, value))


def _get_otp_secret() -> str:
    return os.environ.get("SECA_OTP_SECRET", SECRET_KEY).strip() or SECRET_KEY


ACCESS_TOKEN_EXPIRE_MINUTES = _get_token_expiry_minutes()
OTP_EXPIRE_MINUTES = _get_otp_expiry_minutes()

DEPARTMENT_GROUPS = {
    "RXS": {
        "label": "RXS",
        "groups": {
            "Infrastructure (Sauvegarde & Stockage)": "Infrastructure (Sauvegarde & Stockage)",
            "Service Système (Messagerie, Identité & Accès)": "Service Système (Messagerie, Identité & Accès)",
            "Service Interconnexion (Routage, Commutation & Sécurité Périmétrique)": "Service Interconnexion (Routage, Commutation & Sécurité Périmétrique)",
            "Service Support (Matériel & Déploiement Logiciel)": "Service Support (Matériel & Déploiement Logiciel)",
            "Service Data Center": "Service Data Center",
        },
    },
    "SLM": {
        "label": "SLM",
        "groups": {
            "Groupe GED": "Groupe GED",
            "Groupe Maintenance": "Groupe Maintenance",
            "Groupe DBA": "Groupe DBA",
            "Groupe Développement": "Groupe Développement",
            "Groupe Qualité": "Groupe Qualité",
            "Groupe Décisionnel & Veille Technologique": "Groupe Décisionnel & Veille Technologique",
        },
    },
    "SSI": {
        "label": "SSI",
        "groups": {
            "Pôle SOC & Sécurité des systèmes": "Pôle SOC & Sécurité des systèmes",
            "Pôle Sécurité Industrielle (OT)": "Pôle Sécurité Industrielle (OT)",
            "Pôle Sécurité Applicative & Gouvernance": "Pôle Sécurité Applicative & Gouvernance",
        },
    },
}
DEPARTMENT_ALIASES = {
    "SSE": "SSI",
}
SEX_VALUES = {"male": "Male", "female": "Female"}


def _get_otp_resend_cooldown_seconds() -> int:
    raw = os.environ.get("SECA_OTP_RESEND_COOLDOWN_SECONDS", "60").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 60
    return max(15, min(600, value))


def _get_otp_max_requests_per_hour() -> int:
    raw = os.environ.get("SECA_OTP_MAX_REQUESTS_PER_HOUR", "5").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 5
    return max(1, min(20, value))


OTP_RESEND_COOLDOWN_SECONDS = _get_otp_resend_cooldown_seconds()
OTP_MAX_REQUESTS_PER_HOUR = _get_otp_max_requests_per_hour()

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        return user_id
    except JWTError:
        return None


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _clean_profile_field(value: Optional[str], field_name: str, max_length: int = 120) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail=f"{field_name} is required")
    if len(cleaned) > max_length:
        raise HTTPException(status_code=400, detail=f"{field_name} is too long")
    return cleaned


def _normalize_sex(value: Optional[str]) -> str:
    cleaned = _clean_profile_field(value, "Sex", 20).lower()
    if cleaned not in SEX_VALUES:
        raise HTTPException(status_code=400, detail="Invalid sex value")
    return SEX_VALUES[cleaned]


def _normalize_department(value: Optional[str]) -> str:
    cleaned = _clean_profile_field(value, "Department", 40).upper()
    cleaned = DEPARTMENT_ALIASES.get(cleaned, cleaned)
    if cleaned not in DEPARTMENT_GROUPS:
        raise HTTPException(status_code=400, detail="Invalid department")
    return cleaned


def _normalize_group_name(department: str, group_name: Optional[str]) -> str:
    cleaned = _clean_profile_field(group_name, "Group", 160)
    available = DEPARTMENT_GROUPS[department]["groups"]
    if cleaned not in available:
        raise HTTPException(status_code=400, detail="Invalid group for selected department")
    return available[cleaned]


def _otp_hash(email: str, purpose: str, code: str) -> str:
    material = f"{_get_otp_secret()}::{purpose}::{_normalize_email(email)}::{code}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _generate_otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _record_auth_audit(db: Session, user_id: Optional[int], action: str, details: str) -> None:
    db.add(models.AuditLog(user_id=user_id, action=action, details=details))
    db.commit()


def _send_email_code(email: str, code: str, purpose: str) -> dict:
    smtp_host = os.environ.get("SECA_SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SECA_SMTP_PORT", "587").strip() or "587")
    smtp_username = os.environ.get("SECA_SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SECA_SMTP_PASSWORD", "").strip()
    smtp_from = os.environ.get("SECA_SMTP_FROM_EMAIL", smtp_username).strip()
    smtp_from_name = os.environ.get("SECA_SMTP_FROM_NAME", "SECA Security").strip() or "SECA Security"
    use_ssl = os.environ.get("SECA_SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
    use_tls = os.environ.get("SECA_SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}

    subject = "SECA account verification code" if purpose == "signup" else "SECA password reset code"
    intro = (
        "Use this one-time code to finish creating your SECA account."
        if purpose == "signup"
        else "Use this one-time code to reset your SECA password."
    )
    body = (
        f"{intro}\n\n"
        f"Code: {code}\n"
        f"This code expires in {OTP_EXPIRE_MINUTES} minutes.\n\n"
        "If you did not request this, you can ignore this email."
    )

    if not smtp_host or not smtp_from:
        print(f"[SECA OTP][DEV FALLBACK] {purpose} code for {email}: {code}")
        return {"delivery": "development_fallback", "debug_code": code}

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{smtp_from_name} <{smtp_from}>"
    message["To"] = email
    message.set_content(body)

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as server:
                if smtp_username and smtp_password:
                    server.login(smtp_username, smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                if use_tls:
                    server.starttls()
                if smtp_username and smtp_password:
                    server.login(smtp_username, smtp_password)
                server.send_message(message)
        return {"delivery": "smtp"}
    except Exception as exc:
        allow_fallback = os.environ.get("SECA_SMTP_ALLOW_DEV_FALLBACK", "true").strip().lower() in {"1", "true", "yes", "on"}
        if allow_fallback:
            print(f"[SECA OTP][SMTP FAILED -> DEV FALLBACK] {purpose} code for {email}: {code} ({exc})")
            return {"delivery": "development_fallback", "debug_code": code}
        raise HTTPException(status_code=503, detail="Failed to send verification email") from exc


def _issue_email_otp(
    db: Session,
    *,
    email: str,
    purpose: str,
    user_id: Optional[int] = None,
    password_hash: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    sex: Optional[str] = None,
    department: Optional[str] = None,
    group_name: Optional[str] = None,
) -> dict:
    now = datetime.utcnow()
    latest = (
        db.query(models.EmailOtp)
        .filter(
            models.EmailOtp.email == email,
            models.EmailOtp.purpose == purpose,
        )
        .order_by(models.EmailOtp.created_at.desc())
        .first()
    )
    if latest:
        elapsed = (now - latest.created_at).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            retry_after = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {retry_after}s before requesting another code",
                headers={"Retry-After": str(retry_after)},
            )

    recent_count = (
        db.query(models.EmailOtp)
        .filter(
            models.EmailOtp.email == email,
            models.EmailOtp.purpose == purpose,
            models.EmailOtp.created_at >= now - timedelta(hours=1),
        )
        .count()
    )
    if recent_count >= OTP_MAX_REQUESTS_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail="Too many verification code requests. Try again later.",
            headers={"Retry-After": "3600"},
        )

    db.query(models.EmailOtp).filter(
        models.EmailOtp.email == email,
        models.EmailOtp.purpose == purpose,
        models.EmailOtp.consumed_at.is_(None),
    ).update({"consumed_at": now}, synchronize_session=False)

    code = _generate_otp_code()
    otp = models.EmailOtp(
        user_id=user_id,
        email=email,
        purpose=purpose,
        code_hash=_otp_hash(email, purpose, code),
        password_hash=password_hash,
        first_name=first_name,
        last_name=last_name,
        sex=sex,
        department=department,
        group_name=group_name,
        expires_at=now + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)
    delivery = _send_email_code(email, code, purpose)
    return {
        "message": "Verification code sent.",
        "expires_in_minutes": OTP_EXPIRE_MINUTES,
        "resend_cooldown_seconds": OTP_RESEND_COOLDOWN_SECONDS,
        **delivery,
    }


def _consume_valid_otp(db: Session, *, email: str, purpose: str, code: str) -> models.EmailOtp:
    now = datetime.utcnow()
    otp = (
        db.query(models.EmailOtp)
        .filter(
            models.EmailOtp.email == email,
            models.EmailOtp.purpose == purpose,
            models.EmailOtp.consumed_at.is_(None),
        )
        .order_by(models.EmailOtp.created_at.desc())
        .first()
    )
    if not otp:
        raise HTTPException(status_code=400, detail="No pending verification code found for this email")
    if otp.expires_at < now:
        otp.consumed_at = now
        db.commit()
        raise HTTPException(status_code=400, detail="Verification code expired")
    if not hmac.compare_digest(otp.code_hash, _otp_hash(email, purpose, code.strip())):
        raise HTTPException(status_code=400, detail="Invalid verification code")
    otp.consumed_at = now
    db.commit()
    return otp


@router.post("/register/request-otp")
def register_request_otp(payload: schemas.SignupOtpRequest, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    first_name = _clean_profile_field(payload.first_name, "First name")
    last_name = _clean_profile_field(payload.last_name, "Last name")
    sex = _normalize_sex(payload.sex)
    department = _normalize_department(payload.department)
    group_name = _normalize_group_name(department, payload.group_name)

    response = _issue_email_otp(
        db,
        email=email,
        purpose="signup",
        password_hash=hash_password(payload.password),
        first_name=first_name,
        last_name=last_name,
        sex=sex,
        department=department,
        group_name=group_name,
    )
    return {
        "email": email,
        **response,
    }


@router.post("/register/verify-otp")
def register_verify_otp(payload: schemas.SignupOtpVerify, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    otp = _consume_valid_otp(db, email=email, purpose="signup", code=payload.code)
    if not otp.password_hash:
        raise HTTPException(status_code=400, detail="Signup request is incomplete. Request a new verification code.")

    new_user = models.User(
        email=email,
        password=otp.password_hash,
        first_name=otp.first_name,
        last_name=otp.last_name,
        sex=otp.sex,
        department=otp.department,
        group_name=otp.group_name,
        is_admin=False,
        role="user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    _record_auth_audit(db, new_user.id, "User Registration", f"Verified signup for {email}")
    return {"id": new_user.id, "email": new_user.email, "message": "User registered successfully"}


@router.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return register_request_otp(
        schemas.SignupOtpRequest(
            first_name=user.first_name or "",
            last_name=user.last_name or "",
            email=user.email,
            sex=user.sex or "",
            department=user.department or "",
            group_name=user.group_name or "",
            password=user.password,
        ),
        db,
    )


@router.post("/password-reset/request-otp")
def password_reset_request(payload: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or user.is_admin:
        return {
            "message": "If the email is eligible, a reset code has been sent.",
            "email": email,
            "expires_in_minutes": OTP_EXPIRE_MINUTES,
        }

    response = _issue_email_otp(db, email=email, purpose="password_reset", user_id=user.id)
    return {
        "message": "If the email is eligible, a reset code has been sent.",
        "email": email,
        **response,
    }


@router.post("/password-reset/confirm")
def password_reset_confirm(payload: schemas.PasswordResetConfirm, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or user.is_admin:
        raise HTTPException(status_code=400, detail="Password reset is not available for this account")

    _consume_valid_otp(db, email=email, purpose="password_reset", code=payload.code)
    user.password = hash_password(payload.new_password)
    db.commit()
    _record_auth_audit(db, user.id, "Password Reset", f"Password reset completed for {email}")
    return {"message": "Password updated successfully"}


@router.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == _normalize_email(user.email)).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    is_valid, needs_rehash = verify_password(user.password, db_user.password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if needs_rehash:
        db_user.password = hash_password(user.password)
        db.commit()

    access_token = create_access_token(data={"sub": str(db_user.id)})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "email": db_user.email,
            "is_admin": db_user.is_admin,
            "first_name": db_user.first_name,
            "last_name": db_user.last_name,
            "sex": db_user.sex,
            "department": db_user.department,
            "group_name": db_user.group_name,
        }
    }


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user_id = verify_token(token)
    print(f"get_current_user: token starts with {token[:20]}..., user_id={user_id}")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    print(f"get_current_user: user found = {user is not None}")
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_admin(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@router.get("/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "role": current_user.role,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "sex": current_user.sex,
        "department": current_user.department,
        "group_name": current_user.group_name,
    }
