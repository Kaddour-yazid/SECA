import base64
import hashlib
import hmac
import os
import re
import secrets
from typing import Optional, Tuple

from cryptography.fernet import Fernet

PBKDF2_ID = "pbkdf2_sha256"
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = max(200_000, int(os.environ.get("SECA_PBKDF2_ITERATIONS", "600000")))
LEGACY_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return f"{PBKDF2_ID}${int(iterations)}${_b64_encode(salt)}${_b64_encode(digest)}"


def _verify_pbkdf2(password: str, stored_hash: str) -> Tuple[bool, bool]:
    try:
        algo, iterations_raw, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algo != PBKDF2_ID:
            return False, False
        iterations = int(iterations_raw)
        salt = _b64_decode(salt_b64)
        expected = _b64_decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            PBKDF2_ALGORITHM,
            password.encode("utf-8"),
            salt,
            iterations,
        )
        is_valid = hmac.compare_digest(actual, expected)
        needs_rehash = is_valid and iterations < PBKDF2_ITERATIONS
        return is_valid, needs_rehash
    except Exception:
        return False, False


def verify_password(password: str, stored_hash: str) -> Tuple[bool, bool]:
    """
    Returns:
    - is_valid
    - needs_rehash (for legacy/weak hashes)
    """
    if not stored_hash:
        return False, False

    if stored_hash.startswith(f"{PBKDF2_ID}$"):
        return _verify_pbkdf2(password, stored_hash)

    # Legacy format in this project: plain sha256(password).hexdigest()
    if LEGACY_SHA256_RE.fullmatch(stored_hash):
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        ok = hmac.compare_digest(legacy, stored_hash.lower())
        return ok, ok

    return False, False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_fernet(required: bool = False) -> Optional[Fernet]:
    key = os.environ.get("SECA_URL_ENCRYPTION_KEY", "").strip()
    if not key:
        if required:
            raise RuntimeError(
                "SECA_URL_ENCRYPTION_KEY is missing. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return None
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Invalid SECA_URL_ENCRYPTION_KEY format.") from exc


def encrypt_text(value: str, fernet: Fernet) -> str:
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_text(value: str, fernet: Fernet) -> str:
    return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
