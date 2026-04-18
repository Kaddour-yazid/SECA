import csv
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator, Optional
from urllib.parse import urlsplit

from database import SessionLocal
from models import ThreatUrl
from security_utils import encrypt_text, get_fernet, sha256_hex


def normalize_url(raw: str) -> Optional[str]:
    value = (raw or "").strip()
    if not value:
        return None

    if "://" not in value:
        value = f"http://{value}"

    try:
        parsed = urlsplit(value)
    except ValueError:
        return None

    if not parsed.hostname:
        return None

    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname.lower().strip(".")
    if not host:
        return None

    port = parsed.port
    include_port = bool(port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)))
    netloc = f"{host}:{port}" if include_port else host

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return f"{scheme}://{netloc}{path}"


def extract_domain(normalized_url: str) -> Optional[str]:
    try:
        parsed = urlsplit(normalized_url)
    except ValueError:
        return None
    return (parsed.hostname or "").lower().strip(".") or None


def iter_text_lines(path: Path) -> Iterator[str]:
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield stripped


def iter_csv_urls(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames:
            preferred = next(
                (
                    name
                    for name in reader.fieldnames
                    if name and name.strip().lower() in {"url", "domain", "link", "ioc", "indicator"}
                ),
                None,
            )
            if preferred:
                for row in reader:
                    value = row.get(preferred)
                    if value:
                        yield value
                return

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        simple_reader = csv.reader(handle)
        for row in simple_reader:
            if row and row[0].strip():
                yield row[0].strip()


def iter_json_urls(path: Path) -> Iterator[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                yield item
            elif isinstance(item, dict):
                for key in ("url", "domain", "link", "ioc", "indicator"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        yield value
                        break
    elif isinstance(payload, dict):
        items = payload.get("items") or payload.get("data") or payload.get("urls") or []
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, dict):
                    for key in ("url", "domain", "link", "ioc", "indicator"):
                        value = item.get(key)
                        if isinstance(value, str) and value.strip():
                            yield value
                            break


def load_candidates(path: Path) -> Iterable[str]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".list"}:
        return iter_text_lines(path)
    if suffix == ".csv":
        return iter_csv_urls(path)
    if suffix == ".json":
        return iter_json_urls(path)
    raise ValueError(f"Unsupported file type: {suffix}. Use .txt, .csv, or .json")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python import_threat_urls.py <file.txt|file.csv|file.json> [source] [threat_type] [verified:true|false] [replace]")
        return 1

    input_path = Path(sys.argv[1]).expanduser().resolve()
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return 1

    source = sys.argv[2].strip() if len(sys.argv) >= 3 and sys.argv[2].strip() else input_path.stem
    threat_type = sys.argv[3].strip() if len(sys.argv) >= 4 and sys.argv[3].strip() else "malicious-url"
    verified = str(sys.argv[4]).strip().lower() != "false" if len(sys.argv) >= 5 else True
    replace = str(sys.argv[5]).strip().lower() in {"1", "true", "yes", "replace"} if len(sys.argv) >= 6 else False

    fernet = get_fernet(required=True)
    db = SessionLocal()

    inserted = 0
    updated = 0
    skipped = 0
    invalid = 0

    try:
        if replace:
            deleted = db.query(ThreatUrl).delete()
            print(f"Cleared existing threat_urls rows: {deleted}")

        for candidate in load_candidates(input_path):
            normalized = normalize_url(candidate)
            if not normalized:
                invalid += 1
                continue

            domain = extract_domain(normalized)
            url_hash = sha256_hex(normalized)
            domain_hash = sha256_hex(domain) if domain else None
            encrypted = encrypt_text(normalized, fernet)

            row = db.query(ThreatUrl).filter(ThreatUrl.url_hash == url_hash).first()
            if row:
                row.url_encrypted = encrypted
                row.domain = domain
                row.domain_hash = domain_hash
                row.threat_type = threat_type
                row.source = source
                row.verified = verified
                updated += 1
            else:
                db.add(
                    ThreatUrl(
                        url_hash=url_hash,
                        url_encrypted=encrypted,
                        domain=domain,
                        domain_hash=domain_hash,
                        threat_type=threat_type,
                        source=source,
                        verified=verified,
                    )
                )
                inserted += 1

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print(f"Imported threat URLs from {input_path}")
    print(f"Source: {source}")
    print(f"Threat type: {threat_type}")
    print(f"Verified: {verified}")
    print(f"Inserted: {inserted}")
    print(f"Updated: {updated}")
    print(f"Invalid skipped: {invalid}")
    print(f"Duplicate unchanged: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
