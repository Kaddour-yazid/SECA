import argparse
import csv
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import urlsplit, urlunsplit

from database import SessionLocal
from models import ThreatUrl
from security_utils import encrypt_text, get_fernet, sha256_hex


DEFAULT_DATASET = "sid321axn/malicious-urls-dataset"
DEFAULT_SOURCE = "Kaggle: sid321axn/malicious-urls-dataset"
DEFAULT_CSV_NAME = "malicious_phish.csv"
DEFAULT_IMPORT_TYPES = ("phishing", "malware", "defacement")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download and import the Kaggle malicious URLs dataset into threat_urls."
    )
    parser.add_argument("--dataset", default=DEFAULT_DATASET, help="Kaggle dataset identifier.")
    parser.add_argument(
        "--csv-name",
        default=DEFAULT_CSV_NAME,
        help="CSV filename inside the downloaded dataset directory.",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="Source label stored in threat_urls.source.",
    )
    parser.add_argument(
        "--include-types",
        nargs="+",
        default=list(DEFAULT_IMPORT_TYPES),
        help="Threat types to import from the dataset.",
    )
    parser.add_argument(
        "--verified",
        action="store_true",
        help="Mark imported rows as verified. Default is false because this is a third-party dataset.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2000,
        help="How many inserts to commit per batch.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional row limit for testing. 0 means no limit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and normalize rows without writing to PostgreSQL.",
    )
    return parser.parse_args()


def dataset_download(dataset: str) -> Path:
    try:
        import kagglehub
    except ImportError as exc:
        raise RuntimeError(
            "kagglehub is not installed. Run: pip install kagglehub"
        ) from exc

    return Path(kagglehub.dataset_download(dataset))


def normalize_url(raw_url: str) -> tuple[str, str] | None:
    value = (raw_url or "").strip()
    if not value:
        return None

    schemes: Sequence[str]
    if "://" in value:
        schemes = ("",)
    else:
        schemes = ("https://", "http://")

    for prefix in schemes:
        candidate = f"{prefix}{value}"
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        if not parsed.netloc:
            continue

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            continue

        netloc = parsed.netloc.lower()
        path = parsed.path or ""
        query = parsed.query or ""
        normalized = urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))
        return normalized, hostname

    return None


def iter_candidate_rows(
    csv_path: Path,
    include_types: set[str],
    limit: int = 0,
) -> Iterator[tuple[str, str, str]]:
    yielded = 0
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            threat_type = (row.get("type") or "").strip().lower()
            if threat_type not in include_types:
                continue

            normalized = normalize_url(row.get("url") or "")
            if not normalized:
                continue

            normalized_url, domain = normalized
            yield normalized_url, domain, threat_type
            yielded += 1

            if limit and yielded >= limit:
                return


def load_existing_hashes(db) -> set[str]:
    return {row[0] for row in db.query(ThreatUrl.url_hash).all()}


def flush_batch(db, pending: list[ThreatUrl], dry_run: bool) -> int:
    if not pending:
        return 0

    count = len(pending)
    if not dry_run:
        db.bulk_save_objects(pending)
        db.commit()
    pending.clear()
    return count


def main() -> None:
    args = parse_args()
    include_types = {value.strip().lower() for value in args.include_types if value.strip()}
    if not include_types:
        raise RuntimeError("At least one threat type must be included.")

    dataset_dir = dataset_download(args.dataset)
    csv_path = dataset_dir / args.csv_name
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")

    fernet = get_fernet(required=True)
    db = SessionLocal()

    scanned = 0
    prepared = 0
    inserted = 0
    duplicate = 0
    pending: list[ThreatUrl] = []

    try:
        existing_hashes = load_existing_hashes(db)

        for normalized_url, domain, threat_type in iter_candidate_rows(csv_path, include_types, args.limit):
            scanned += 1
            url_hash = sha256_hex(normalized_url)
            if url_hash in existing_hashes:
                duplicate += 1
                continue

            pending.append(
                ThreatUrl(
                    url_hash=url_hash,
                    url_encrypted=encrypt_text(normalized_url, fernet),
                    domain=domain,
                    domain_hash=sha256_hex(domain),
                    threat_type=threat_type,
                    source=args.source,
                    verified=bool(args.verified),
                )
            )
            existing_hashes.add(url_hash)
            prepared += 1

            if len(pending) >= args.batch_size:
                inserted += flush_batch(db, pending, args.dry_run)

        inserted += flush_batch(db, pending, args.dry_run)
    finally:
        db.close()

    print(f"Dataset directory: {dataset_dir}")
    print(f"CSV file: {csv_path}")
    print(f"Included threat types: {', '.join(sorted(include_types))}")
    print(f"Rows scanned after filtering: {scanned}")
    print(f"Rows prepared: {prepared}")
    print(f"Duplicates skipped: {duplicate}")
    print(f"Rows {'that would be inserted' if args.dry_run else 'inserted'}: {inserted}")


if __name__ == "__main__":
    main()
