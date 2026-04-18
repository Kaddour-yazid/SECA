import csv
import sys
from pathlib import Path
from urllib.parse import urlsplit

import kagglehub


DATASET_REF = "sid321axn/malicious-urls-dataset"
DEFAULT_FILENAME = "malicious_phish.csv"
OUTPUT_FILENAME = "generated_kaggle_url_feed.txt"
MALICIOUS_LABELS = {"phishing", "malware", "defacement"}


def normalize_url(raw: str) -> str | None:
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


def find_dataset_csv(root: Path) -> Path:
    csv_path = root / DEFAULT_FILENAME
    if csv_path.exists():
        return csv_path
    candidates = sorted(root.glob("*.csv"))
    if not candidates:
        raise FileNotFoundError(f"No CSV file found in {root}")
    return candidates[0]


def main() -> int:
    dataset_root = Path(kagglehub.dataset_download(DATASET_REF))
    csv_path = find_dataset_csv(dataset_root)
    output_path = Path(__file__).resolve().parent / OUTPUT_FILENAME

    written = 0
    seen: set[str] = set()

    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle, output_path.open(
        "w", encoding="utf-8", newline=""
    ) as out:
        out.write("# Auto-generated from Kaggle dataset sid321axn/malicious-urls-dataset\n")
        out.write("# Format: normalized_url,threat_type\n")

        reader = csv.DictReader(handle)
        for row in reader:
            raw_type = (row.get("type") or "").strip().lower()
            if raw_type not in MALICIOUS_LABELS:
                continue
            normalized = normalize_url(row.get("url") or "")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.write(f"{normalized},{raw_type}\n")
            written += 1

    print(f"Downloaded dataset to: {dataset_root}")
    print(f"Source CSV: {csv_path}")
    print(f"Generated feed: {output_path}")
    print(f"Malicious entries written: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
