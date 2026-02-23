import argparse
import json
import random
from datetime import datetime, timedelta

from database import SessionLocal
from models import Scan, User

SEED_TAG = "gateway_demo_v1"

PLATFORMS = [
    ("https://chatgpt.com", "suspicious", 42),
    ("https://www.youtube.com", "suspicious", 28),
    ("https://www.linkedin.com", "clean", 18),
    ("https://www.facebook.com", "malicious", 8),
    ("https://x.com", "suspicious", 7),
    ("https://www.reddit.com", "clean", 12),
    ("https://github.com", "clean", 16),
    ("https://stackoverflow.com", "clean", 14),
    ("https://www.wikipedia.org", "clean", 10),
    ("https://www.netflix.com", "malicious", 6),
    ("https://www.tiktok.com", "malicious", 6),
    ("https://www.instagram.com", "malicious", 7),
]


def pick_platform() -> tuple[str, str]:
    population = [(url, status) for (url, status, _w) in PLATFORMS]
    weights = [w for (_url, _status, w) in PLATFORMS]
    return random.choices(population, weights=weights, k=1)[0]


def status_to_score(status: str) -> int:
    if status == "malicious":
        return random.randint(65, 95)
    if status == "suspicious":
        return random.randint(35, 64)
    return random.randint(2, 34)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed demo URL scan rows for Start Gateway UI.")
    parser.add_argument("--count", type=int, default=240, help="Number of demo rows to insert")
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Keep previously seeded rows instead of replacing them",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.is_admin.is_(True)).order_by(User.id.asc()).first()
        fallback_user = db.query(User).order_by(User.id.asc()).first()
        actor = admin_user or fallback_user
        if actor is None:
            print("No users found. Create a user/admin first, then rerun.")
            return 1

        if not args.keep_existing:
            deleted = db.query(Scan).filter(Scan.details.like(f"%{SEED_TAG}%")).delete(synchronize_session=False)
            db.commit()
            if deleted:
                print(f"Removed {deleted} previously seeded rows.")

        now = datetime.utcnow()
        rows: list[Scan] = []

        for idx in range(max(1, args.count)):
            url, status = pick_platform()
            created_at = now - timedelta(minutes=random.randint(0, 60 * 24 * 14), seconds=random.randint(0, 59))
            score = status_to_score(status)
            details = {
                "seed_tag": SEED_TAG,
                "source": "gateway_demo_seed",
                "platform_url": url,
                "generated_at": created_at.isoformat(),
            }
            rows.append(
                Scan(
                    user_id=actor.id,
                    scan_type="url_advanced",
                    target=url,
                    status=status,
                    threat_score=score,
                    details=json.dumps(details),
                    created_at=created_at,
                )
            )

        db.bulk_save_objects(rows)
        db.commit()
        print(f"Inserted {len(rows)} demo scans for user_id={actor.id}.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

