import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


def mask_database_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, hostinfo = netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, _ = userinfo.split(":", 1)
            userinfo = f"{username}:***"
        netloc = f"{userinfo}@{hostinfo}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def get_query_sslmode(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)
    values = query.get("sslmode") or query.get("ssl_mode") or []
    return values[0] if values else "(not set in URL)"


def scalar(conn, sql: str):
    return conn.execute(text(sql)).scalar()


def row(conn, sql: str):
    return conn.execute(text(sql)).mappings().first()


def main() -> int:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(env_path)

    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        print("DATABASE_URL is missing. Set it in backend/.env.")
        return 1

    ssl_mode_env = os.getenv("SECA_DB_SSLMODE", "").strip() or "(not set)"
    print(f"DATABASE_URL: {mask_database_url(db_url)}")
    print(f"SECA_DB_SSLMODE: {ssl_mode_env}")
    print(f"URL sslmode: {get_query_sslmode(db_url)}")
    print("")

    engine = create_engine(db_url, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            server_ssl = scalar(conn, "SHOW ssl;")
            ssl_row = row(
                conn,
                "SELECT ssl, version, cipher, bits "
                "FROM pg_stat_ssl WHERE pid = pg_backend_pid();",
            )
            data_dir = scalar(conn, "SHOW data_directory;")

            print("Transport encryption")
            print(f"- Server SSL setting: {server_ssl}")
            if ssl_row:
                print(
                    "- Current session SSL: "
                    f"{ssl_row.get('ssl')} "
                    f"(version={ssl_row.get('version')}, cipher={ssl_row.get('cipher')}, bits={ssl_row.get('bits')})"
                )
            else:
                print("- Current session SSL: unknown (pg_stat_ssl returned no row)")
            print("")

            threat_stats = row(
                conn,
                "SELECT "
                "COUNT(*) AS total, "
                "COUNT(*) FILTER (WHERE url_encrypted LIKE 'gAAAAA%%') AS fernet_like, "
                "COUNT(*) FILTER (WHERE url_encrypted ILIKE 'http%%') AS plaintext_like "
                "FROM threat_urls;"
            )
            if threat_stats:
                print("Application-level encryption (threat_urls.url_encrypted)")
                print(f"- Total rows: {threat_stats.get('total')}")
                print(f"- Fernet-token-like rows (gAAAAA...): {threat_stats.get('fernet_like')}")
                print(f"- Plaintext-like rows (http...): {threat_stats.get('plaintext_like')}")
                print("")

            phish_count = scalar(conn, "SELECT COUNT(*) FROM phishtank_entries;")
            print("Plaintext risk check")
            print(f"- phishtank_entries rows (stored as plaintext URL in current schema): {phish_count}")
            print("")

            print("At-rest encryption")
            print(f"- PostgreSQL data directory: {data_dir}")
            if isinstance(data_dir, str) and len(data_dir) >= 2 and data_dir[1] == ":":
                drive = data_dir[:2]
                print(f"- Verify disk encryption with: manage-bde -status {drive}")
            else:
                print("- Verify disk encryption with your OS volume encryption tool.")

    except Exception as exc:
        print(f"Database security check failed: {exc}")
        return 1
    finally:
        engine.dispose()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
