from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
DB_DIR = BACKEND_DIR / "db"
VENV_DIR = BACKEND_DIR / ".venv"
REQUIREMENTS_FILE = BACKEND_DIR / "requirements.txt"
STAMP_FILE = VENV_DIR / ".requirements.sha256"


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        check=check,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_venv() -> Path:
    python_in_venv = _venv_python()
    if python_in_venv.exists():
        return python_in_venv

    print(f"[setup] Creating virtual environment at: {VENV_DIR}")
    _run([sys.executable, "-m", "venv", str(VENV_DIR)], cwd=BACKEND_DIR)

    if not python_in_venv.exists():
        raise RuntimeError(f"Failed to create virtual environment at {VENV_DIR}")
    return python_in_venv


def _deps_import_ok(python_exe: Path) -> bool:
    probe = _run(
        [
            str(python_exe),
            "-c",
            "import fastapi, sqlalchemy, uvicorn, psycopg2",
        ],
        check=False,
    )
    return probe.returncode == 0


def ensure_dependencies(python_exe: Path) -> None:
    req_hash = _sha256(REQUIREMENTS_FILE)
    stamped_hash = STAMP_FILE.read_text(encoding="utf-8").strip() if STAMP_FILE.exists() else ""

    needs_install = stamped_hash != req_hash or not _deps_import_ok(python_exe)
    if not needs_install:
        print("[setup] Dependencies already satisfied.")
        return

    print("[setup] Installing backend dependencies...")
    _run([str(python_exe), "-m", "pip", "install", "--upgrade", "pip"], cwd=BACKEND_DIR, check=False)
    _run([str(python_exe), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)], cwd=BACKEND_DIR)
    STAMP_FILE.write_text(req_hash, encoding="utf-8")
    print("[setup] Dependencies installed.")


def build_uvicorn_command(python_exe: Path, host: str, port: int, reload_enabled: bool) -> list[str]:
    cmd = [
        str(python_exe),
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        host,
        "--port",
        str(port),
        "--app-dir",
        str(DB_DIR),
    ]
    if reload_enabled:
        cmd.extend(
            [
                "--reload",
                "--reload-dir",
                str(DB_DIR),
                "--reload-exclude",
                "seed_gateway_demo_scans.py",
                "--reload-exclude",
                "sonprj.db",
                "--reload-exclude",
                "sonprj_backup.db",
                "--reload-exclude",
                "security_analyzer.db",
                "--reload-exclude",
                "__pycache__",
            ]
        )
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap and run SECA Postgres backend.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-reload", action="store_true", help="Disable Uvicorn auto-reload")
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="Prepare venv/dependencies and exit without starting the server",
    )
    args = parser.parse_args()

    if not REQUIREMENTS_FILE.exists():
        raise FileNotFoundError(f"Missing requirements file: {REQUIREMENTS_FILE}")
    if not DB_DIR.exists():
        raise FileNotFoundError(f"Missing backend db directory: {DB_DIR}")

    python_exe = ensure_venv()
    ensure_dependencies(python_exe)

    if args.setup_only:
        print("[setup] Completed.")
        return 0

    cmd = build_uvicorn_command(
        python_exe=python_exe,
        host=args.host,
        port=args.port,
        reload_enabled=not args.no_reload,
    )
    print(f"[run] Starting backend from: {DB_DIR}")
    print(f"[run] Using interpreter: {python_exe}")
    print(f"[run] Command: {' '.join(cmd)}")
    return _run(cmd, cwd=BACKEND_DIR, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
