import argparse
import getpass
import hashlib

from database import SessionLocal
from models import User


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def prompt_password() -> str:
    while True:
        password = getpass.getpass("Password: ").strip()
        confirm = getpass.getpass("Confirm password: ").strip()
        if not password:
            print("Password cannot be empty.")
            continue
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        return password


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or promote an admin user."
    )
    parser.add_argument("--email", help="Admin email (example: admin@example.com)")
    parser.add_argument("--password", help="Admin password (omit to prompt securely)")
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset password for existing user as well.",
    )
    args = parser.parse_args()

    email = (args.email or input("Admin email: ").strip()).lower()
    if not email:
        print("Email is required.")
        return 1

    password = args.password
    if not password:
        password = prompt_password()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        password_hash = hash_password(password)

        if user is None:
            user = User(
                email=email,
                password=password_hash,
                role="admin",
                is_admin=True,
            )
            db.add(user)
            db.commit()
            print(f"Created admin user: {email}")
            return 0

        changed = False
        if not user.is_admin:
            user.is_admin = True
            changed = True
        if user.role != "admin":
            user.role = "admin"
            changed = True
        if args.reset_password or user.password != password_hash:
            user.password = password_hash
            changed = True

        if changed:
            db.commit()
            print(f"Updated existing user as admin: {email}")
        else:
            print(f"User already admin and unchanged: {email}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
