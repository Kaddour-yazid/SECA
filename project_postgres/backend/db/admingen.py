import argparse
import getpass
from difflib import SequenceMatcher
from typing import Dict, List
import re
import unicodedata

from database import SessionLocal
from models import User
from security_utils import hash_password


DEPARTMENT_GROUPS: Dict[str, List[str]] = {
    "RXS": [
        "Infrastructure (Sauvegarde & Stockage)",
        "Service Système (Messagerie, Identité & Accès)",
        "Service Interconnexion (Routage, Commutation & Sécurité Périmétrique)",
        "Service Support (Matériel & Déploiement Logiciel)",
        "Service Data Center",
    ],
    "SLM": [
        "Groupe GED",
        "Groupe Maintenance",
        "Groupe DBA",
        "Groupe Développement",
        "Groupe Qualité",
        "Groupe Décisionnel & Veille Technologique",
    ],
    "SSI": [
        "Sécurité des Systèmes",
        "Sécurité Industrielle (OT)",
        "Sécurité Applicative & Gouvernance",
    ],
}

DEPARTMENT_ALIASES = {
    "SSE": "SSI",
}

SEX_VALUES = {
    "male": "Male",
    "female": "Female",
}


def prompt_password() -> str:
    while True:
        password = getpass.getpass("Password: ").strip()
        confirm = getpass.getpass("Confirm password: ").strip()
        if not password:
            print("Password cannot be empty.")
            continue
        if len(password) < 8:
            print("Password must contain at least 8 characters.")
            continue
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        return password


def prompt_required(label: str) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print(f"{label} is required.")


def normalize_department(value: str) -> str:
    cleaned = (value or "").strip().upper()
    cleaned = DEPARTMENT_ALIASES.get(cleaned, cleaned)
    if cleaned not in DEPARTMENT_GROUPS:
        raise ValueError(f"Invalid department: {value}")
    return cleaned


def normalize_sex(value: str) -> str:
    cleaned = (value or "").strip().lower()
    if cleaned not in SEX_VALUES:
        raise ValueError("Sex must be one of: male, female")
    return SEX_VALUES[cleaned]


def _group_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    normalized = normalized.encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized.lower()).strip()
    return normalized


def normalize_group_name(department: str, group_name: str) -> str:
    cleaned = (group_name or "").strip()
    groups = DEPARTMENT_GROUPS[department]
    if cleaned in groups:
        return cleaned

    cleaned_key = _group_key(cleaned)
    for candidate in groups:
        if _group_key(candidate) == cleaned_key:
            return candidate

    best_match = None
    best_ratio = 0.0
    for candidate in groups:
        ratio = SequenceMatcher(None, cleaned_key, _group_key(candidate)).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = candidate

    if best_match and best_ratio >= 0.78:
        return best_match

    raise ValueError(f"Invalid group for {department}: {group_name}")


def prompt_department() -> str:
    print("Available departments:")
    for department, groups in DEPARTMENT_GROUPS.items():
        print(f"  - {department} ({len(groups)} groups)")
    print("  - SSE (alias of SSI)")
    while True:
        raw = input("Department: ").strip()
        try:
            return normalize_department(raw)
        except ValueError as exc:
            print(exc)


def prompt_group(department: str) -> str:
    groups = DEPARTMENT_GROUPS[department]
    print(f"Available groups for {department}:")
    for index, group_name in enumerate(groups, start=1):
        print(f"  {index}. {group_name}")
    while True:
        raw = input("Group number or exact name: ").strip()
        if raw.isdigit():
            index = int(raw)
            if 1 <= index <= len(groups):
                return groups[index - 1]
        try:
            return normalize_group_name(department, raw)
        except ValueError as exc:
            print(exc)


def list_structure() -> int:
    total = 0
    print("Admin structure by department:")
    for department, groups in DEPARTMENT_GROUPS.items():
        total += len(groups)
        print(f"{department}: {len(groups)} group admins")
        for index, group_name in enumerate(groups, start=1):
            print(f"  {index}. {group_name}")
    print(f"Total possible group-scoped admins: {total}")
    print("Alias: SSE -> SSI")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or promote an admin user with profile metadata.")
    parser.add_argument("--email", help="Admin email (example: admin@example.com)")
    parser.add_argument("--password", help="Admin password (omit to prompt securely)")
    parser.add_argument("--first-name", help="First name")
    parser.add_argument("--last-name", help="Last name")
    parser.add_argument("--sex", help="Sex value: male or female")
    parser.add_argument("--department", help="Department code: RXS, SLM, SSI or SSE")
    parser.add_argument("--group", dest="group_name", help="Exact group name for the selected department")
    parser.add_argument("--list-structure", action="store_true", help="List supported departments and groups, then exit")
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset password for existing user as well.",
    )
    args = parser.parse_args()

    if args.list_structure:
        return list_structure()

    email = (args.email or prompt_required("Admin email")).strip().lower()
    password = args.password or prompt_password()
    first_name = (args.first_name or prompt_required("First name")).strip()
    last_name = (args.last_name or prompt_required("Last name")).strip()

    if args.sex:
        try:
            sex = normalize_sex(args.sex)
        except ValueError as exc:
            print(exc)
            return 1
    else:
        while True:
            try:
                sex = normalize_sex(prompt_required("Sex (male/female)"))
                break
            except ValueError as exc:
                print(exc)

    if args.department:
        try:
            department = normalize_department(args.department)
        except ValueError as exc:
            print(exc)
            return 1
    else:
        department = prompt_department()

    if args.group_name:
        try:
            group_name = normalize_group_name(department, args.group_name)
        except ValueError as exc:
            print(exc)
            return 1
    else:
        group_name = prompt_group(department)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        password_hash = hash_password(password)

        if user is None:
            user = User(
                email=email,
                password=password_hash,
                first_name=first_name,
                last_name=last_name,
                sex=sex,
                department=department,
                group_name=group_name,
                role="admin",
                is_admin=True,
            )
            db.add(user)
            db.commit()
            print(f"Created admin user: {email}")
            print(f"Department: {department}")
            print(f"Group: {group_name}")
            return 0

        changed = False
        updates = {
            "first_name": first_name,
            "last_name": last_name,
            "sex": sex,
            "department": department,
            "group_name": group_name,
            "role": "admin",
            "is_admin": True,
        }

        for field_name, field_value in updates.items():
            if getattr(user, field_name) != field_value:
                setattr(user, field_name, field_value)
                changed = True

        if args.reset_password or user.password != password_hash:
            user.password = password_hash
            changed = True

        if changed:
            db.commit()
            print(f"Updated existing user as admin: {email}")
            print(f"Department: {department}")
            print(f"Group: {group_name}")
        else:
            print(f"User already admin and unchanged: {email}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
