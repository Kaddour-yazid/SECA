from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def build_ca(subject_name: str, years: int) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "MA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SECA Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a local CA for future SECA HTTPS proxy interception.")
    parser.add_argument("--out-dir", default="proxy_ca", help="Output directory for cert/key files")
    parser.add_argument("--name", default="SECA Local Root CA", help="Common name for the generated CA")
    parser.add_argument("--years", type=int, default=5, help="Certificate validity in years")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / "seca_proxy_ca.crt"
    key_path = out_dir / "seca_proxy_ca.key"

    cert_pem, key_pem = build_ca(subject_name=args.name, years=max(1, args.years))
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    print(f"Generated CA certificate: {cert_path}")
    print(f"Generated CA private key: {key_path}")
    print("Install the CA certificate on client devices before enabling HTTPS interception.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
