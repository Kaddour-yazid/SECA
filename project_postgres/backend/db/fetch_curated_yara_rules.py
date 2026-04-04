import io
import json
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path


SIGNATURE_BASE_ZIP_URL = "https://codeload.github.com/Neo23x0/signature-base/zip/refs/heads/master"
EXCLUDED_FILES = {
    "generic_anomalies.yar",
    "general_cloaking.yar",
    "gen_webshells_ext_vars.yar",
    "thor_inverse_matches.yar",
    "yara_mixed_ext_vars.yar",
    "configured_vulns_ext_vars.yar",
    "gen_fake_amsi_dll.yar",
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar",
    "yara-rules_vuln_drivers_strict_renamed.yar",
}


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (base_dir / "yara_rules" / "signature-base")
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = Path(temp_dir) / "signature-base.zip"
        with urllib.request.urlopen(SIGNATURE_BASE_ZIP_URL, timeout=60) as response:
            archive_path.write_bytes(response.read())

        with zipfile.ZipFile(archive_path, "r") as archive:
            root_prefix = next(
                (name.split("/", 1)[0] for name in archive.namelist() if name.endswith("/yara/") or "/yara/" in name),
                None,
            )
            if not root_prefix:
                raise RuntimeError("Unable to locate yara/ directory inside signature-base archive")

            extracted = 0
            skipped = 0
            if output_dir.exists():
                shutil.rmtree(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            for member in archive.infolist():
                member_name = member.filename.replace("\\", "/")
                yara_segment = f"{root_prefix}/yara/"
                if yara_segment not in member_name or member.is_dir():
                    continue
                relative_name = member_name.split(yara_segment, 1)[1]
                if not relative_name:
                    continue
                target_path = output_dir / relative_name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if target_path.name.lower() in EXCLUDED_FILES:
                    skipped += 1
                    continue
                if not target_path.suffix.lower() in {".yar", ".yara"}:
                    continue
                with archive.open(member) as source, open(target_path, "wb") as destination:
                    destination.write(source.read())
                extracted += 1

    manifest = {
        "source": "Neo23x0/signature-base",
        "url": SIGNATURE_BASE_ZIP_URL,
        "extracted_rules": extracted,
        "skipped_rules": skipped,
        "excluded_files": sorted(EXCLUDED_FILES),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Downloaded curated YARA rules to {output_dir} ({extracted} files, skipped {skipped})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
