# SECA Safe Demo Pack

Use these files for presentation screenshots and controlled tests.

## Safety

- No real malware is included.
- No sample performs persistence, injection, encryption, deletion, or credential theft.
- URL samples use reserved domains such as `.invalid`, `.test`, and `.example`.
- EICAR files are standard antivirus test strings and may be quarantined by Windows Defender or ClamAV.

## Recommended Demo Order

1. Upload `files/fake_invoice.pdf.exe` to show suspicious extension handling.
2. Upload `files/eicar_test_file.com.txt` to show antivirus/YARA-style detection and quarantine behavior.
3. Upload `emails/phishing_invoice_demo.eml` to show email parsing and URL/attachment correlation.
4. Copy URLs from `urls/url_demo_samples.txt` into URL Scanner.

## Notes

- If Windows Defender deletes the EICAR file, that is expected and useful for explaining quarantine.
- Keep these samples in this folder and do not send them to external systems.
- For a live demo, test each sample before the presentation and keep screenshots as backup.
