# SECA Safe Demo Pack

Use these files for presentation screenshots and controlled tests.

## Safety

- No real malware is included.
- No sample performs persistence, injection, encryption, deletion, or credential theft.
- URL samples use reserved domains such as `.invalid`, `.test`, and `.example`.
- EICAR files are standard antivirus test strings and may be quarantined by Windows Defender or ClamAV.

## Recommended Demo Order

1. Upload `files/clean_text_demo.txt` to show the clean baseline.
2. Upload `files/fake_invoice.pdf.exe` to show suspicious extension handling.
3. Upload `files/eicar_quarantine_demo.txt` to show antivirus/YARA-style detection and quarantine behavior.
4. Run `files/suspicious_dynamic_demo.cmd` in the sandbox to show harmless but observable runtime activity.
5. Run `files/malicious_behavior_simulator.cmd` in the sandbox to show process creation, suspicious-path file activity, safe self-deletion, encoded artifact creation, high-risk utility execution, and a blocked `.invalid` beacon-like attempt.
6. Upload `emails/phishing_invoice_demo.eml` to show email parsing and URL/attachment correlation.
7. Copy URLs from `urls/url_demo_samples.txt` into URL Scanner.

## Double-extension demo

- `files/fake_report.pdf.cmd` simulates a deceptive attachment name.
- It is still a `.cmd` script, not a hidden real executable.
- Use it to explain why extensions must be visible and why double extensions are suspicious.

## Windows Sandbox quick launch

- On another machine, run `generate_sandbox_launcher.ps1` first. It creates `run_malicious_simulator_in_sandbox.local.wsb` with the correct local clone path.
- Open `run_malicious_simulator_in_sandbox.local.wsb` to boot Windows Sandbox and run the double-extension demo automatically.
- `run_malicious_simulator_in_sandbox.wsb` is kept as an example for this workstation.
- The `.wsb` maps only the demo `files` folder as read-only.
- If the project folder is moved, update the `<HostFolder>` path inside the `.wsb` file.

## Notes

- If Windows Defender deletes the EICAR file, that is expected and useful for explaining quarantine.
- The dynamic `.cmd` files are behavior simulators. They are designed for sandbox execution and write only demo markers inside `%TEMP%\seca_sandbox_demo` and `%APPDATA%\seca_sandbox_demo`.
- Keep these samples in this folder and do not send them to external systems.
- For a live demo, test each sample before the presentation and keep screenshots as backup.
