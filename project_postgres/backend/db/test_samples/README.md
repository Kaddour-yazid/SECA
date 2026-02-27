## Safe Sandbox Test Samples

### `benign_dynamic_probe.cmd`
Harmless dynamic probe for validating sandbox telemetry:
- launches low-risk processes (`cmd`, `powershell`, `notepad`)
- opens one short-lived outbound TCP connection to `example.com:443`
- writes only a temp log file inside the sandbox guest

This is not malware. It is only for validating your dynamic report pipeline.

### How to use
1. Open your app and go to **File Scanner**.
2. Upload `test_samples/benign_dynamic_probe.cmd`.
3. Run dynamic analysis.
4. Expected result: verdict should stay `clean` or low-confidence, but process/network sections should show activity.
