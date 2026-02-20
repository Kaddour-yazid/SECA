import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

# Host path on the real machine.
SHARE_ROOT = Path(r"C:\sandbox_share")
# Mapped path as seen from inside Windows Sandbox.
SANDBOX_SHARE_ROOT = os.environ.get("SECA_SANDBOX_MAPPED_FOLDER", r"C:\sandbox_share")

INBOX = SHARE_ROOT / "inbox"
TO_ANALYZE = SHARE_ROOT / "to_analyze"
OUT = SHARE_ROOT / "out"
TOOLS = SHARE_ROOT / "tools"
WSB_PATH = SHARE_ROOT / "session_launch.wsb"
MONITOR_SCRIPT = SHARE_ROOT / "monitor.ps1"


def _ensure_dirs() -> None:
    for path in (INBOX, TO_ANALYZE, OUT, TOOLS):
        path.mkdir(parents=True, exist_ok=True)


def _safe_unlink(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _clear_stale_triggers() -> None:
    for pattern in ("*.scan.json", "*.scan.tmp"):
        for path in INBOX.glob(pattern):
            _safe_unlink(path)


def _write_session_wsb() -> Path:
    """
    Always generate the .wsb file so host/sandbox paths stay in sync with this runner.
    """
    monitor_inside_sandbox = f"{SANDBOX_SHARE_ROOT}\\monitor.ps1"
    content = f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{SHARE_ROOT}</HostFolder>
      <SandboxFolder>{SANDBOX_SHARE_ROOT}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File {monitor_inside_sandbox}</Command>
  </LogonCommand>
</Configuration>
"""
    WSB_PATH.write_text(content, encoding="utf-8")
    return WSB_PATH


def _host_diagnostics(session_id: str) -> Dict[str, object]:
    """
    Runtime diagnostics to quickly detect path or sync issues.
    """
    inbox_files = sorted(p.name for p in INBOX.glob("*.json"))
    try:
        acl = subprocess.run(
            ["icacls", str(INBOX)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except Exception:
        acl = "unavailable"
    return {
        "session_id": session_id,
        "host_share": str(SHARE_ROOT),
        "sandbox_share": SANDBOX_SHARE_ROOT,
        "inbox": str(INBOX),
        "inbox_exists": INBOX.exists(),
        "inbox_files": inbox_files,
        "inbox_acl": acl,
    }


def create_trigger(session_id: str, filename: str, duration: int = 60) -> Path:
    """
    Write trigger atomically so sandbox monitor never sees a partial file.
    """
    trigger = {
        "sessionId": session_id,
        "targetRelativePath": filename,
        "durationSeconds": duration,
    }
    trigger_path = INBOX / f"{session_id}.scan.json"
    tmp_path = INBOX / f"{session_id}.scan.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(trigger, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, trigger_path)
    return trigger_path


def launch_wsb(wsb_path: Path) -> None:
    """Open the .wsb file (Windows launches Windows Sandbox)."""
    os.startfile(str(wsb_path))


def _process_running(image_name: str) -> bool:
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return image_name.lower() in (result.stdout or "").lower()
    except Exception:
        # Avoid false negatives if tasklist is unavailable.
        return True


def _sandbox_alive() -> bool:
    return any(
        _process_running(name)
        for name in (
            "WindowsSandboxRemoteSession.exe",
            "WindowsSandboxServer.exe",
            "WindowsSandbox.exe",
            "vmmemWindowsSandbox.exe",
        )
    )


def wait_for_sandbox_launch(
    timeout: int = 25,
    on_tick: Optional[Callable[[float, float], None]] = None,
    abort_if: Optional[Callable[[], bool]] = None,
) -> bool:
    """Wait until at least one Windows Sandbox process is visible."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        elapsed = time.time() - t0
        if on_tick:
            on_tick(elapsed, float(timeout))
        if abort_if and abort_if():
            return False
        if _sandbox_alive():
            return True
        time.sleep(0.5)
    return False


def wait_for_ready(
    timeout: int = 30,
    min_mtime: Optional[float] = None,
    on_tick: Optional[Callable[[float, float], None]] = None,
    abort_if: Optional[Callable[[], bool]] = None,
) -> bool:
    ready = SHARE_ROOT / "sandbox_ready.txt"
    t0 = time.time()
    while time.time() - t0 < timeout:
        elapsed = time.time() - t0
        if on_tick:
            on_tick(elapsed, float(timeout))
        if ready.exists():
            if min_mtime is None:
                return True
            try:
                if ready.stat().st_mtime >= min_mtime:
                    return True
            except OSError:
                pass
        if abort_if and abort_if():
            return False
        time.sleep(0.5)
    return False


def wait_for_done(
    session_id: str,
    timeout: int = 180,
    on_tick: Optional[Callable[[float, float], None]] = None,
    abort_if: Optional[Callable[[], bool]] = None,
) -> Optional[Path]:
    out_dir = OUT / f"session_{session_id}"
    done_file = out_dir / f"done_{session_id}.json"
    t0 = time.time()
    while time.time() - t0 < timeout:
        elapsed = time.time() - t0
        if on_tick:
            on_tick(elapsed, float(timeout))
        if done_file.exists():
            return out_dir
        if abort_if and abort_if():
            # If the VM exits right after writing artifacts, allow a short grace
            # window so host-side file sync can complete before failing the run.
            grace_deadline = time.time() + 8
            while time.time() < grace_deadline:
                if done_file.exists():
                    return out_dir
                time.sleep(0.5)
            return None
        time.sleep(1)
    return None


def run_dynamic_scan(
    file_bytes: bytes,
    filename: str,
    duration: int = 60,
    launch_wsb_file: bool = True,
    allow_existing_monitor: bool = False,
    on_progress: Optional[Callable[[str, int], None]] = None,
    session_id: Optional[str] = None,
    abort_if: Optional[Callable[[], bool]] = None,
) -> Dict[str, object]:
    """
    file_bytes: raw bytes of uploaded file
    filename: basename only; saved at to_analyze/<filename>
    duration: seconds to monitor inside sandbox
    launch_wsb_file: whether runner should open the .wsb
    """
    def report(step: str, progress: int) -> None:
        if on_progress:
            bounded = max(0, min(100, int(progress)))
            on_progress(step, bounded)

    _ensure_dirs()
    report("Preparing sandbox workspace...", 6)
    session = session_id or uuid.uuid4().hex
    safe_name = Path(filename).name or "uploaded.bin"
    ready_marker = SHARE_ROOT / "sandbox_ready.txt"
    abort_reason: Optional[str] = None

    if abort_if and abort_if():
        return {"status": "error", "reason": "cancelled", "diagnostics": {"session_id": session}}

    if not MONITOR_SCRIPT.exists():
        return {
            "status": "error",
            "reason": "monitor-missing",
            "message": f"Expected monitor script at {MONITOR_SCRIPT}",
        }

    target_path = TO_ANALYZE / safe_name
    with open(target_path, "wb") as handle:
        handle.write(file_bytes)
    report("Writing file to sandbox share...", 10)

    (OUT / f"session_{session}").mkdir(parents=True, exist_ok=True)

    # Keep queue deterministic: a previous failed sample may leave stale triggers behind.
    _clear_stale_triggers()

    trigger_path = create_trigger(session, safe_name, duration)
    report("Writing sandbox trigger...", 15)
    diagnostics = _host_diagnostics(session)
    diagnostics["trigger_path"] = str(trigger_path)

    wsb_path = _write_session_wsb()
    diagnostics["wsb_path"] = str(wsb_path)
    diagnostics["ready_marker"] = str(ready_marker)
    ready_baseline = None

    if launch_wsb_file:
        if ready_marker.exists():
            try:
                ready_marker.unlink()
                diagnostics["stale_ready_removed"] = True
            except OSError:
                diagnostics["stale_ready_removed"] = False
        ready_baseline = time.time()
        print("[INFO] Launching Windows Sandbox via generated .wsb")
        report("Launching Windows Sandbox VM...", 20)
        launch_wsb(wsb_path)

        if not wait_for_sandbox_launch(
            timeout=30,
            on_tick=lambda elapsed, timeout: report(
                "Starting Windows Sandbox process...",
                20 + int(min(1.0, elapsed / max(timeout, 1.0)) * 8),
            ),
            abort_if=abort_if,
        ):
            _safe_unlink(trigger_path)
            diagnostics["launch_failed"] = True
            return {"status": "error", "reason": "sandbox-launch-failed", "diagnostics": diagnostics}

    def should_abort() -> bool:
        nonlocal abort_reason
        if abort_if and abort_if():
            abort_reason = "cancelled"
            return True
        # Give Sandbox a short startup window before deciding it exited.
        if ready_baseline and (time.time() - ready_baseline) > 12 and not _sandbox_alive():
            abort_reason = "sandbox-exited"
            return True
        return False

    print("[INFO] Waiting for sandbox ready marker...")
    session_done_file = OUT / f"session_{session}" / f"done_{session}.json"
    ready_via = ""
    if wait_for_ready(
        timeout=90,
        min_mtime=ready_baseline,
        on_tick=lambda elapsed, timeout: report(
            "Booting sandbox VM...",
            20 + int(min(1.0, elapsed / max(timeout, 1.0)) * 25),
        ),
        abort_if=should_abort,
    ):
        ready_via = "ready-marker"
    elif allow_existing_monitor or not launch_wsb_file:
        # Fallback: if monitor is already running from an existing session,
        # it may consume triggers without rewriting sandbox_ready.txt.
        t0 = time.time()
        fallback_timeout = 25
        while time.time() - t0 < fallback_timeout:
            elapsed = time.time() - t0
            report(
                "Waiting for monitor to pick up trigger...",
                35 + int(min(1.0, elapsed / fallback_timeout) * 10),
            )
            if should_abort():
                break
            if not trigger_path.exists():
                ready_via = "trigger-consumed"
                break
            if session_done_file.exists():
                ready_via = "done-file"
                break
            time.sleep(1)
    else:
        diagnostics["ready_strict_mode"] = True

    if not ready_via:
        reason = abort_reason or "sandbox-not-ready"
        _safe_unlink(trigger_path)
        if reason == "sandbox-exited":
            report("Sandbox session closed unexpectedly.", 35)
        elif reason == "cancelled":
            report("Sandbox scan cancelled.", 35)
        return {"status": "error", "reason": reason, "diagnostics": diagnostics}

    diagnostics["ready_via"] = ready_via

    print("[INFO] Sandbox ready. Waiting for done marker...")
    report("Sandbox ready. Executing file...", 50)
    outdir = wait_for_done(
        session,
        timeout=duration + 120,
        on_tick=lambda elapsed, timeout: report(
            "Executing and collecting telemetry...",
            50 + int(min(1.0, elapsed / max(timeout, 1.0)) * 45),
        ),
        abort_if=should_abort,
    )
    if outdir is None:
        reason = abort_reason or "scan-timeout"
        _safe_unlink(trigger_path)
        if reason == "sandbox-exited":
            report("Sandbox session closed unexpectedly.", 65)
        elif reason == "cancelled":
            report("Sandbox scan cancelled.", 65)
        return {"status": "error", "reason": reason, "diagnostics": diagnostics}

    report("Collecting sandbox artifacts...", 97)
    collected: List[str] = [str(path) for path in outdir.glob("*")]
    return {
        "status": "done",
        "session": session,
        "out_dir": str(outdir),
        "files": collected,
        "diagnostics": diagnostics,
    }


if __name__ == "__main__":
    testfile = Path(r"C:\somepath\sample.pdf")
    with open(testfile, "rb") as handle:
        result = run_dynamic_scan(handle.read(), testfile.name, duration=60, launch_wsb_file=True)
    print(result)
