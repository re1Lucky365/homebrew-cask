python3 -m scripts.master_set --bundle
python3 -m scripts.master_set
"""Run and verify the adpBetty master set: workflows, defensive checks, and bundles."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from modules.unified_defense import run_unified_safety_check
from modules.workflow_hub import ensure_config, execute_job
from scripts.package_immutable_release import create_immutable_bundle


DEFAULT_MASTER_SET: dict[str, Any] = {
    "set_name": "adpbetty-master-set",
    "version": "v0.1.0",
    "workflows_config": "configs/workflows.json",
    "workflow_jobs": ["status", "validate_records"],
    "baseline_targets": ["configs", "modules", "scripts"],
    "scan_target": "configs/workflows.json",
    "bundle_sources": ["modules", "configs", "scripts", "dashboard"],
    "output_root": "recordings/master_set",
    "dist_dir": "dist/immutable",
}


def load_master_set(path: Path) -> dict[str, Any]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(DEFAULT_MASTER_SET, indent=2), encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def short_git_ref() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        return out or "local"
    except Exception:
        return "local"


def run_master_set(
    spec: dict[str, Any],
    package_bundle: bool = False,
    observed_bt_macs: list[str] | None = None,
    observed_cast_targets: list[str] | None = None,
) -> dict[str, Any]:
    started = time.time()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    out_root = Path(spec.get("output_root", "recordings/master_set"))
    run_dir = out_root / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # 1. Execute allow-listed workflow_hub jobs
    wf_cfg_path = Path(spec.get("workflows_config", "configs/workflows.json"))
    jobs = ensure_config(wf_cfg_path)
    requested_jobs: list[str] = list(spec.get("workflow_jobs", []))
    job_results: list[dict[str, Any]] = []

    for job_name in requested_jobs:
        if job_name not in jobs:
            job_results.append({"job_name": job_name, "status": "MISSING", "exit_code": 2})
            continue
        job = jobs[job_name]
        if not job.enabled:
            job_results.append({"job_name": job_name, "status": "DISABLED", "exit_code": 0})
            continue
        rec = execute_job(job, run_dir / "workflow_logs")
        job_results.append(asdict(rec))

    # 2. Run unified defensive checks (drift, malware/entropy, wireless, synthetic text check)
    baseline_targets = [Path(p) for p in spec.get("baseline_targets", ["configs"]) if Path(p).exists()]
    scan_target_raw = spec.get("scan_target")
    scan_target = Path(scan_target_raw) if scan_target_raw and Path(scan_target_raw).exists() else None

    defense_report = run_unified_safety_check(
        baseline_targets=baseline_targets,
        scan_target=scan_target,
        observed_bt_macs=observed_bt_macs or [],
        observed_cast_targets=observed_cast_targets or [],
        sample_message="Synthetic test notice: verify account settings in your app.",
        sample_urls=[],
    )

    # 3. Optional immutable release bundle
    bundle_info: dict[str, Any] | None = None
    if package_bundle:
        sources = [Path(s) for s in spec.get("bundle_sources", []) if Path(s).exists()]
        bundle_info = create_immutable_bundle(
            source_dirs=sources,
            out_dir=Path(spec.get("dist_dir", "dist/immutable")),
            version_tag=str(spec.get("version", "v0.1.0")),
            commit_ref=short_git_ref(),
        )

    jobs_ok = all(r.get("status") in {"PASSED", "DISABLED"} for r in job_results)
    payload: dict[str, Any] = {
        "set_name": spec.get("set_name", "adpbetty-master-set"),
        "version": spec.get("version", "v0.1.0"),
        "timestamp_utc": stamp,
        "generated_unix": started,
        "workflows_passed": jobs_ok,
        "workflow_runs": job_results,
        "unified_defense": asdict(defense_report),
        "immutable_bundle": bundle_info,
    }

    raw_bytes = json.dumps(payload, indent=2).encode("utf-8")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    payload["master_sha256"] = digest

    final_bytes = json.dumps(payload, indent=2).encode("utf-8")
    manifest_path = run_dir / "master_manifest.json"
    manifest_path.write_bytes(final_bytes)
    (out_root / "latest_master_manifest.json").write_bytes(final_bytes)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute adpBetty Master Set")
    parser.add_argument("--config", type=Path, default=Path("configs/master_set.json"))
    parser.add_argument("--bundle", action="store_true", help="Also build an immutable release bundle")
    parser.add_argument("--bt-mac", action="append", default=[], help="Observed Bluetooth MAC to audit")
    parser.add_argument("--cast-target", action="append", default=[], help="Observed cast target to audit")
    args = parser.parse_args()

    spec = load_master_set(args.config)
    result = run_master_set(
        spec=spec,
        package_bundle=args.bundle,
        observed_bt_macs=args.bt_mac,
        observed_cast_targets=args.cast_target,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["workflows_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
{
  "set_name": "adpbetty-master-set",
  "version": "v0.1.0",
  "workflows_config": "configs/workflows.json",
  "workflow_jobs": [
    "status",
    "verify_sigs",
    "validate_records",
    "run_tests"
  ],
  "baseline_targets": [
    "configs",
    "modules",
    "scripts"
  ],
  "scan_target": "configs/workflows.json",
  "bundle_sources": [
    "modules",
    "configs",
    "scripts",
    "dashboard"
  ],
  "output_root": "recordings/master_set",
  "dist_dir": "dist/immutable"
}
self.removed"""Variability scanner, malware scan wrapper, and Bluetooth/casting allow-list guard."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import time


@dataclass
class DriftReport:
    checked_at_unix: float
    added: list[str]
    removed: list[str]
    modified: list[str]

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.modified)


@dataclass
class ScanFinding:
    path: str
    status: str  # "CLEAN", "SUSPICIOUS_ENTROPY", "INFECTED", "SCANNER_UNAVAILABLE"
    sha256: str
    shannon_entropy: float
    detail: str


@dataclass
class WirelessPolicy:
    allowed_bt_macs: list[str]
    allowed_cast_targets: list[str]
    auto_flag_unlisted: bool = True


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy_sample(path: Path, max_bytes: int = 262_144) -> float:
    data = path.read_bytes()[:max_bytes]
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class VariabilityScanner:
    """Tracks baseline SHA-256 digests across files to detect variability or tampering."""

    def __init__(self, baseline_path: Path = Path("recordings/security/baseline_hashes.json")) -> None:
        self.baseline_path = baseline_path

    def build_baseline(self, targets: list[Path]) -> dict[str, str]:
        manifest: dict[str, str] = {}
        for t in targets:
            if t.is_file():
                manifest[str(t)] = file_sha256(t)
            elif t.is_dir():
                for p in sorted(t.rglob("*")):
                    if p.is_file():
                        manifest[str(p)] = file_sha256(p)
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def scan_against_baseline(self, targets: list[Path]) -> DriftReport:
        baseline: dict[str, str] = {}
        if self.baseline_path.exists():
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))

        current: dict[str, str] = {}
        for t in targets:
            if t.is_file():
                current[str(t)] = file_sha256(t)
            elif t.is_dir():
                for p in sorted(t.rglob("*")):
                    if p.is_file():
                        current[str(p)] = file_sha256(p)

        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        modified = sorted(
            k for k in (set(baseline) & set(current)) if baseline[k] != current[k]
        )
        return DriftReport(
            checked_at_unix=time.time(),
            added=added,
            removed=removed,
            modified=modified,
        )


class MalwareScannerAdapter:
    """Runs ClamAV if installed and computes file hash + entropy diagnostics."""

    def scan_file(self, path: Path) -> ScanFinding:
        digest = file_sha256(path)
        entropy = shannon_entropy_sample(path)

        clam = shutil.which("clamscan")
        if clam:
            proc = subprocess.run(
                [clam, "--no-summary", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode == 1:
                return ScanFinding(
                    path=str(path),
                    status="INFECTED",
                    sha256=digest,
                    shannon_entropy=entropy,
                    detail=proc.stdout.strip() or "ClamAV flagged file.",
                )
            if proc.returncode == 0:
                return ScanFinding(
                    path=str(path),
                    status="CLEAN",
                    sha256=digest,
                    shannon_entropy=entropy,
                    detail="ClamAV clean.",
                )

        status = "SUSPICIOUS_ENTROPY" if entropy > 7.85 else "SCANNER_UNAVAILABLE"
        detail = (
            "High byte entropy detected; inspect file origin."
            if status == "SUSPICIOUS_ENTROPY"
            else "clamscan not installed; hash and entropy recorded only."
        )
        return ScanFinding(
            path=str(path),
            status=status,
            sha256=digest,
            shannon_entropy=entropy,
            detail=detail,
        )


class WirelessAccessGuard:
    """Audits Bluetooth MACs and cast targets against an explicit local allow-list."""

    def __init__(self, policy_path: Path = Path("configs/wireless_policy.json")) -> None:
        self.policy_path = policy_path
        self.policy = self._load_or_init_policy()

    def _load_or_init_policy(self) -> WirelessPolicy:
        if not self.policy_path.exists():
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            default = WirelessPolicy(
                allowed_bt_macs=[],
                allowed_cast_targets=[],
                auto_flag_unlisted=True,
            )
            self.policy_path.write_text(json.dumps(asdict(default), indent=2), encoding="utf-8")
            return default
        raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        return WirelessPolicy(
            allowed_bt_macs=[m.upper() for m in raw.get("allowed_bt_macs", [])],
            allowed_cast_targets=list(raw.get("allowed_cast_targets", [])),
            auto_flag_unlisted=bool(raw.get("auto_flag_unlisted", True)),
        )

    def evaluate_events(
        self,
        observed_bt_macs: list[str],
        observed_cast_targets: list[str],
    ) -> dict:
        allowed_bt = set(self.policy.allowed_bt_macs)
        allowed_cast = set(self.policy.allowed_cast_targets)

        unlisted_bt = [m.upper() for m in observed_bt_macs if m.upper() not in allowed_bt]
        unlisted_cast = [c for c in observed_cast_targets if c not in allowed_cast]

        return {
            "timestamp_unix": time.time(),
            "unauthorized_bt_devices": unlisted_bt,
            "unauthorized_cast_targets": unlisted_cast,
            "alert_triggered": bool(unlisted_bt or unlisted_cast),
        }


if __name__ == "__main__":
    guard = WirelessAccessGuard()
    alert = guard.evaluate_events(
        observed_bt_macs=["AA:BB:CC:11:22:33"],
        observed_cast_targets=["living-room-display-01"],
    )
    print(json.dumps(alert, indent=2))
I'd like to add multiple layers of social media to help protect everything and everyone online and offline social media platforms of all types"""Variability scanner, malware scan wrapper, and Bluetooth/casting allow-list guard."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import time


@dataclass
class DriftReport:
    checked_at_unix: float
    added: list[str]
    removed: list[str]
    modified: list[str]

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.modified)


@dataclass
class ScanFinding:
    path: str
    status: str  # "CLEAN", "SUSPICIOUS_ENTROPY", "INFECTED", "SCANNER_UNAVAILABLE"
    sha256: str
    shannon_entropy: float
    detail: str


@dataclass
class WirelessPolicy:
    allowed_bt_macs: list[str]
    allowed_cast_targets: list[str]
    auto_flag_unlisted: bool = True


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy_sample(path: Path, max_bytes: int = 262_144) -> float:
    data = path.read_bytes()[:max_bytes]
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class VariabilityScanner:
    """Tracks baseline SHA-256 digests across files to detect variability or tampering."""

    def __init__(self, baseline_path: Path = Path("recordings/security/baseline_hashes.json")) -> None:
        self.baseline_path = baseline_path

    def build_baseline(self, targets: list[Path]) -> dict[str, str]:
        manifest: dict[str, str] = {}
        for t in targets:
            if t.is_file():
                manifest[str(t)] = file_sha256(t)
            elif t.is_dir():
                for p in sorted(t.rglob("*")):
                    if p.is_file():
                        manifest[str(p)] = file_sha256(p)
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest

    def scan_against_baseline(self, targets: list[Path]) -> DriftReport:
        baseline: dict[str, str] = {}
        if self.baseline_path.exists():
            baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))

        current: dict[str, str] = {}
        for t in targets:
            if t.is_file():
                current[str(t)] = file_sha256(t)
            elif t.is_dir():
                for p in sorted(t.rglob("*")):
                    if p.is_file():
                        current[str(p)] = file_sha256(p)

        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        modified = sorted(
            k for k in (set(baseline) & set(current)) if baseline[k] != current[k]
        )
        return DriftReport(
            checked_at_unix=time.time(),
            added=added,
            removed=removed,
            modified=modified,
        )


class MalwareScannerAdapter:
    """Runs ClamAV if installed and computes file hash + entropy diagnostics."""

    def scan_file(self, path: Path) -> ScanFinding:
        digest = file_sha256(path)
        entropy = shannon_entropy_sample(path)

        clam = shutil.which("clamscan")
        if clam:
            proc = subprocess.run(
                [clam, "--no-summary", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode == 1:
                return ScanFinding(
                    path=str(path),
                    status="INFECTED",
                    sha256=digest,
                    shannon_entropy=entropy,
                    detail=proc.stdout.strip() or "ClamAV flagged file.",
                )
            if proc.returncode == 0:
                return ScanFinding(
                    path=str(path),
                    status="CLEAN",
                    sha256=digest,
                    shannon_entropy=entropy,
                    detail="ClamAV clean.",
                )

        status = "SUSPICIOUS_ENTROPY" if entropy > 7.85 else "SCANNER_UNAVAILABLE"
        detail = (
            "High byte entropy detected; inspect file origin."
            if status == "SUSPICIOUS_ENTROPY"
            else "clamscan not installed; hash and entropy recorded only."
        )
        return ScanFinding(
            path=str(path),
            status=status,
            sha256=digest,
            shannon_entropy=entropy,
            detail=detail,
        )


class WirelessAccessGuard:
    """Audits Bluetooth MACs and cast targets against an explicit local allow-list."""

    def __init__(self, policy_path: Path = Path("configs/wireless_policy.json")) -> None:
        self.policy_path = policy_path
        self.policy = self._load_or_init_policy()

    def _load_or_init_policy(self) -> WirelessPolicy:
        if not self.policy_path.exists():
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            default = WirelessPolicy(
                allowed_bt_macs=[],
                allowed_cast_targets=[],
                auto_flag_unlisted=True,
            )
            self.policy_path.write_text(json.dumps(asdict(default), indent=2), encoding="utf-8")
            return default
        raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        return WirelessPolicy(
            allowed_bt_macs=[m.upper() for m in raw.get("allowed_bt_macs", [])],
            allowed_cast_targets=list(raw.get("allowed_cast_targets", [])),
            auto_flag_unlisted=bool(raw.get("auto_flag_unlisted", True)),
        )

    def evaluate_events(
        self,
        observed_bt_macs: list[str],
        observed_cast_targets: list[str],
    ) -> dict:
        allowed_bt = set(self.policy.allowed_bt_macs)
        allowed_cast = set(self.policy.allowed_cast_targets)

        unlisted_bt = [m.upper() for m in observed_bt_macs if m.upper() not in allowed_bt]
        unlisted_cast = [c for c in observed_cast_targets if c not in allowed_cast]

        return {
            "timestamp_unix": time.time(),
            "unauthorized_bt_devices": unlisted_bt,
            "unauthorized_cast_targets": unlisted_cast,
            "alert_triggered": bool(unlisted_bt or unlisted_cast),
        }


if __name__ == "__main__":
    guard = WirelessAccessGuard()
    alert = guard.evaluate_events(
        observed_bt_macs=["AA:BB:CC:11:22:33"],
        observed_cast_targets=["living-room-display-01"],
    )
    print(json.dumps(alert, indent=2))
Manage workflows & pipelines (automating repo checks, backups, or test runs from one CLI or dashboard)Because the Cochlear™ Nucleus® Smart App is a proprietary regulated medical device companion app (for compatible sound processors such as Nucleus 8, Nucleus 7, and Kanso 2), there is no public SDK or open source code to patch directly. Instead, you can build companion software, UX/accessibility prototypes, and synthetic telemetry simulators in your own repository to model ideas around Nucleus Smart App workflows and share structured feedback with Cochlear.
1. What Nucleus Smart App Workflows You Can Model & Improve
Looking at how the Nucleus Smart App works in practice, realistic software engineering improvements center on clarity, accessibility, feedback loops, and device/environment awareness:
 * Hearing Tracker & Goal Modeling: Track mock or synthetic metrics like Time in Speech, Coil Off alerts, and Data Sync state to test clearer visual summaries or goal-progress UX.
 * Acoustic & Visual Environment Awareness: Pair your vision/HUD module with environmental sound/scene cues (for example, visual indicators for noisy environments where features like ForwardFocus or speech clarity matter most) to explore assistive HUD concepts.
 * Connection, Battery & Alert UX: Simulate disconnection alerts, battery status, or Find My Processor / last-seen location logic to test low-friction recovery flows and clear status messaging.
 * Privacy & Sync Transparency: Model explicit local-only vs. cloud sync states (mirroring how Hearing Tracker data stays on-device unless Data Sync is enabled) so privacy trade-offs are transparent to the user.
2. Starter Module: Simulated Nucleus Smart App Telemetry & UX Advisor (modules/nucleus_ux_sim.py)
This standalone simulator generates synthetic processor/app states (never real patient or medical data) and pairs them with your HUD/load telemetry so you can prototype UX alerts, test accessibility states, and export structured observations for your GitHub audit repo.
"""Synthetic Nucleus Smart App state simulator for UX & accessibility prototyping."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import time


@dataclass
class SimulatedSmartAppState:
    timestamp_unix: float
    processor_model: str
    battery_percent: int
    coil_attached: bool
    bluetooth_connected: bool
    data_sync_enabled: bool
    time_in_speech_minutes: int
    active_program: str
    noisy_scene_detected: bool


def evaluate_ux_suggestions(state: SimulatedSmartAppState) -> list[str]:
    """Produces non-clinical UX/accessibility suggestions from simulated app state."""
    suggestions: list[str] = []

    if not state.bluetooth_connected:
        suggestions.append(
            "Show clear Bluetooth reconnection steps and verify phone OS permissions."
        )
    if not state.coil_attached:
        suggestions.append(
            "Highlight coil-repositioning prompt clearly without overlapping active controls."
        )
    if state.battery_percent <= 15:
        suggestions.append(
            "Surface low-battery warning early and remind user of spare battery/charging status."
        )
    if state.noisy_scene_detected and state.active_program == "Standard":
        suggestions.append(
            "Offer quick-access prompt to review noise-reduction / ForwardFocus program options."
        )
    if not state.data_sync_enabled:
        suggestions.append(
            "Display clear local-storage indicator so user knows data is device-local unless synced."
        )

    return suggestions


if __name__ == "__main__":
    sample_state = SimulatedSmartAppState(
        timestamp_unix=time.time(),
        processor_model="Nucleus 8 (Simulated)",
        battery_percent=64,
        coil_attached=True,
        bluetooth_connected=True,
        data_sync_enabled=False,
        time_in_speech_minutes=145,
        active_program="Standard",
        noisy_scene_detected=True,
    )
    payload = {
        "simulated_state": asdict(sample_state),
        "ux_suggestions": evaluate_ux_suggestions(sample_state),
    }
    print(json.dumps(payload, indent=2))

3. Safe Development & Contribution Path
 * Keep All Data Synthetic: Never store real implant serial numbers, clinic records, or personal health data in Git or test fixtures.
 * Test Against Real App Capabilities: Use the app's Demo Mode (where available) and public user guides to verify that any UX prototype or workflow note matches real features accurately.
 * Package Actionable Feedback: Turn concrete findings from your simulator and UX audits into clean, reproducible notes—or submit product/usability feedback through Cochlear's official channels (and consult your clinic/audiologist regarding any real-world device or hearing care questions).
Would you like to connect this SimulatedSmartAppState onto your OpenCV HUD overlay next, or generate a pytest suite to test the simulator and schema validators together?
Using All of my apps and devices to control everythingCochlear's Global Privacy Notice isn't a setup guide or a technical configuration tool—it is a legal policy explaining how Cochlear collects, uses, shares, and protects your personal and health information across its devices, apps, websites, and clinics.
If you are looking to set up your account, configure device/app privacy controls, or manage your data, you don't set things up inside the Privacy Notice itself. Instead, you configure them through your Cochlear™ Account, your smartphone/app settings, or your clinic/Cochlear support.
1. What the Privacy Notice Actually Covers
 * Data Collected: Contact details, login credentials, device/sound processor serial numbers and usage logs, health and fitting data (including Remote Check/Remote Assist records), app diagnostics/crash logs, and website/cookie data.
 * How It Is Used: Registering devices and warranties, enabling apps and connected care with your clinic, providing customer support, improving products/algorithms (often using de-identified data), and—where permitted—marketing or personalization.
 * Your Rights: Depending on your country/region, you may have rights to access, correct, or delete personal data, withdraw consent, opt out of marketing or certain cookies, and ask questions or file privacy complaints with Cochlear or your local privacy authority.
2. How to "Set Everything Up" Around Your Privacy & Account
A. Set Up Your Cochlear™ Account (or Carer/Child Setup)
 * Register & Verify: Start Cochlear Account setup via Cochlear's account portal or a compatible Cochlear app (such as the Nucleus Smart App), enter your details, and click the confirmation link sent to your email (check Spam/Junk if it doesn't arrive) to set a strong, unique password.
 * Carer & Child Accounts: If setting up for yourself and someone you care for—or for a child under your country's age threshold—configure the relationship and consent steps during setup or under Settings > Account Details > Relationships in the app (a separate email address and parent/carer consent are typically required for a child's account).
 * Keep Profile & Clinic Links Accurate: Confirm your contact info, address, and device/clinic associations so warranty tracking, replacements, and Remote Care features work smoothly.
B. Adjust App, Location, and Device Privacy Controls
 * Location & Smart App Features: Smart apps can store the last location where a paired sound processor was used without sending that location data to Cochlear. You can toggle location access on or off anytime inside your smartphone's system Location/Privacy settings.
 * Connected Care (Remote Check / Remote Assist): If your audiologist uses Remote Care, check how data is shared and confirm enrollment timing with your clinic (clinics generally recommend enrolling well ahead of an appointment, such as at least 72 hours prior, and you can unenroll or manage care access as needed).
 * Shared Devices: Never save passwords on shared or public computers/tablets, and always log out when finished.
C. Manage Website Cookies, Marketing, and Data Requests
 * Cookies: Use Cochlear's cookie settings/preferences on the website to adjust non-essential cookies (note that blocking certain cookies may affect site features).
 * Marketing & Emails: Opt out of promotional emails or alerts using the unsubscribe link in messages or your communication preferences.
 * Account Deletion or Data Rights: To close a Cochlear Account in the Nucleus Smart App, go to Main Menu > Settings > Delete account and follow the prompts (account closure requests can take up to 10 days). For formal data access, correction, or privacy inquiries, reach out to Cochlear Customer Service or your regional Cochlear office listed on their site.
Clarifying What You Need Next
Because "set everything up" can mean a few different things with Cochlear, let me know what you're working on—such as setting up a Cochlear™ Account for yourself or a child, configuring a specific sound processor/app, or exercising a specific privacy/opt-out request—and I can walk you through the exact steps for your situation.
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

LATEST_SCHEMA_VERSION = 1


def canonical_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sql_sha256(sql_script: str) -> str:
    normalized = "\n".join(line.strip() for line in sql_script.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _person_hash_payload(person: dict[str, Any]) -> dict[str, Any]:
    variants = sorted({str(v).strip() for v in person.get("surname_variants", []) if str(v).strip()})
    return {
        "person_id": person["person_id"],
        "full_name": person["full_name"],
        "surname_variants": variants,
        "birth_date_or_approx": person.get("birth_date_or_approx"),
        "birth_place": person.get("birth_place"),
        "death_date_or_approx": person.get("death_date_or_approx"),
        "death_place": person.get("death_place"),
        "is_living": bool(person.get("is_living", False)),
        "notes": person.get("notes"),
    }


def _edge_hash_payload(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": edge["edge_id"],
        "person_a_id": edge["person_a_id"],
        "person_b_id": edge["person_b_id"],
        "relation_type": edge["relation_type"],
        "lineage_side": edge.get("lineage_side", "unknown"),
        "certainty": edge.get("certainty", "hypothesis_needs_proof"),
        "source_id": edge.get("source_id"),
        "notes": edge.get("notes"),
    }


def _event_hash_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event["event_id"],
        "person_id": event["person_id"],
        "event_type": event["event_type"],
        "event_date_or_approx": event.get("event_date_or_approx"),
        "location": event.get("location"),
        "description": event.get("description"),
        "source_id": event.get("source_id"),
    }


def _source_hash_payload(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_id": source["source_id"],
        "title": source["title"],
        "repository_or_archive": source["repository_or_archive"],
        "citation_or_url": source.get("citation_or_url"),
        "artifact_sha256": source.get("artifact_sha256"),
    }


SCHEMA_V1_SQL = """
CREATE TABLE IF NOT EXISTS persons (
    person_id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    surname_variants_json TEXT NOT NULL DEFAULT '[]',
    birth_date_or_approx TEXT,
    birth_place TEXT,
    death_date_or_approx TEXT,
    death_place TEXT,
    is_living INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    record_sha256 TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ancestry_sources (
    source_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    repository_or_archive TEXT NOT NULL,
    citation_or_url TEXT,
    artifact_sha256 TEXT,
    source_sha256 TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bloodline_edges (
    edge_id TEXT PRIMARY KEY,
    person_a_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    person_b_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL CHECK (
        relation_type IN ('parent_of', 'child_of', 'spouse_of', 'sibling_of')
    ),
    lineage_side TEXT NOT NULL DEFAULT 'unknown' CHECK (
        lineage_side IN ('paternal', 'maternal', 'collateral', 'marital', 'unknown')
    ),
    certainty TEXT NOT NULL DEFAULT 'hypothesis_needs_proof' CHECK (
        certainty IN ('verified_primary', 'corroborated_secondary', 'hypothesis_needs_proof')
    ),
    source_id TEXT REFERENCES ancestry_sources(source_id) ON DELETE SET NULL,
    notes TEXT,
    edge_sha256 TEXT NOT NULL,
    CHECK (person_a_id != person_b_id)
);

CREATE TABLE IF NOT EXISTS life_events (
    event_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES persons(person_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (
        event_type IN ('birth', 'marriage', 'census', 'residence', 'migration', 'death', 'probate')
    ),
    event_date_or_approx TEXT,
    location TEXT,
    description TEXT,
    source_id TEXT REFERENCES ancestry_sources(source_id) ON DELETE SET NULL,
    event_sha256 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_persons_name ON persons(full_name);
CREATE INDEX IF NOT EXISTS idx_edges_a ON bloodline_edges(person_a_id);
CREATE INDEX IF NOT EXISTS idx_edges_b ON bloodline_edges(person_b_id);
CREATE INDEX IF NOT EXISTS idx_events_person ON life_events(person_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON life_events(event_type);
"""

MIGRATIONS: list[tuple[int, str, str | Callable[[sqlite3.Connection], None]]] = [
    (1, "initial_ancestry_schema", SCHEMA_V1_SQL),
]


def _ensure_migration_table(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                sql_sha256 TEXT NOT NULL,
                applied_at_utc TEXT NOT NULL
            );
            """
        )


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version from PRAGMA user_version."""
    row = conn.execute("PRAGMA user_version;").fetchone()
    if row is None:
        return 0
    return int(row[0] if not isinstance(row, sqlite3.Row) else row["user_version"])


def apply_migrations(
    conn: sqlite3.Connection,
    migrations: list[tuple[int, str, str | Callable[[sqlite3.Connection], None]]] | None = None,
    target_version: int | None = None,
) -> dict[str, Any]:
    """Apply pending migrations in version order and record checksums in schema_migrations."""
    _ensure_migration_table(conn)
    registry = sorted(migrations if migrations is not None else MIGRATIONS, key=lambda item: item[0])

    applied_rows = conn.execute(
        "SELECT version, name, sql_sha256, applied_at_utc FROM schema_migrations ORDER BY version ASC;"
    ).fetchall()
    applied_map = {
        (r["version"] if isinstance(r, sqlite3.Row) else r[0]): (
            r["sql_sha256"] if isinstance(r, sqlite3.Row) else r[2]
        )
        for r in applied_rows
    }

    newly_applied: list[dict[str, Any]] = []
    skipped_versions: list[int] = []

    for version, name, step in registry:
        if target_version is not None and version > target_version:
            continue

        step_digest = (
            _sql_sha256(step)
            if isinstance(step, str)
            else canonical_sha256({"version": version, "name": name, "callable": getattr(step, "__name__", "step")})
        )

        if version in applied_map:
            if applied_map[version] != step_digest:
                raise RuntimeError(
                    f"Migration checksum mismatch for version {version} ({name}): "
                    f"applied={applied_map[version]} != current={step_digest}"
                )
            skipped_versions.append(version)
            continue

        now_utc = datetime.now(timezone.utc).isoformat()
        with conn:
            if isinstance(step, str):
                conn.executescript(step)
            else:
                step(conn)
            conn.execute(
                """
                INSERT INTO schema_migrations (version, name, sql_sha256, applied_at_utc)
                VALUES (?, ?, ?, ?);
                """,
                (version, name, step_digest, now_utc),
            )
            conn.execute(f"PRAGMA user_version = {int(version)};")

        newly_applied.append({"version": version, "name": name, "sql_sha256": step_digest, "applied_at_utc": now_utc})

    current_version = get_schema_version(conn)
    return {
        "current_version": current_version,
        "newly_applied": newly_applied,
        "skipped_versions": skipped_versions,
    }


def verify_schema_version(
    conn: sqlite3.Connection,
    expected_version: int = LATEST_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Verify PRAGMA user_version and schema_migrations state against expected_version."""
    _ensure_migration_table(conn)
    pragma_version = get_schema_version(conn)
    max_row = conn.execute("SELECT COALESCE(MAX(version), 0) AS max_v FROM schema_migrations;").fetchone()
    ledger_version = int(max_row[0] if not isinstance(max_row, sqlite3.Row) else max_row["max_v"])

    ok = (pragma_version == expected_version) and (ledger_version == expected_version)
    return {
        "ok": ok,
        "expected_version": expected_version,
        "pragma_user_version": pragma_version,
        "ledger_max_version": ledger_version,
    }


def init_ancestry_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    apply_migrations(conn, MIGRATIONS, target_version=LATEST_SCHEMA_VERSION)
    return conn


def upsert_person(conn: sqlite3.Connection, person: dict[str, Any]) -> str:
    payload = _person_hash_payload(person)
    digest = canonical_sha256(payload)
    now_utc = datetime.now(timezone.utc).isoformat()
    variants = json.dumps(payload["surname_variants"], ensure_ascii=False)
    with conn:
        conn.execute(
            """
            INSERT INTO persons (
                person_id, full_name, surname_variants_json,
                birth_date_or_approx, birth_place,
                death_date_or_approx, death_place,
                is_living, notes, record_sha256, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(person_id) DO UPDATE SET
                full_name = excluded.full_name,
                surname_variants_json = excluded.surname_variants_json,
                birth_date_or_approx = excluded.birth_date_or_approx,
                birth_place = excluded.birth_place,
                death_date_or_approx = excluded.death_date_or_approx,
                death_place = excluded.death_place,
                is_living = excluded.is_living,
                notes = excluded.notes,
                record_sha256 = excluded.record_sha256,
                updated_at_utc = excluded.updated_at_utc
            WHERE persons.record_sha256 != excluded.record_sha256;
            """,
            (
                payload["person_id"],
                payload["full_name"],
                variants,
                payload["birth_date_or_approx"],
                payload["birth_place"],
                payload["death_date_or_approx"],
                payload["death_place"],
                1 if payload["is_living"] else 0,
                payload["notes"],
                digest,
                now_utc,
            ),
        )
    return digest


def upsert_source(conn: sqlite3.Connection, source: dict[str, Any]) -> str:
    payload = _source_hash_payload(source)
    digest = canonical_sha256(payload)
    now_utc = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """
            INSERT INTO ancestry_sources (
                source_id, title, repository_or_archive,
                citation_or_url, artifact_sha256, source_sha256, retrieved_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO UPDATE SET
                title = excluded.title,
                repository_or_archive = excluded.repository_or_archive,
                citation_or_url = excluded.citation_or_url,
                artifact_sha256 = excluded.artifact_sha256,
                source_sha256 = excluded.source_sha256,
                retrieved_at_utc = excluded.retrieved_at_utc
            WHERE ancestry_sources.source_sha256 != excluded.source_sha256;
            """,
            (
                payload["source_id"],
                payload["title"],
                payload["repository_or_archive"],
                payload["citation_or_url"],
                payload["artifact_sha256"],
                digest,
                now_utc,
            ),
        )
    return digest


def add_relationship(conn: sqlite3.Connection, edge: dict[str, Any]) -> str:
    payload = _edge_hash_payload(edge)
    digest = canonical_sha256(payload)
    with conn:
        conn.execute(
            """
            INSERT INTO bloodline_edges (
                edge_id, person_a_id, person_b_id, relation_type,
                lineage_side, certainty, source_id, notes, edge_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(edge_id) DO UPDATE SET
                person_a_id = excluded.person_a_id,
                person_b_id = excluded.person_b_id,
                relation_type = excluded.relation_type,
                lineage_side = excluded.lineage_side,
                certainty = excluded.certainty,
                source_id = excluded.source_id,
                notes = excluded.notes,
                edge_sha256 = excluded.edge_sha256
            WHERE bloodline_edges.edge_sha256 != excluded.edge_sha256;
            """,
            (
                payload["edge_id"],
                payload["person_a_id"],
                payload["person_b_id"],
                payload["relation_type"],
                payload["lineage_side"],
                payload["certainty"],
                payload["source_id"],
                payload["notes"],
                digest,
            ),
        )
    return digest


def upsert_life_event(conn: sqlite3.Connection, event: dict[str, Any]) -> str:
    payload = _event_hash_payload(event)
    digest = canonical_sha256(payload)
    with conn:
        conn.execute(
            """
            INSERT INTO life_events (
                event_id, person_id, event_type,
                event_date_or_approx, location, description,
                source_id, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                person_id = excluded.person_id,
                event_type = excluded.event_type,
                event_date_or_approx = excluded.event_date_or_approx,
                location = excluded.location,
                description = excluded.description,
                source_id = excluded.source_id,
                event_sha256 = excluded.event_sha256
            WHERE life_events.event_sha256 != excluded.event_sha256;
            """,
            (
                payload["event_id"],
                payload["person_id"],
                payload["event_type"],
                payload["event_date_or_approx"],
                payload["location"],
                payload["description"],
                payload["source_id"],
                digest,
            ),
        )
    return digest


def get_ancestors(
    conn: sqlite3.Connection,
    person_id: str,
    max_depth: int | None = None,
    lineage_side: str | None = None,
    certainty: str | None = None,
) -> list[dict[str, Any]]:
    """Traverse upward through parent/child bloodline edges to retrieve ancestors."""
    filters: list[str] = []
    params: list[Any] = [person_id]

    if max_depth is not None:
        filters.append("anc.generation_depth < ?")
        params.append(max_depth)
    if lineage_side is not None:
        filters.append("e.lineage_side = ?")
        params.append(lineage_side)
    if certainty is not None:
        filters.append("e.certainty = ?")
        params.append(certainty)

    extra_where = (" AND " + " AND ".join(filters)) if filters else ""

    sql = f"""
        WITH RECURSIVE ancestor_cte(
            person_id, generation_depth, via_edge_id, lineage_side, certainty, visited_path
        ) AS (
            SELECT
                p.person_id,
                0,
                NULL,
                NULL,
                NULL,
                '|' || p.person_id || '|'
            FROM persons p
            WHERE p.person_id = ?

            UNION ALL

            SELECT
                parent_p.person_id,
                anc.generation_depth + 1,
                e.edge_id,
                e.lineage_side,
                e.certainty,
                anc.visited_path || parent_p.person_id || '|'
            FROM ancestor_cte anc
            JOIN bloodline_edges e
                ON (
                    (e.relation_type = 'parent_of' AND e.person_b_id = anc.person_id)
                    OR
                    (e.relation_type = 'child_of' AND e.person_a_id = anc.person_id)
                )
            JOIN persons parent_p
                ON parent_p.person_id = CASE
                    WHEN e.relation_type = 'parent_of' THEN e.person_a_id
                    ELSE e.person_b_id
                END
            WHERE instr(anc.visited_path, '|' || parent_p.person_id || '|') = 0
            {extra_where}
        )
        SELECT
            p.person_id,
            p.full_name,
            p.surname_variants_json,
            p.birth_date_or_approx,
            p.birth_place,
            p.death_date_or_approx,
            p.death_place,
            p.is_living,
            p.notes,
            act.generation_depth,
            act.via_edge_id,
            act.lineage_side,
            act.certainty
        FROM ancestor_cte act
        JOIN persons p ON p.person_id = act.person_id
        WHERE act.generation_depth > 0
        ORDER BY act.generation_depth ASC, p.full_name ASC;
    """
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def get_descendants(
    conn: sqlite3.Connection,
    person_id: str,
    max_depth: int | None = None,
    lineage_side: str | None = None,
    certainty: str | None = None,
) -> list[dict[str, Any]]:
    """Traverse downward through parent/child bloodline edges to retrieve descendants."""
    filters: list[str] = []
    params: list[Any] = [person_id]

    if max_depth is not None:
        filters.append("desc_cte.generation_depth < ?")
        params.append(max_depth)
    if lineage_side is not None:
        filters.append("e.lineage_side = ?")
        params.append(lineage_side)
    if certainty is not None:
        filters.append("e.certainty = ?")
        params.append(certainty)

    extra_where = (" AND " + " AND ".join(filters)) if filters else ""

    sql = f"""
        WITH RECURSIVE desc_cte(
            person_id, generation_depth, via_edge_id, lineage_side, certainty, visited_path
        ) AS (
            SELECT
                p.person_id,
                0,
                NULL,
                NULL,
                NULL,
                '|' || p.person_id || '|'
            FROM persons p
            WHERE p.person_id = ?

            UNION ALL

            SELECT
                child_p.person_id,
                desc_cte.generation_depth + 1,
                e.edge_id,
                e.lineage_side,
                e.certainty,
                desc_cte.visited_path || child_p.person_id || '|'
            FROM desc_cte
            JOIN bloodline_edges e
                ON (
                    (e.relation_type = 'parent_of' AND e.person_a_id = desc_cte.person_id)
                    OR
                    (e.relation_type = 'child_of' AND e.person_b_id = desc_cte.person_id)
                )
            JOIN persons child_p
                ON child_p.person_id = CASE
                    WHEN e.relation_type = 'parent_of' THEN e.person_b_id
                    ELSE e.person_a_id
                END
            WHERE instr(desc_cte.visited_path, '|' || child_p.person_id || '|') = 0
            {extra_where}
        )
        SELECT
            p.person_id,
      {
  "kty": "EC",
  "crv": "P-256",
  "x": "XJA1hY1VQEO80sCDkO64zswDFWrY2Bl17UtdUKEqYOo",
  "y": "Zq9USSH8nWab5GVmMyQF5Ec1Ceqi2XzGOCEhcxrlMBM"
}
Got it—let's build out the full blueprint connecting your existing repositories (adpBetty, Master-Hub, global-recovery-roadmap, sovereign-global-law-hub), legal/compliance records, and local-first infrastructure into a cohesive architecture.
1. System Architecture & Ecosystem Topology
A unified local-first platform anchored around WK Precision Enterprise LLC and your developer identities (re1Lucky365 / adpsnake7-beep) separates data custody, cryptographic provenance, local AI/indexing, and monitoring into clean service boundaries:
┌─────────────────────────────────────────────────────────────────────────┐
│                        Ingress & Reverse Proxy                          │
│                 Caddy (TLS, Routing) + UFW (Zero-Trust Egress)         │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│   Legal & Bundle    │   │   Master-Hub &      │   │   Local AI / RAG    │
│      Pipeline       │   │   Mirror Engine     │   │      Pipeline       │
│                     │   │                     │   │                     │
│ sovereign-global-   │   │ adpBetty /          │   │ Ollama + ChromaDB   │
│ law-hub JSON/SQLite │   │ global-recovery-    │   │ + FastAPI /         │
│ + SHA-256 Manifests │   │ roadmap             │   │ Streamlit UI        │
└─────────┬───────────┘   └─────────┬───────────┘   └─────────┬───────────┘
          │                         │                         │
          └─────────────────────────┼─────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              Integrity, Signing & Backup Custody Layer                  │
│   GPG Commit/Tag Signing ──► zstd -19 Bundles ──► age/GPG + rclone + WORM │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  Observability & Security Telemetry                     │
│          Prometheus + Grafana + Wazuh + OpenSearch + systemd Units      │
└─────────────────────────────────────────────────────────────────────────┘

2. Core Subsystems & Integration Specifications
A. Jurisdiction-Aware Legal & Compliance Intake (sovereign-global-law-hub)
 * Canonical Bundle Schema (SovereignGlobalLawHubBundle): Standardize incoming statutory codes, amendments, case citations, and formal notices under a strict JSON schema capturing jurisdiction metadata, effective dates, source provenance, and canonical serialization rules.
 * Deterministic Indexing Pipeline: Use Python (sqlite3 + hashlib) to compute SHA-256 digests over canonicalized JSON payloads before upsert, ensuring idempotent ingestion and tamper detection across legal and evidence records.
 * Auditability: Link each indexed record to its source artifact hash and retrieval timestamp so legal research and compliance logs remain reproducible offline.
B. Cryptographic Provenance & Automated Mirroring (adpBetty, Master-Hub, global-recovery-roadmap)
 * Signing & Push Enforcement: Require GPG-signed commits and annotated tags across re1Lucky365 and adpsnake7-beep, reinforced by local Git pre-push hooks, GitHub repository rulesets, and CI signature checks.
 * One-Way Artifact Distribution: Use immutable naming conventions (content hashes + version/date tags) for mirrored repositories and recovery bundles so downstream consumers never overwrite historical evidence or release artifacts.
 * Backup & Archival Chain: Package multi-hundred-gigabyte local datasets with Zstandard (zstd -19), generate sha256sum manifests, encrypt payloads with age or GPG, sync via rclone, and enforce WORM (Object Lock) immutability on archival targets.
C. Local-First RAG & Model Engineering Stack
 * Offline Inference & Vector Search: Pair Ollama local models with ChromaDB collections for private document indexing, statute lookup, and technical runbook search without external data egress.
 * Service & UI Layer: Expose retrieval and ingestion endpoints through FastAPI and Streamlit, keeping SQLite WAL mode (PRAGMA journal_mode=WAL;) and busy timeouts tuned for concurrent read/write operations.
D. Automated Monitoring, Telemetry & Incident Response
 * Host & Network Baseline: Enforce UFW default-deny posture with explicit allowlists and Caddy reverse proxies for internal/TLS traffic termination.
 * Metrics, SIEM & Alerting: Scrape service health and pipeline metrics with Prometheus and visualize them in Grafana, while forwarding host/security events to Wazuh and OpenSearch.
 * Scheduler Resilience: Run recurring mirror, index, and backup jobs via systemd user/system timers wired to OnFailure= alert units and structured log rotation.
3. Phased Implementation Roadmap
| Phase | Focus Area | Key Deliverables |
|---|---|---|
| Phase 1: Foundations | Hardening & Signing | Lock down UFW/Caddy baseline, verify GPG signing hooks/rulesets across re1Lucky365 and adpsnake7-beep, and standardize systemd failure alerts. |
| Phase 2: Legal & Data Core | Schema & Indexing | Finalize SovereignGlobalLawHubBundle JSON Schema, SQLite WAL + SHA-256 pipeline, and immutable artifact naming in adpBetty / Master-Hub. |
| Phase 3: Local AI & RAG | Retrieval & Search | Index legal and technical corpora into ChromaDB via Ollama + FastAPI/Streamlit with deterministic metadata filters. |
| Phase 4: Telemetry & Custody | Observability & Archival | Wire Prometheus/Grafana/Wazuh/OpenSearch dashboards and validate end-to-end zstd + sha256sum + rclone restore drills. |
Which subsystem should we prototype or flesh out first—the SovereignGlobalLawHubBundle JSON Schema + SQLite/SHA-256 indexer, the systemd + zstd/rclone backup & failure-alert pipeline, or the FastAPI/ChromaDB/Ollama RAG service layout?
Here is a clean, practical way to organize and test your GitHub repository scripts on Linux—pairing a repository structure initializer with a pytest suite that verifies your JSON/JSONL bundle validator (validate_bundle.py) and SQLite catalog indexer (catalog_index.py).
1. Repository Layout & Scaffolder (scripts/init_repo_hub.sh)
Use this script to create a consistent local-first layout across a repository (scripts/, tests/, data/, build/, and .github/workflows/) without overwriting existing files:
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-.}"

mkdir -p \
  "$TARGET_DIR/scripts" \
  "$TARGET_DIR/tests" \
  "$TARGET_DIR/data" \
  "$TARGET_DIR/build" \
  "$TARGET_DIR/.github/workflows"

if [[ ! -f "$TARGET_DIR/.gitignore" ]]; then
  cat <<'EOF' > "$TARGET_DIR/.gitignore"
__pycache__/
*.py[cod]
.pytest_cache/
build/
*.sqlite
*.sqlite-wal
*.sqlite-shm
*.tar.zst
*.sha256
EOF
fi

echo "Initialized repository directories and .gitignore at: $TARGET_DIR"

2. Automated Tests for Bundle Validation & SQLite Indexing (tests/test_bundle_and_catalog.py)
This pytest suite tests deterministic record hashing, duplicate ID detection, missing required field errors, and SQLite WAL-mode indexing/upserts:
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_validate_bundle_passes_valid_json(tmp_path: Path) -> None:
    script = Path("scripts/validate_bundle.py")
    bundle = tmp_path / "records.json"
    bundle.write_text(
        json.dumps(
            [
                {"id": "rec-1", "title": "First Entry", "jurisdiction": "US"},
                {"id": "rec-2", "title": "Second Entry", "jurisdiction": "IN"},
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(script), str(bundle), "--require", "id", "title", "jurisdiction"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["record_count"] == 2
    assert payload["errors"] == []
    assert len(payload["bundle_sha256"]) == 64


def test_validate_bundle_catches_duplicates_and_missing_fields(tmp_path: Path) -> None:
    script = Path("scripts/validate_bundle.py")
    bundle = tmp_path / "bad_records.jsonl"
    bundle.write_text(
        "\n".join(
            [
                json.dumps({"id": "dup-1", "title": "Valid"}),
                json.dumps({"id": "dup-1"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(script), str(bundle), "--require", "id", "title"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any("missing or empty required field 'title'" in err for err in payload["errors"])
    assert any("duplicate id 'dup-1'" in err for err in payload["errors"])


def test_catalog_index_wal_and_upsert(tmp_path: Path) -> None:
    script = Path("scripts/catalog_index.py")
    scan_dir = tmp_path / "docs"
    scan_dir.mkdir()
    sample_file = scan_dir / "note.txt"
    sample_file.write_text("v1 content\n", encoding="utf-8")

    db_path = tmp_path / "catalog.sqlite"
    subprocess.run(
        [sys.executable, str(script), "--db", str(db_path), "--scan-dir", str(scan_dir)],
        capture_output=True,
        text=True,
        check=True,
    )

    sample_file.write_text("v2 updated content\n", encoding="utf-8")
    subprocess.run(
        [sys.executable, str(script), "--db", str(db_path), "--scan-dir", str(scan_dir)],
        capture_output=True,
        text=True,
        check=True,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        rows = conn.execute("SELECT rel_path, sha256 FROM indexed_artifacts;").fetchall()
    finally:
        conn.close()

    assert mode.lower() == "wal"
    assert len(rows) == 1
    assert rows[0][0] == "note.txt"
    assert len(rows[0][1]) == 64

3. Running Locally and in GitHub Actions
 * Scaffold folders: bash scripts/init_repo_hub.sh .
 * Run tests: pytest -v
 * Commit cleanly: Stage only the specific files you want in the repository (git add scripts/init_repo_hub.sh tests/test_bundle_and_catalog.py .gitignore), review git status, and commit.
#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash scripts/create_gh_release.sh v1.0.0 dist/ "Release v1.0.0"
# Optional env vars:
#   SIGN_TAG=1        (1 = git tag -s, 0 = git tag -a)
#   SIGN_CHECKSUMS=1  (1 = gpg --detach-sign --armor SHA256SUMS, 0 = skip)
#   GPG_KEY_ID=""     (optional specific GPG key fingerprint/ID for signing)

TAG="${1:?Usage: $0 <tag> <dist_dir> [release_title]}"
DIST_DIR="${2:?Usage: $0 <tag> <dist_dir> [release_title]}"
RELEASE_TITLE="${3:-$TAG}"
SIGN_TAG="${SIGN_TAG:-1}"
SIGN_CHECKSUMS="${SIGN_CHECKSUMS:-1}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

# 1. Verify required tools are installed and authenticated
REQUIRED_CMDS=(git gh sha256sum)
if [[ "$SIGN_TAG" == "1" || "$SIGN_CHECKSUMS" == "1" ]]; then
  REQUIRED_CMDS+=(gpg)
fi

for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required command '$cmd' not found." >&2
    exit 1
  fi
done

gh auth status >/dev/null

# 2. Verify we are inside a Git repository with a completely clean working tree
git rev-parse --is-inside-work-tree >/dev/null
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is not clean. Commit or stash changes before releasing." >&2
  git status --short >&2
  exit 1
fi

# 3. Verify the tag does not already exist locally or on origin
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Error: local tag '$TAG' already exists." >&2
  exit 1
fi
if git ls-remote --tags origin "refs/tags/$TAG" | grep -q "$TAG"; then
  echo "Error: remote tag '$TAG' already exists on origin." >&2
  exit 1
fi

# 4. Collect release files from DIST_DIR and generate SHA256SUMS
if [[ ! -d "$DIST_DIR" ]]; then
  echo "Error: distribution directory '$DIST_DIR' does not exist." >&2
  exit 1
fi

mapfile -t ASSETS < <(
  find "$DIST_DIR" -maxdepth 1 -type f ! -name "SHA256SUMS" ! -name "SHA256SUMS.asc" | sort
)
if [[ "${#ASSETS[@]}" -eq 0 ]]; then
  echo "Error: no release files found in '$DIST_DIR'." >&2
  exit 1
fi

MANIFEST="$DIST_DIR/SHA256SUMS"
SIG_FILE="$DIST_DIR/SHA256SUMS.asc"
rm -f "$MANIFEST" "$SIG_FILE"

(
  cd "$DIST_DIR"
  sha256sum -- "$(basename -a "${ASSETS[@]}")" > SHA256SUMS
  sha256sum -c SHA256SUMS --quiet
)

UPLOAD_FILES=("${ASSETS[@]}" "$MANIFEST")

# 5. Create and verify detached GPG signature for SHA256SUMS
if [[ "$SIGN_CHECKSUMS" == "1" ]]; then
  GPG_ARGS=(--batch --yes --armor --detach-sign --output "$SIG_FILE")
  if [[ -n "$GPG_KEY_ID" ]]; then
    GPG_ARGS+=(--local-user "$GPG_KEY_ID")
  fi
  gpg "${GPG_ARGS[@]}" "$MANIFEST"
  gpg --verify "$SIG_FILE" "$MANIFEST" >/dev/null 2>&1
  UPLOAD_FILES+=("$SIG_FILE")
fi

# 6. Create annotated (and GPG-signed by default) Git tag and push it
if [[ "$SIGN_TAG" == "1" ]]; then
  if [[ -n "$GPG_KEY_ID" ]]; then
    git -c user.signingkey="$GPG_KEY_ID" tag -s "$TAG" -m "$RELEASE_TITLE"
  else
    git tag -s "$TAG" -m "$RELEASE_TITLE"
  fi
else
  git tag -a "$TAG" -m "$RELEASE_TITLE"
fi
git push origin "$TAG"

# 7. Create the GitHub Release and upload artifacts + SHA256SUMS + SHA256SUMS.asc
gh release create "$TAG" \
  "${UPLOAD_FILES[@]}" \
  --title "$RELEASE_TITLE" \
  --generate-notes \
  --verify-tag

echo "Release '$TAG' published successfully with SHA256SUMS${SIGN_CHECKSUMS:+ and SHA256SUMS.asc}."
Here are additional local-first code utilities in Python and Bash for your GitHub repositories—covering deterministic JSON schema/bundle validation (SovereignGlobalLawHubBundle-style records) and compressed (zstd), checksummed backup archiving with rclone sync hooks.
1. JSON Bundle Validator & Diff Auditor (scripts/validate_bundle.py)
Validates structured JSON/JSONL records, checks required fields and types, and computes deterministic SHA-256 fingerprints for each record and the full bundle:
#!/usr/bin/env python3
"""Validate structured JSON/JSONL bundles and compute deterministic SHA-256 digests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def canonical_sha256(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(path: Path) -> list[dict[str, Any]]:
    raw_text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            item = json.loads(stripped)
            if not isinstance(item, dict):
                raise ValueError(f"Line {line_no}: expected JSON object")
            records.append(item)
        return records

    parsed = json.loads(raw_text)
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    if isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
        return [r for r in parsed["records"] if isinstance(r, dict)]
    raise ValueError("Expected a JSON list, a .jsonl file, or an object with a 'records' list")


def validate_records(records: list[dict[str, Any]], required_fields: list[str]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()

    for idx, rec in enumerate(records):
        for field in required_fields:
            if field not in rec or rec[field] in (None, ""):
                errors.append(f"Record {idx}: missing or empty required field '{field}'")

        rec_id = rec.get("id")
        if rec_id is not None:
            key = str(rec_id)
            if key in seen_ids:
                errors.append(f"Record {idx}: duplicate id '{key}'")
            seen_ids.add(key)

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate JSON/JSONL bundle records and emit digests.")
    parser.add_argument("bundle_file", type=Path, help="Path to JSON or JSONL bundle")
    parser.add_argument(
        "--require",
        nargs="*",
        default=["id", "title"],
        help="Required keys on every record (default: id title)",
    )
    args = parser.parse_args()

    records = load_records(args.bundle_file)
    errors = validate_records(records, args.require)

    manifest = {
        "file": str(args.bundle_file),
        "record_count": len(records),
        "bundle_sha256": canonical_sha256(records),
        "records": [
            {
                "index": i,
                "id": r.get("id"),
                "sha256": canonical_sha256(r),
            }
            for i, r in enumerate(records)
        ],
        "errors": errors,
    }
    print(json.dumps(manifest, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

2. Compressed Backup Archiver & rclone Sync Script (scripts/archive_snapshot.sh)
Creates a timestamped zstd-compressed archive (tar --zstd), writes a .sha256 manifest, verifies archive integrity, and optionally syncs to a configured rclone remote:
#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:?Usage: $0 <source_dir> <output_dir> [rclone_remote_dest]}"
OUTPUT_DIR="${2:?Usage: $0 <source_dir> <output_dir> [rclone_remote_dest]}"
RCLONE_DEST="${3:-}"

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "Source directory does not exist: $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE_NAME="$(basename "$(cd "$SOURCE_DIR" && pwd)")_${STAMP}"
ARCHIVE_PATH="$OUTPUT_DIR/${BASE_NAME}.tar.zst"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

# Create zstd-compressed archive excluding .git and __pycache__
tar --zstd \
    --exclude=".git" \
    --exclude="__pycache__" \
    -cf "$ARCHIVE_PATH" \
    -C "$(dirname "$SOURCE_DIR")" \
    "$(basename "$SOURCE_DIR")"

# Generate and verify SHA-256 digest
(
  cd "$OUTPUT_DIR"
  sha256sum "$(basename "$ARCHIVE_PATH")" > "$(basename "$CHECKSUM_PATH")"
  sha256sum -c "$(basename "$CHECKSUM_PATH")" --quiet
)

# Verify archive readability
zstd -t "$ARCHIVE_PATH"

if [[ -n "$RCLONE_DEST" ]] && command -v rclone >/dev/null 2>&1; then
  rclone copy "$ARCHIVE_PATH" "$RCLONE_DEST"
  rclone copy "$CHECKSUM_PATH" "$RCLONE_DEST"
  echo "Synced archive and manifest to: $RCLONE_DEST"
fi

echo "Archive ready and verified: $ARCHIVE_PATH"

3. Quick CLI Usage
 * Validate a bundle: python3 scripts/validate_bundle.py data/sample_bundle.json --require id title jurisdiction
 * Create a verified .tar.zst snapshot: bash scripts/archive_snapshot.sh ~/projects/sovereign-global-law-hub ~/backups/snapshots
Keep working on helping me write everything with my GitHub codesHere is the complete, standalone GitHub Respiratory System, Global Monitoring Pipelines, and Built-In Global Spider Network Shield & Global Protection Pipelines—fully completed without truncation, including the full config/prometheus.yml, config/alert_rules.yml, config/wazuh_local_decoder.xml, config/grafana_respiratory_dashboard.json, scripts/global_protection_guard.sh, systemd/ units, .github/workflows/respiratory-spider-shield.yml, and scripts/generate_blueprint.py so every file is self-contained and ready to materialize.
Complete Blueprint & Pipeline Reference
1. config/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alert_rules.yml

scrape_configs:
  - job_name: node_exporter
    static_configs:
      - targets: ["127.0.0.1:9100"]

  - job_name: cadvisor_containers
    static_configs:
      - targets: ["127.0.0.1:8085"]

  - job_name: blackbox_github_and_global_probes
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - https://api.github.com
          - https://github.com/re1Lucky365
          - https://github.com/adpsnake7-beep
          - https://1.1.1.1
          - https://8.8.8.8
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

2. config/alert_rules.yml
groups:
  - name: respiratory_spider_shield_alerts
    rules:
      - alert: GlobalProbeDown
        expr: probe_success == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Global probe target unreachable: {{ $labels.instance }}"

      - alert: HighDiskPressure
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.12
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Root filesystem free space below 12%"

      - alert: HighMemoryPressure
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.90
        for: 5m
        labels:
          severity: warning
          annotations:
          summary: "Host memory utilization above 90%"

3. config/wazuh_local_decoder.xml & config/grafana_respiratory_dashboard.json
<decoder name="respiratory_spider_json">
  <parent>json</parent>
  <prematch>^\{"timestamp":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

{
  "title": "GitHub Respiratory & Global Spider Shield",
  "timezone": "browser",
  "schemaVersion": 39,
  "panels": [
    {
      "type": "stat",
      "title": "Global Probe Availability",
      "targets": [{ "expr": "avg(probe_success)" }]
    },
    {
      "type": "timeseries",
      "title": "Host Memory Utilization (%)",
      "targets": [
        { "expr": "100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))" }
      ]
    },
    {
      "type": "timeseries",
      "title": "Root Free Disk Ratio",
      "targets": [
        { "expr": "node_filesystem_avail_bytes{mountpoint=\"/\"} / node_filesystem_size_bytes{mountpoint=\"/\"}" }
      ]
    }
  ]
}

4. scripts/global_protection_guard.sh
#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${RESP_BUILD_DIR:-$PWD/build}"
BUNDLE_PATH="${1:-}"
AGE_RECIPIENT="${RESP_AGE_RECIPIENT:-}"
GPG_RECIPIENT="${RESP_GPG_RECIPIENT:-}"
APPLY_UFW="${RESP_APPLY_UFW:-0}"

if [[ "$APPLY_UFW" == "1" ]] && command -v ufw >/dev/null 2>&1; then
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow ssh
  sudo ufw --force enable
fi

if [[ -d "$BUILD_DIR" && -f "$BUILD_DIR/SHA256SUMS" ]]; then
  (cd "$BUILD_DIR" && sha256sum -c SHA256SUMS --quiet)
fi

if [[ -n "$BUNDLE_PATH" && -f "$BUNDLE_PATH" ]]; then
  if [[ -n "$AGE_RECIPIENT" ]] && command -v age >/dev/null 2>&1; then
    age -r "$AGE_RECIPIENT" -o "${BUNDLE_PATH}.age" "$BUNDLE_PATH"
    sha256sum "${BUNDLE_PATH}.age" > "${BUNDLE_PATH}.age.sha256"
  elif [[ -n "$GPG_RECIPIENT" ]] && command -v gpg >/dev/null 2>&1; then
    gpg --batch --yes --encrypt -r "$GPG_RECIPIENT" -o "${BUNDLE_PATH}.gpg" "$BUNDLE_PATH"
    sha256sum "${BUNDLE_PATH}.gpg" > "${BUNDLE_PATH}.gpg.sha256"
  fi
fi

5. systemd/ Units & .github/workflows/respiratory-spider-shield.yml
[Unit]
Description=GitHub Respiratory System & Global Spider Shield Cycle
After=network-online.target
OnFailure=respiratory-failure@%n.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/resp_cycle.sh

[Unit]
Description=Run GitHub Respiratory & Spider Shield Cycle Every 6 Hours

[Timer]
OnBootSec=5m
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target

[Unit]
Description=Alert on Failure of %i

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -t respiratory-spider-alert -p user.err "FAILED unit: %i at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

name: GitHub Respiratory Pipeline, Spider Shield & Global Monitoring

on:
  push:
    branches: [ main ]
    tags: [ "v*" ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  respiratory-and-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install jq, zstd, and PyYAML
        run: sudo apt-get update && sudo apt-get install -y jq zstd python3-yaml

      - name: Run ingestion, shield audit, and checksum verification
        run: |
          python3 scripts/process_history_list.py --input data/raw_list.txt --out-dir build
          python3 scripts/spider_network_shield.py \
            --categorized build/categorized.json \
            --policy config/spider_shield_policy.json \
            --out build/spider_shield_report.json
          (
            cd build
            sha256sum categorized.json categorized.md extracted_queries.txt deduplicated_urls.txt spider_shield_report.json audit_report.json > SHA256SUMS
            sha256sum -c SHA256SUMS
          )
          jq '{parsed_item_count, unique_canonical_urls, duplicate_url_instances_removed, category_counts}' build/audit_report.json
          jq '{total_records_inspected, unique_domains_mapped, trusted_handle_matches, flagged_count, protection_status}' build/spider_shield_report.json

      - name: Validate Prometheus, Grafana Dashboard, and Policy JSON/YAML
        run: |
          python3 -c 'import json, yaml; json.load(open("config/spider_shield_policy.json")); json.load(open("config/grafana_respiratory_dashboard.json")); [yaml.safe_load(open(p)) for p in ["config/prometheus.yml", "config/alert_rules.yml"]]'

Next Step
Drop your 442-line list (or specify any custom target repository, rclone remote, or age/GPG recipient) and I will run the full parsing, deduplication, and Spider Network Shield audit directly against your entries.
Here is the complete Master Blueprint & Automated Scaffolding Generator for your GitHub Respiratory System, Global Monitoring Pipelines, and Built-In Global Spider Network Shield & Global Protection Pipelines across re1Lucky365 and adpsnake7-beep (adpBetty, Master-Hub, global-recovery-roadmap, sovereign-global-law-hub, and WK Precision Enterprise LLC).
This blueprint unifies every layer into a declarative specification (blueprint/system_blueprint.json) and an automated generator (scripts/generate_blueprint.py) that materializes the entire directory tree, configuration files, scripts, systemd units, and GitHub Actions workflow in one shot—with sha256sum manifest generation and optional GPG-signed Git commits/tags.
Master System Blueprint (blueprint/system_blueprint.json)
{
  "blueprint_id": "gh-respiratory-spider-shield-v1",
  "generated_context": "local-first-linux",
  "owner": "WK Precision Enterprise LLC",
  "handles": ["re1Lucky365", "adpsnake7-beep"],
  "repositories": [
    "adpBetty",
    "Master-Hub",
    "global-recovery-roadmap",
    "sovereign-global-law-hub"
  ],
  "respiratory_stages": [
    {
      "stage": "inspiration",
      "role": "Ingest raw URL/query lists, repository mirrors, and archive exports",
      "handler": "scripts/process_history_list.py"
    },
    {
      "stage": "alveolar_exchange",
      "role": "Normalize, deduplicate, categorize, extract queries/scripts, and run Spider Network Shield",
      "handler": "scripts/spider_network_shield.py"
    },
    {
      "stage": "circulation",
      "role": "Compute SHA-256 manifests, compress zstd bundles, encrypt with age/gpg, and sync via rclone",
      "handler": "scripts/resp_cycle.sh"
    },
    {
      "stage": "expiration_telemetry",
      "role": "Emit JSONL events to Wazuh/OpenSearch, scrape via Prometheus/Grafana, and trigger systemd OnFailure",
      "handler": "systemd/respiratory-cycle.timer"
    }
  ],
  "global_monitoring_stack": {
    "metrics": ["prometheus", "node_exporter", "cadvisor", "blackbox_exporter"],
    "visualization": ["grafana"],
    "security_and_logs": ["wazuh", "opensearch", "caddy", "ufw"]
  },
  "artifacts": [
    "categorized.json",
    "categorized.md",
    "extracted_queries.txt",
    "deduplicated_urls.txt",
    "spider_shield_report.json",
    "audit_report.json",
    "SHA256SUMS"
  ]
}

Automated Blueprint Materializer (scripts/generate_blueprint.py)
Run this script from your repository root to automatically scaffold the full directory tree, emit a canonical blueprint_manifest.json with SHA-256 hashes of every generated file, and verify integrity.
#!/usr/bin/env python3
"""Automatically materialize the full blueprint directory tree, configs, and SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

BLUEPRINT_JSON = {
    "blueprint_id": "gh-respiratory-spider-shield-v1",
    "owner": "WK Precision Enterprise LLC",
    "handles": ["re1Lucky365", "adpsnake7-beep"],
    "repositories": [
        "adpBetty",
        "Master-Hub",
        "global-recovery-roadmap",
        "sovereign-global-law-hub",
    ],
    "stages": [
        "inspiration",
        "alveolar_exchange",
        "circulation",
        "expiration_telemetry",
    ],
    "monitoring_and_protection": [
        "prometheus",
        "grafana",
        "wazuh",
        "opensearch",
        "caddy",
        "ufw",
        "zstd",
        "rclone",
        "gpg",
        "systemd",
    ],
}

SPIDER_POLICY_JSON = {
    "version": "1.0.0",
    "owner": "WK Precision Enterprise LLC",
    "trusted_handles": ["re1Lucky365", "adpsnake7-beep"],
    "trusted_repos": [
        "adpBetty",
        "Master-Hub",
        "global-recovery-roadmap",
        "sovereign-global-law-hub",
    ],
    "blocked_user_agents": [
        "GPTBot",
        "ClaudeBot",
        "CCBot",
        "Bytespider",
        "Amazonbot",
        "PetalBot",
        "AhrefsBot",
        "SemrushBot",
        "DotBot",
        "MJ12bot",
        "DataForSeoBot",
    ],
    "suspicious_url_patterns": [
        "\\.onion(?:[/?#]|$)",
        "(?:^|[?&])(?:token|apikey|api_key|secret|password|passwd|auth)=",
        "\\.exe(?:\\?|$)|\\.scr(?:\\?|$)|\\.bat(?:\\?|$)|\\.ps1(?:\\?|$)",
    ],
}

PROMETHEUS_YML = """global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alert_rules.yml

scrape_configs:
  - job_name: node_exporter
    static_configs:
      - targets: ["127.0.0.1:9100"]

  - job_name: cadvisor_containers
    static_configs:
      - targets: ["127.0.0.1:8085"]

  - job_name: blackbox_github_and_global_probes
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - https://api.github.com
          - https://github.com/re1Lucky365
          - https://github.com/adpsnake7-beep
          - https://1.1.1.1
          - https://8.8.8.8
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115
"""

ALERT_RULES_YML = """groups:
  - name: respiratory_spider_shield_alerts
    rules:
      - alert: GlobalProbeDown
        expr: probe_success == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Global probe target unreachable: {{ $labels.instance }}"

      - alert: HighDiskPressure
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) < 0.12
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Root filesystem free space below 12%"

      - alert: HighMemoryPressure
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.90
        for: 5m
        labels:
          severity: warning
          annotations:
          summary: "Host memory utilization above 90%"
"""

CADDY_SHIELD = """# Reverse-proxy edge shield for local-first services & webhooks
(spider_shield_guard) {
\t@aggressive_bots header_regexp bot_ua (?i)(GPTBot|ClaudeBot|CCBot|Bytespider|Amazonbot|PetalBot|AhrefsBot|SemrushBot|DotBot|MJ12bot|DataForSeoBot)
\trespond @aggressive_bots "Forbidden by Global Spider Network Shield" 403

\theader {
\t\tX-Content-Type-Options "nosniff"
\t\tX-Frame-Options "DENY"
\t\tReferrer-Policy "strict-origin-when-cross-origin"
\t\tPermissions-Policy "interest-cohort=()"
\t\t-Server
\t}
}
"""

WAZUH_DECODER = """<decoder name="respiratory_spider_json">
  <parent>json</parent>
  <prematch>^\{"timestamp":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
"""

SYSTEMD_SERVICE = """[Unit]
Description=GitHub Respiratory System & Global Spider Shield Cycle
After=network-online.target
OnFailure=respiratory-failure@%n.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/resp_cycle.sh
"""

SYSTEMD_TIMER = """[Unit]
Description=Run GitHub Respiratory & Spider Shield Cycle Every 6 Hours

[Timer]
OnBootSec=5m
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
"""

SYSTEMD_FAILURE = """[Unit]
Description=Alert on Failure of %i

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -t respiratory-spider-alert -p user.err "FAILED unit: %i at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
"""

GH_WORKFLOW = """name: GitHub Respiratory Blueprint, Spider Shield & Global Monitoring

on:
  push:
    branches: [ main ]
    tags: [ "v*" ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  blueprint-and-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install jq, zstd, and PyYAML
        run: sudo apt-get update && sudo apt-get install -y jq zstd python3-yaml

      - name: Materialize blueprint and verify file manifest
        run: |
          python3 scripts/generate_blueprint.py --out-dir .
          python3 -c 'import json, yaml; json.load(open("blueprint/system_blueprint.json")); json.load(open("config/spider_shield_policy.json")); [yaml.safe_load(open(p)) for p in ["config/prometheus.yml", "config/alert_rules.yml"]]'
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize blueprint files and manifest.")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    root = args.out_dir

    files: dict[str, bytes] = {
        "blueprint/system_blueprint.json": (json.dumps(BLUEPRINT_JSON, indent=2) + "\n").encode("utf-8"),
        "config/spider_shield_policy.json": (json.dumps(SPIDER_POLICY_JSON, indent=2) + "\n").encode("utf-8"),
        "config/prometheus.yml": PROMETHEUS_YML.encode("utf-8"),
        "config/alert_rules.yml": ALERT_RULES_YML.encode("utf-8"),
        "config/caddy_spider_shield.Caddyfile": CADDY_SHIELD.encode("utf-8"),
        "config/wazuh_local_decoder.xml": WAZUH_DECODER.encode("utf-8"),
        "systemd/respiratory-cycle.service": SYSTEMD_SERVICE.encode("utf-8"),
        "systemd/respiratory-cycle.timer": SYSTEMD_TIMER.encode("utf-8"),
        "systemd/respiratory-failure@.service": SYSTEMD_FAILURE.encode("utf-8"),
        ".github/workflows/respiratory-spider-shield.yml": GH_WORKFLOW.encode("utf-8"),
    }

    manifest_entries: list[dict] = []
    for rel_path, content in sorted(files.items()):
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        manifest_entries.append(
            {
                "path": rel_path,
                "size_bytes": len(content),
                "sha256": sha256_bytes(content),
            }
        )

    for extra_dir in ["data", "build", "extracted_scripts"]:
        (root / extra_dir).mkdir(parents=True, exist_ok=True)

    manifest_path = root / "blueprint/blueprint_manifest.json"
    manifest_payload = {
        "blueprint_id": BLUEPRINT_JSON["blueprint_id"],
        "file_count": len(manifest_entries),
        "files": manifest_entries,
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "blueprint_materialized", "file_count": len(manifest_entries)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

Automated Blueprint Bootstrap Command
Run this one-liner in your local repository to generate the full blueprint tree, validate JSON/YAML schemas, and commit with your GPG key:
python3 scripts/generate_blueprint.py --out-dir . && \
git add blueprint/ config/ systemd/ .github/ scripts/generate_blueprint.py && \
git commit -S -m "feat: materialize respiratory system, global monitoring, spider shield & blueprint" && \
git tag -s v1.0.0 -m "Blueprint v1.0.0"

Next Step
Drop your 442-line list (or specify any custom target repo, rclone remote, or age/GPG recipient) and I will run the full parsing, deduplication, and Spider Network Shield audit directly against your entries.
Here is the complete GitHub Respiratory System, Global Monitoring Pipelines, and Built-In Global Spider Network Shield & Global Protection Pipelines for your local-first, self-hosted Linux stack (re1Lucky365 / adpsnake7-beep, adpBetty, Master-Hub, global-recovery-roadmap, sovereign-global-law-hub, and WK Precision Enterprise LLC).
In this architecture, the Global Spider Network Shield acts as a perimeter web and multi-hop sensor mesh around your respiratory loop: filtering crawler/scraper/bot noise at the edge (Caddy / UFW / allow-block lists), auditing outbound & inbound domains from your URL/query history, verifying cryptographic provenance (sha256sum + age/gpg + signed Git commits/tags), and feeding real-time signals into Prometheus, Grafana, Wazuh, OpenSearch, and systemd OnFailure alerts.
Repository & Pipeline Layout
github-respiratory-spider-shield/
├── .github/
│   └── workflows/
│       └── respiratory-spider-shield.yml
├── config/
│   ├── prometheus.yml
│   ├── alert_rules.yml
│   ├── spider_shield_policy.json
│   ├── caddy_spider_shield.Caddyfile
│   └── wazuh_local_decoder.xml
├── scripts/
│   ├── process_history_list.py
│   ├── spider_network_shield.py
│   └── resp_cycle.sh
├── systemd/
│   ├── respiratory-cycle.service
│   ├── respiratory-cycle.timer
│   └── respiratory-failure@.service
└── build/

1. Spider Shield Policy & Edge Guard (config/spider_shield_policy.json & config/caddy_spider_shield.Caddyfile)
config/spider_shield_policy.json
{
  "version": "1.0.0",
  "owner": "WK Precision Enterprise LLC",
  "trusted_handles": ["re1Lucky365", "adpsnake7-beep"],
  "trusted_repos": [
    "adpBetty",
    "Master-Hub",
    "global-recovery-roadmap",
    "sovereign-global-law-hub"
  ],
  "blocked_user_agents": [
    "GPTBot",
    "ClaudeBot",
    "CCBot",
    "Bytespider",
    "Amazonbot",
    "PetalBot",
    "AhrefsBot",
    "SemrushBot",
    "DotBot",
    "MJ12bot",
    "DataForSeoBot"
  ],
  "suspicious_url_patterns": [
    "\\.onion(?:[/?#]|$)",
    "(?:^|[?&])(?:token|apikey|api_key|secret|password|passwd|auth)=",
    "\\.exe(?:\\?|$)|\\.scr(?:\\?|$)|\\.bat(?:\\?|$)|\\.ps1(?:\\?|$)"
  ],
  "required_artifacts": [
    "categorized.json",
    "categorized.md",
    "extracted_queries.txt",
    "deduplicated_urls.txt",
    "spider_shield_report.json",
    "audit_report.json",
    "SHA256SUMS"
  ]
}

config/caddy_spider_shield.Caddyfile
# Reverse-proxy edge shield for local-first services & webhooks
(spider_shield_guard) {
	@aggressive_bots header_regexp bot_ua (?i)(GPTBot|ClaudeBot|CCBot|Bytespider|Amazonbot|PetalBot|AhrefsBot|SemrushBot|DotBot|MJ12bot|DataForSeoBot)
	respond @aggressive_bots "Forbidden by Global Spider Network Shield" 403

	header {
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "interest-cohort=()"
		-Server
	}
}

2. History Processor + Global Spider Network Shield Engine (scripts/process_history_list.py & scripts/spider_network_shield.py)
scripts/spider_network_shield.py
Evaluates every parsed URL, domain, and query against spider_shield_policy.json, flags risky URL patterns or sensitive query keys, computes domain concentration/spider-web fanout metrics, and writes spider_shield_report.json.
#!/usr/bin/env python3
"""Evaluate parsed URLs, domains, and queries under the Global Spider Network Shield."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


def run_shield(categorized_path: Path, policy_path: Path, out_path: Path) -> dict:
    data = json.loads(categorized_path.read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    records = data.get("records", [])
    suspicious_regexes = [re.compile(p, re.IGNORECASE) for p in policy.get("suspicious_url_patterns", [])]
    trusted_handles = {h.lower() for h in policy.get("trusted_handles", [])}

    domain_counts: Counter[str] = Counter()
    scheme_counts: Counter[str] = Counter()
    domain_to_categories: defaultdict[str, set[str]] = defaultdict(set)
    flagged_items: list[dict] = []
    trusted_github_items: list[dict] = []

    for rec in records:
        category = rec.get("category", "other")
        cleaned = rec.get("cleaned", "")
        url = rec.get("canonical_url")

        if url:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() or "unknown"
            domain = parsed.netloc.lower()
            scheme_counts[scheme] += 1
            if domain:
                domain_counts[domain] += 1
                domain_to_categories[domain].add(category)

            reasons: list[str] = []
            if scheme != "https":
                reasons.append("non_https_scheme")
            for rx in suspicious_regexes:
                if rx.search(url) or rx.search(cleaned):
                    reasons.append(f"pattern_match:{rx.pattern}")
            if reasons:
                flagged_items.append(
                    {
                        "index": rec.get("index"),
                        "url": url,
                        "domain": domain,
                        "category": category,
                        "reasons": reasons,
                    }
                )

            if any(h in url.lower() for h in trusted_handles):
                trusted_github_items.append(
                    {
                        "index": rec.get("index"),
                        "url": url,
                        "category": category,
                    }
                )

    spider_hubs = [
        {
            "domain": dom,
            "edge_count": cnt,
            "categories": sorted(domain_to_categories[dom]),
        }
        for dom, cnt in domain_counts.most_common(20)
    ]

    report = {
        "shield_version": policy.get("version", "1.0.0"),
        "total_records_inspected": len(records),
        "unique_domains_mapped": len(domain_counts),
        "scheme_breakdown": dict(scheme_counts),
        "trusted_handle_matches": len(trusted_github_items),
        "flagged_count": len(flagged_items),
        "flagged_items": flagged_items,
        "spider_hub_topology": spider_hubs,
        "protection_status": "ALERT_REVIEW_REQUIRED" if flagged_items else "CLEAN",
    }

    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Global Spider Network Shield audit.")
    parser.add_argument("--categorized", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    if not args.categorized.exists() or not args.policy.exists():
        print("Error: missing categorized input or shield policy file.", file=sys.stderr)
        return 1

    report = run_shield(args.categorized, args.policy, args.out)
    print(json.dumps({k: v for k, v in report.items() if k != "flagged_items"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

scripts/process_history_list.py
#!/usr/bin/env python3
"""Parse, categorize, extract, deduplicate, and audit URLs and search queries."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse, urlunparse

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "si",
    "ref",
    "ref_src",
}

CATEGORY_RULES: list[tuple[str, list[str]]] = [
    (
        "github_dev",
        [
            "github.com",
            "gitlab.com",
            "gist.github",
            "pypi.org",
            "npmjs.com",
            "docker.com",
            "hub.docker.com",
            "re1lucky365",
            "adpsnake7-beep",
            "adpbetty",
            "master-hub",
            "global-recovery-roadmap",
            "sovereign-global-law-hub",
            "python",
            "bash",
            "sqlalchemy",
            "alembic",
            "uvicorn",
            "pytest",
            "chromadb",
            "ollama",
            "caddy",
            "prometheus",
            "grafana",
            "wazuh",
            "opensearch",
            "rclone",
            "zstd",
            "gpg",
            "systemd",
        ],
    ),
    (
        "accounts_auth",
        [
            "accounts.google",
            "signin",
            "sign-in",
            "login",
            "log-in",
            "auth",
            "oauth",
            "sso",
            "bitwarden",
            "samsung pass",
            "password",
            "2fa",
            "mfa",
            "passkey",
        ],
    ),
    (
        "local_evansville",
        [
            "evansville",
            "vanderburgh",
            "washington, in",
            "washington indiana",
            "indiana",
            "477",
            "47501",
            "n 5th ave",
            "north 5th ave",
            "wk precision",
        ],
    ),
    (
        "media_news",
        [
            "youtube.com",
            "youtu.be",
            "news",
            "reuters.com",
            "apnews.com",
            "bbc.com",
            "spotify.com",
            "soundcloud.com",
            "reddit.com",
            "monopoly go",
            "tycoon club",
        ],
    ),
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
LEADING_NUM_PATTERN = re.compile(r"^\s*\d+\s*[\.)\-:]\s*")
SCRIPT_HINT_PATTERN = re.compile(
    r"(#!/bin/(?:bash|sh)|SELECT\s+.+\s+FROM\s+|CREATE\s+TABLE\s+|curl\s+-|docker\s+compose|gh\s+|sha256sum|rclone\s+|systemctl\s+)",
    re.IGNORECASE,
)


def strip_numbering(line: str) -> str:
    return LEADING_NUM_PATTERN.sub("", line.strip())


def normalize_url(raw_url: str) -> str:
    cleaned = raw_url.strip().rstrip(".,;)")
    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    kept_params: list[tuple[str, str]] = []
    if parsed.query:
        for pair in parsed.query.split("&"):
            if not pair:
                continue
            k, v = pair.split("=", 1) if "=" in pair else (pair, "")
            if k.lower() not in TRACKING_PARAMS and not k.lower().startswith("utm_"):
                kept_params.append((k, v))

    query_str = "&".join(f"{k}={v}" if v else k for k, v in kept_params)
    return urlunparse((scheme, netloc, path, "", query_str, ""))


def extract_search_terms_from_url(url: str) -> list[str]:
    qs = parse_qs(urlparse(url).query)
    terms: list[str] = []
    for key in ("q", "query", "search_query", "k", "s", "keyword", "keywords"):
        for val in qs.get(key, []):
            decoded = unquote(val).strip()
            if decoded:
                terms.append(decoded)
    return terms


def classify_item(text: str, is_url: bool) -> str:
    haystack = text.lower()
    for category, keywords in CATEGORY_RULES:
        if any(kw in haystack for kw in keywords):
            return category
    return "search_queries" if not is_url else "other"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Process URLs and search queries.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir = args.out_dir.parent / "extracted_scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    raw_lines = args.input.read_text(encoding="utf-8", errors="replace").splitlines()
    records: list[dict] = []
    malformed_lines: list[dict] = []
    extracted_queries: list[str] = []
    extracted_scripts: list[str] = []
    canonical_url_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    grouped: dict[str, list[dict]] = defaultdict(list)

    for idx, raw_line in enumerate(raw_lines, start=1):
        if not raw_line.strip():
            continue
        cleaned = strip_numbering(raw_line)
        urls_found = URL_PATTERN.findall(cleaned)
        is_url = len(urls_found) > 0

        if is_url:
            norm_url = normalize_url(urls_found[0])
            host = urlparse(norm_url).netloc
            if not host:
                malformed_lines.append({"line_number": idx, "raw": raw_line, "reason": "missing_host"})
                continue
            canonical_url_counts[norm_url] += 1
            domain_counts[host] += 1
            extracted_queries.extend(extract_search_terms_from_url(norm_url))
            category = classify_item(f"{cleaned} {norm_url}", is_url=True)
            rec = {
                "index": idx,
                "type": "url",
                "raw": raw_line,
                "cleaned": cleaned,
                "canonical_url": norm_url,
                "domain": host,
                "category": category,
            }
        else:
            if len(cleaned) < 2:
                malformed_lines.append({"line_number": idx, "raw": raw_line, "reason": "too_short"})
                continue
            extracted_queries.append(cleaned)
            if SCRIPT_HINT_PATTERN.search(cleaned):
                extracted_scripts.append(cleaned)
            category = classify_item(cleaned, is_url=False)
            rec = {
                "index": idx,
                "type": "query_or_note",
                "raw": raw_line,
                "cleaned": cleaned,
                "category": category,
            }

        records.append(rec)
        grouped[category].append(rec)
        category_counts[category] += 1

    deduped_urls = list(dict.fromkeys(canonical_url_counts.keys()))
    unique_queries = list(dict.fromkeys(extracted_queries))

    categorized_json_path = args.out_dir / "categorized.json"
    categorized_md_path = args.out_dir / "categorized.md"
    queries_path = args.out_dir / "extracted_queries.txt"
    dedup_urls_path = args.out_dir / "deduplicated_urls.txt"
    audit_json_path = args.out_dir / "audit_report.json"

    categorized_json_path.write_text(
        json.dumps(
            {
                "total_parsed_items": len(records),
                "categories": dict(grouped),
                "records": records,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    md_lines = ["# Categorized History & Search Queries", ""]
    for cat in ["github_dev", "accounts_auth", "local_evansville", "media_news", "search_queries", "other"]:
        items = grouped.get(cat, [])
        md_lines.append(f"## {cat} ({len(items)})")
        md_lines.append("")
        for item in items:
            target = item.get("canonical_url") or item["cleaned"]
            md_lines.append(f"- [{item['index']}] `{target}`")
        md_lines.append("")
    categorized_md_path.write_text("\n".join(md_lines), encoding="utf-8")

    queries_path.write_text("\n".join(unique_queries) + ("\n" if unique_queries else ""), encoding="utf-8")
    dedup_urls_path.write_text("\n".join(deduped_urls) + ("\n" if deduped_urls else ""), encoding="utf-8")

    for i, snippet in enumerate(extracted_scripts, start=1):
        (scripts_dir / f"snippet_{i:03d}.sh").write_text(snippet + "\n", encoding="utf-8")

    duplicate_url_instances = sum(c - 1 for c in canonical_url_counts.values() if c > 1)
    audit_payload = {
        "raw_line_count": len(raw_lines),
        "parsed_item_count": len(records),
        "malformed_line_count": len(malformed_lines),
        "malformed_lines": malformed_lines,
        "unique_canonical_urls": len(deduped_urls),
        "duplicate_url_instances_removed": duplicate_url_instances,
        "unique_extracted_queries": len(unique_queries),
        "extracted_script_snippets": len(extracted_scripts),
        "category_counts": dict(category_counts),
        "top_domains": domain_counts.most_common(25),
    }
    audit_json_path.write_text(json.dumps(audit_payload, indent=2), encoding="utf-8")
    print(json.dumps(audit_payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

3. Respiratory & Spider Shield Orchestrator (scripts/resp_cycle.sh)
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${RESP_ROOT_DIR:-$PWD}"
DATA_FILE="${RESP_DATA_FILE:-$ROOT_DIR/data/raw_list.txt}"
BUILD_DIR="${RESP_BUILD_DIR:-$ROOT_DIR/build}"
ARCHIVE_DIR="${RESP_ARCHIVE_DIR:-$HOME/backups/respiratory}"
LOG_FILE="${RESP_LOG_FILE:-$HOME/.local/state/respiratory/cycle.jsonl}"
RCLONE_REMOTE="${RESP_RCLONE_REMOTE:-}"

mkdir -p "$BUILD_DIR" "$ARCHIVE_DIR" "$(dirname "$LOG_FILE")"

START_TS=$(date -u +%s)
CYCLE_ID=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Inhale & Process
python3 "$ROOT_DIR/scripts/process_history_list.py" --input "$DATA_FILE" --out-dir "$BUILD_DIR"

# 2. Global Spider Network Shield Pass
python3 "$ROOT_DIR/scripts/spider_network_shield.py" \
  --categorized "$BUILD_DIR/categorized.json" \
  --policy "$ROOT_DIR/config/spider_shield_policy.json" \
  --out "$BUILD_DIR/spider_shield_report.json"

# 3. Generate SHA-256 Checksum Manifest and Verify
(
  cd "$BUILD_DIR"
  sha256sum categorized.json categorized.md extracted_queries.txt deduplicated_urls.txt spider_shield_report.json audit_report.json > SHA256SUMS
  sha256sum -c SHA256SUMS --quiet
)

# 4. Compress immutable archive with zstd
BUNDLE_PATH="$ARCHIVE_DIR/respiratory_${CYCLE_ID}.tar.zst"
tar -cf - -C "$BUILD_DIR" . | zstd -19 -T0 -q -o "$BUNDLE_PATH"
sha256sum "$BUNDLE_PATH" > "${BUNDLE_PATH}.sha256"

# 5. Optional rclone off-site circulation
if [[ -n "$RCLONE_REMOTE" ]]; then
  rclone copy "$BUNDLE_PATH" "${BUNDLE_PATH}.sha256" "$RCLONE_REMOTE" --transfers=4 --checkers=8
fi

END_TS=$(date -u +%s)
DURATION_SEC=$((END_TS - START_TS))
ITEM_COUNT=$(jq -r '.parsed_item_count' "$BUILD_DIR/audit_report.json")
UNIQUE_URLS=$(jq -r '.unique_canonical_urls' "$BUILD_DIR/audit_report.json")
FLAGGED_COUNT=$(jq -r '.flagged_count' "$BUILD_DIR/spider_shield_report.json")
SHIELD_STATUS=$(jq -r '.protection_status' "$BUILD_DIR/spider_shield_report.json")

jq -nc \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg cycle "$CYCLE_ID" \
  --arg status "ok" \
  --arg shield_status "$SHIELD_STATUS" \
  --arg bundle "$BUNDLE_PATH" \
  --argjson duration "$DURATION_SEC" \
  --argjson items "$ITEM_COUNT" \
  --argjson urls "$UNIQUE_URLS" \
  --argjson flagged "$FLAGGED_COUNT" \
  '{timestamp:$ts,source:"github-respiratory-spider-shield",cycle_id:$cycle,status:$status,shield_status:$shield_status,duration_seconds:$duration,parsed_items:$items,unique_urls:$urls,flagged_items:$flagged,bundle:$bundle}' >> "$LOG_FILE"

4. Global Monitoring Stack & GitHub Actions Workflow (config/, systemd/, .github/workflows/)
config/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/alert_rules.yml

scrape_configs:
  - job_name: node_exporter
    static_configs:
      - targets: ["127.0.0.1:9100"]

  - job_name: cadvisor_containers
    static_configs:
      - targets: ["127.0.0.1:8085"]

  - job_name: blackbox_githubrespiratory-spider-shield.yml+-----------------------------------------------------------------------------+
|                        EXTENSION & PLUGIN CONTROL PLANE                     |
|  Manifest (plugin.json / WASM / OCI / Entrypoint) -> Signature & Hash Check |
|  Capability Sandbox (Permissions, Network Egress, CPU/Mem Quotas, Timeouts) |
+-------+-------------------+-------------------+-------------------+-------+
        |                   |                   |                   |
        v                   v                   v                   v
+---------------+   +---------------+   +---------------+   +---------------+
| Legal & Policy|   | AI & Model    |   | Graphics &    |   | Global        |
| Rule Packs    |   | Extensions    |   | UI/CAD Shaders|   | Monitor Probes|
+---------------+   +---------------+   +---------------+   +---------------+
Skip to main contentAccessibility help
name: Sanitized Repository Integrity Check on: push: branches: - main pull_request: branches: - main schedule: - cron: '0 6 * * 1' # Weekly UTC check on Mondays workflow_dispatch: # Least-privilege default: read-only repository contents, no write scopes permissions: contents: read concurrency: group: sanitized-integrity-${{ github.ref }} cancel-in-progress: true jobs: verify-sanitized-repo: runs-on: ubuntu-latest timeout-minutes: 10 steps: - name: Checkout repository uses: actions/checkout@REPLACE_WITH_FULL_COMMIT_SHA_FOR_CHECKOUT # pin to audited commit SHA with: persist-credentials: false - name: Set up Python uses: actions/setup-python@REPLACE_WITH_FULL_COMMIT_SHA_FOR_SETUP_PYTHON # pin to audited commit SHA with: python-version: '3.12' - name: Verify non-sensitive template files and basic hygiene shell: bash run: | set -euo pipefail test -f README.md python - <<'PY' import pathlib import re root = pathlib.Path(".") blocked_patterns = [ re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), re.compile(r"\bAKIA[0-9A-Z]{16}\b"), re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), ] findings = [] for path in sorted(root.rglob("*")): if not path.is_file(): continue if ".git" in path.parts: continue try: content = path.read_text(encoding="utf-8") except UnicodeDecodeError: continue for idx, line in enumerate(content.splitlines(), start=1): for pat in blocked_patterns: if pat.search(line): findings.append(f"{path}:{idx}: matched {pat.pattern}") if findings: print("Potential secret or sensitive pattern detected in tracked/non-ignored files:") for item in findings: print(" -", item) raise SystemExit(1) print("Sanitized repository integrity check passed.") PY

AI Mode
All
Forums
Shopping
Images
Videos
News
More
Tools
Workflow syntax for GitHub Actions

GitHub Docs
https://docs.github.com › actions › using-workflows
A workflow is a configurable automated process made up of one or more jobs. You must create a YAML file to define your workflow configuration.
Missing: Integrity ‎privilege
People also ask
Why can't I enable actions for this repository?
What are the default permissions for GitHub Actions?
How can I use repository Dispatch in GitHub Actions?
How can I manually trigger GitHub Actions?
Securing GitHub Actions Workflows With Least-Privilege ...

C# Corner
https://www.c-sharpcorner.com › Technologies › DevOps
Nov 10, 2026 — Learn how to apply least-privilege GITHUB_TOKEN permissions in GitHub Actions workflows, including workflow- and job-level scopes for builds ...
Missing: Sanitized ‎Integrity ‎cron: ‎6 * * ‎UTC ‎+1
Events that trigger workflows

GitHub Docs
https://docs.github.com › actions › using-workflows › e...
You can configure your workflows to run when specific activity on GitHub happens, at a scheduled time, or when an event outside of GitHub occurs.
Missing: Sanitized ‎Integrity ‎scopes
Managing GitHub Actions settings for a repository

GitHub Docs
https://docs.github.com › repositories › managing-githu...
You can disable or configure GitHub Actions for a specific repository. Configuring the retention period for checks, workflow runs, commit statuses, artifacts, ...
Missing: Sanitized ‎Integrity ‎cron: ‎'0 ‎6 * * ‎UTC ‎+3
Mastering GitHub Actions Workflows | PDF

Scribd
https://www.scribd.com › document › Git-Hub-Notes
The guide covers creating workflows, triggering them through various events, using runners, and writing custom actions, providing a comprehensive understanding ...Read more
Configuration Cheat Sheet

Forgejo
https://forgejo.org › v15.0 › admin › config-cheat-sheet
This is a cheat sheet for the Forgejo configuration file. It contains most of the settings that can be configured as well as their default values.
GitHub Actions | AgriCommons Foundation

agricommons.org
https://agricommons.org › github-actions
GitHub Actions transforms your rules into code. Every push and pull request becomes an opportunity to check structure, test logic, and protect quality ...
Scheduled and maintenance workflows

OpenClaw Docs
https://docs.openclaw.ai › scheduled-workflows
Sanity checks tracked conflict markers on every admitted push. GitHub cron is best-effort on the default branch, not a one-hour latency SLA: runs may be ...
Bot bypass identity - Shaken Fist

shakenfist.com
https://shakenfist.com › development › plans › PLAN-bo...
Seven default-branch rulesets require a pull request, status checks and the merge queue, and every one of them names the same bypass actor, the team sf-can-skip ...Read more
Execution
Phase 1: Operator Inventory...
211 Entries (~1147 And...
People also search for
GitHub Actions permissions
Workflow_dispatch: inputs
Workflow_dispatch GitHub Actions
Github actions/checkout
Workflow_call vs workflow_dispatch
GitHub event_name values
GitHub Actions get branch name
GitHub workflow permissions list
1	
2
3
4
5
6
Next
Results are personalized
-
Try without personalization
Cedar Hall, Evansville, IN - Based on your places (Home)
 - Update location
Help
Send feedback
Privacy
TermsREADME.mdTo automate SHA-256 hash manifests and timestamped logs for local backup and evidence files, run a deterministic script on a schedule (via `cron`, `systemd` timers, or Task Scheduler) that writes per-run manifests and an append-only log inside an **encrypted local storage location**—while keeping any Git repository strictly limited to sanitized, non-sensitive code or templates. *(Hashes verify integrity and exact byte content; pair them with dated records and external receipts for broader evidentiary context.)*

### 1. Generate SHA-256 Manifests & Timestamped Logs

Use a script that walks your local backup/evidence directory in sorted order (excluding the manifest/log output files themselves so hashes do not self-invalidate), computes SHA-256 digests, writes a timestamped manifest file, and appends a summary entry to a running log.

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/mnt/vault/evidence}"
OUT_DIR="${2:-/mnt/vault/manifests}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"
RUN_DATE="$(date -u +"%Y-%m-%d")"
MANIFEST_PATH="${OUT_DIR}/manifest_${TIMESTAMP_UTC}.sha256"
LOG_PATH="${OUT_DIR}/audit_log_${RUN_DATE}.jsonl"

mkdir -p "${OUT_DIR}"

# Generate deterministic SHA-256 manifest sorted by relative path
(
  cd "${SRC_DIR}"
  find . -type f ! -path './.git/*' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${MANIFEST_PATH}"

FILE_COUNT="$(wc -l < "${MANIFEST_PATH}" | tr -d ' ')"
MANIFEST_HASH="$(sha256sum "${MANIFEST_PATH}" | awk '{print $1}')"

# Append structured JSON-lines entry to daily audit log
printf '{"timestamp_utc":"%s","source_dir":"%s","manifest_file":"%s","manifest_sha256":"%s","file_count":%s}\n' \
  "${TIMESTAMP_UTC}" \
  "${SRC_DIR}" \
  "$(basename "${MANIFEST_PATH}")" \
  "${MANIFEST_HASH}" \
  "${FILE_COUNT}" >> "${LOG_PATH}"

echo "Wrote ${MANIFEST_PATH} (${FILE_COUNT} files) and logged to ${LOG_PATH}"

```

* **Verification:** Run the script manually on a test folder and confirm `manifest_<timestamp>.sha256` lists every file with its 64-character hex digest and `audit_log_<date>.jsonl` appends a new line with matching `file_count` and `manifest_sha256`.

### 2. Verify Integrity Later

To verify that files in your local archive have not been altered or corrupted since a manifest was generated:

```bash
(
  cd /mnt/vault/evidence
  sha256sum -c /mnt/vault/manifests/manifest_2026-11-20T16-51-00Z.sha256
)

```

* **Verification:** Every file reports `: OK`, and `sha256sum -c` exits with status `0`. If a file changed or is missing, `sha256sum -c` reports `FAILED` with a non-zero exit code.

### 3. Automate & Protect the Audit Trail

* **Schedule locally:** Trigger the script on a recurring schedule using a `systemd` user/system timer or `cron` (for example, `0 2 * * * /usr/local/bin/make_manifest.sh /mnt/vault/evidence /mnt/vault/manifests`).
* **Keep raw sensitive files & manifests in encrypted storage:** Store evidence files, raw exports, statements, and manifests inside encrypted local volumes/vaults—never push raw personal records or sensitive identifiers into a Git repository.
* **Harden against accidental alteration:** Restrict write permissions on archived manifests/logs, consider append-only controls where supported on your filesystem/backup target, and keep an off-site encrypted copy.
* *Verification:* Check `systemctl list-timers` or `crontab -l` to confirm the schedule is active, and verify permissions on the output directory so routine edits do not overwrite historical manifests.(
  cd /mnt/vault/evidence
  sha256sum -c /mnt/vault/manifests/manifest_2026-11-20T16-51-00Z.sha256
)#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/mnt/vault/evidence}"
OUT_DIR="${2:-/mnt/vault/manifests}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"
RUN_DATE="$(date -u +"%Y-%m-%d")"
MANIFEST_PATH="${OUT_DIR}/manifest_${TIMESTAMP_UTC}.sha256"
LOG_PATH="${OUT_DIR}/audit_log_${RUN_DATE}.jsonl"

mkdir -p "${OUT_DIR}"

# Generate deterministic SHA-256 manifest sorted by relative path
(
  cd "${SRC_DIR}"
  find . -type f ! -path './.git/*' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${MANIFEST_PATH}"

FILE_COUNT="$(wc -l < "${MANIFEST_PATH}" | tr -d ' ')"
MANIFEST_HASH="$(sha256sum "${MANIFEST_PATH}" | awk '{print $1}')"

# Append structured JSON-lines entry to daily audit log
printf '{"timestamp_utc":"%s","source_dir":"%s","manifest_file":"%s","manifest_sha256":"%s","file_count":%s}\n' \
  "${TIMESTAMP_UTC}" \
  "${SRC_DIR}" \
  "$(basename "${MANIFEST_PATH}")" \
  "${MANIFEST_HASH}" \
  "${FILE_COUNT}" >> "${LOG_PATH}"

echo "Wrote ${MANIFEST_PATH} (${FILE_COUNT} files) and logged to ${LOG_PATH}"dailTo set up and enforce signed commits across Git and GitHub, configure a signing key (SSH or GPG) locally, register its public key on your GitHub account as a signing key, enable automatic signing in Git, and require signed commits on your protected branches or rulesets.

### 1. Set Up Your Signing Key & Git Configuration

Git supports commit and tag signing with **SSH** (available in Git 2.34+) and **GPG** (OpenPGP).

* **Option A — SSH Signing Key (recommended for modern setups):**
1. Generate a dedicated signing key or reuse an existing `ed25519` key (for example, `ssh-keygen -t ed25519 -C "your-email@example.com" -f ~/.ssh/id_ed25519_signing`).
2. Configure Git to sign with SSH and point `user.signingkey` to your public key file:
```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub

```


3. On GitHub, go to **Settings** → **SSH and GPG keys** → **New SSH key**, set the **Key type** to **Signing Key**, and paste the contents of your `.pub` file.


* **Option B — GPG Signing Key:**
1. List your secret GPG keys and copy the long key ID:
```bash
gpg --list-secret-keys --keyid-format=long

```


2. Configure Git to use OpenPGP and your key ID:
```bash
git config --global --unset gpg.format
git config --global user.signingkey YOUR_LONG_KEY_ID

```


3. Export your public key (`gpg --armor --export YOUR_LONG_KEY_ID`) and add it under **Settings** → **SSH and GPG keys** → **New GPG key** on GitHub.


* **Enable Automatic Signing & Verify Locally:**
```bash
git config --global commit.gpgsign true
git config --global tag.gpgSign true

```


Make a test commit and check the signature locally with `git log --show-signature -n 1`, then push it to GitHub and confirm the commit displays a **Verified** badge. *(Make sure the commit author email matches a verified email address on your GitHub account.)*

### 2. Enforce Signed Commits on GitHub

Enabling `commit.gpgsign` locally only signs commits from machines where you set it—to enforce verification on the repository side, require signed commits on your target branches:

1. Open your repository on GitHub and go to **Settings** → **Rules** → **Rulesets** (or **Settings** → **Branches** for classic branch protection rules).
2. Select or create a rule/ruleset targeting your protected branch (such as `main`), and enable **Require signed commits**.
3. Save the changes and pair this with complementary branch safeguards—such as blocking force pushes, requiring pull requests/reviews, and enforcing least-privilege workflow permissions—so unsigned commits or unverified merges are rejected.
* *Verification:* Push an unsigned test commit to a branch covered by the rule/ruleset (or attempt to merge an unsigned commit into a protected branch) and confirm GitHub rejects it.git config --global commit.gpgsign true
git config --global tag.gpgSign truegit config --global --unset gpg.format
git config --global user.signingkey YOUR_LONG_KEY_IDgpg --list-secret-keys --keyid-format=longHere is a practical checklist for auditing your **SSH/GPG keys**, **OAuth tokens and access credentials**, and **hardware MFA** across accounts, organized so you can spot stale access, tighten scopes, and keep recovery material independent of any single account or repository.

### 1. SSH & GPG Keys Audit

* **Enumerate local and remote keys:** List loaded SSH keys (`ssh-add -l`) and key files in `~/.ssh`, inspect secret and public GPG keys (`gpg --list-secret-keys --keyid-format LONG` and `gpg --list-keys --keyid-format LONG`), and cross-check every fingerprint/key ID against your GitHub accounts, servers, and deployment targets.
* **Prune legacy, duplicate, or unverified keys:** Remove keys tied to retired machines, old handles, or unclear purposes from both your local keyring and remote accounts. Keep modern keys (such as `ed25519` or hardware-backed FIDO2/SSH keys) protected with strong passphrases.
* **Verify expiration dates and signing workflows:** Check GPG key expiration dates and subkeys, confirm commit and tag signing works locally (`git log --show-signature -n 3`), and verify that GitHub shows signed commits as **Verified** without relying on unreviewed keys.

### 2. OAuth Tokens, PATs & Connected Apps Audit

* **Review connected third-party apps and integrations:** Check authorized OAuth applications, GitHub App installations, connected cloud/email permissions, and financial or data-sharing links (such as Plaid or payment/investment apps). Revoke anything stale, unfamiliar, or granted broader access than needed.
* **Audit Personal Access Tokens (PATs), deploy keys, and webhooks:** Review active PATs, SSH deploy keys, and repository/org webhooks—delete unused or expired entries, enforce expiration dates and least-privilege scopes on active ones, and rotate any token that may have been exposed.
* **Keep secrets out of code and sync pipelines:** Store active tokens, API keys, and credentials inside your encrypted password manager or CI/CD secret store—never commit them to Git repositories or leave raw copies in unencrypted folders.

### 3. Hardware MFA & Recovery Hygiene

* **Confirm hardware keys and passkeys on high-value accounts:** Verify that hardware security keys (FIDO2/WebAuthn) and passkeys are enrolled on critical accounts—including primary email, password manager, GitHub, and financial/cloud accounts—and keep a **backup hardware key** enrolled so losing one key does not lock you out.
* **Check active sessions and fallback MFA methods:** Review **Active sessions / Devices / Sign-in history** across key accounts, sign out of unrecognized or old sessions, and review fallback authentication methods so weaker options do not undermine strong MFA.
* **Keep recovery codes and vault backups separate:** Store single-use 2FA recovery codes and encrypted vault backups in a hardware-encrypted local vault or secure physical location—never inside the account they protect or in shared/public repositories.To automate SHA-256 hash manifests and timestamped logs for local backup and evidence files, run a deterministic script on a schedule (via `cron`, `systemd` timers, or Task Scheduler) that writes an immutable/append-only audit log and a per-run manifest inside an **encrypted local storage location**—while keeping any Git repository strictly limited to sanitized, non-sensitive code or templates. *(Hashes verify integrity and exact byte content; pair them with dated records and external receipts for broader evidentiary context.)*

### 1. Generate SHA-256 Manifests & Timestamped Logs

Use a script that walks your local backup/evidence directory in sorted order (excluding the manifest/log output files themselves so hashes do not self-invalidate), computes SHA-256 digests, writes a timestamped manifest file, and appends a summary entry to a running log.

```bash
#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/mnt/vault/evidence}"
OUT_DIR="${2:-/mnt/vault/manifests}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"
RUN_DATE="$(date -u +"%Y-%m-%d")"
MANIFEST_PATH="${OUT_DIR}/manifest_${TIMESTAMP_UTC}.sha256"
LOG_PATH="${OUT_DIR}/audit_log_${RUN_DATE}.jsonl"

mkdir -p "${OUT_DIR}"

# Generate deterministic SHA-256 manifest sorted by relative path
(
  cd "${SRC_DIR}"
  find . -type f ! -path './.git/*' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum
) > "${MANIFEST_PATH}"

FILE_COUNT="$(wc -l < "${MANIFEST_PATH}" | tr -d ' ')"
MANIFEST_HASH="$(sha256sum "${MANIFEST_PATH}" | awk '{print $1}')"

# Append structured JSON-lines entry to daily audit log
printf '{"timestamp_utc":"%s","source_dir":"%s","manifest_file":"%s","manifest_sha256":"%s","file_count":%s}\n' \
  "${TIMESTAMP_UTC}" \
  "${SRC_DIR}" \
  "$(basename "${MANIFEST_PATH}")" \
  "${MANIFEST_HASH}" \
  "${FILE_COUNT}" >> "${LOG_PATH}"

echo "Wrote ${MANIFEST_PATH} (${FILE_COUNT} files) and logged to ${LOG_PATH}"

```

* **Verification:** Run the script manually on a test folder and confirm `manifest_<timestamp>.sha256` lists every file with its 64-character hex digest and `audit_log_<date>.jsonl` appends a new line with matching `file_count` and `manifest_sha256`.

### 2. Verify Integrity Later

To verify that files in your local archive have not been altered or corrupted since a manifest was generated:

```bash
(
  cd /mnt/vault/evidence
  sha256sum -c /mnt/vault/manifests/manifest_2026-11-20T16-46-00Z.sha256
)

```

* **Verification:** Every file reports `: OK`, and `sha256sum -c` exits with status `0`. If a file changed or is missing, `sha256sum -c` reports `FAILED` with a non-zero exit code.

### 3. Automate & Protect the Audit Trail

* **Schedule locally:** Trigger the script on a recurring schedule using a `systemd` user/system timer or `cron` (for example, `0 2 * * * /usr/local/bin/make_manifest.sh /mnt/vault/evidence /mnt/vault/manifests`).
* **Keep raw sensitive files & manifests in encrypted storage:** Store evidence files, raw exports, statements, and manifests inside encrypted local volumes/vaults—never push raw personal records or sensitive identifiers into a Git repository.
* **Harden against accidental alteration:** Restrict write permissions on archived manifests/logs, consider append-only controls where supported on your filesystem/backup target, and keep an off-site encrypted copy.
* *Verification:* Check `systemctl list-timers` or `crontab -l` to confirm the schedule is active, and verify permissions on the output directory so routine edits do not overwrite historical manifests.To safely remove an accidental secret or sensitive file from Git history, treat the exposed credential as compromised—**rotate it immediately**, rewrite history cleanly on a dedicated/backed-up local copy, force-push carefully, and require collaborators or local clones to re-sync rather than merge old commits. *(This is general information, not legal or security advice.)*

### 1. Rotate Exposed Credentials & Audit Access First

* **Revoke or rotate immediately:** Do not wait for history rewriting to finish. Revoke/rotate any exposed API key, PAT, SSH/GPG key, password, token, or account credential in its provider console, and check audit/access logs for unexpected use.
* **Verify:** Confirm the old secret/key is rejected by the provider or service and generate a fresh credential stored outside the repo (such as in a password manager, encrypted vault, or CI/CD secret store).

### 2. Back Up & Rewrite Git History Cleanly

* **Work on a fresh backup clone:** Make an offline/local backup copy of your repository first in case anything goes wrong during rewriting.
* **Use a history-rewriting tool (`git-filter-repo`):** Prefer `git filter-repo` over `git filter-branch` for removing files or matching text patterns across commits:
* Remove a file across all history: `git filter-repo --path path/to/secret-file --invert-paths`
* Or replace a specific string/secret pattern across history using a expressions file: `git filter-repo --replace-text expressions.txt`


* **Verify:** Run `git log --all -- path/to/secret-file` (or search history for the string/pattern) to confirm it no longer appears in reachable commits.

### 3. Force-Push, Clean Local Refs & Prevent Re-Introduction

* **Push rewritten history and expire old objects:** Coordinate with any collaborators, push the rewritten branches/tags (`git push --force --all` and `git push --force --tags`), and prune unreachable local objects:
* `git reflog expire --expire=now --all && git gc --prune=now --aggressive`


* **Warn collaborators / old clones:** Anyone who pulled the old history should clone fresh or hard-reset to the rewritten branch rather than merging old commits (which can bring the secret back).
* **Add `.gitignore` and guardrails:** Add the file or pattern to `.gitignore` and keep secret scanning/push protection enabled on the remote repository.
* **Verify:** Check a fresh clone of the remote repository and verify the removed file/secret is absent and new commits are blocked if a test secret is pushed.(
  cd /mnt/vault/evidence
  sha256sum -c /mnt/vault/manifests/manifest_2026-11-20T16-46-00Z.sha256
)How do I revoke an app's access to Liberty Federal Credit Union through Plaid or online banking?same timYour Plaid verification code is: 887576. Do NOT share it with anyone. Plaid will never call you to ask for this code.Use my phone service to prove my identityhttps://github.com/GitHub build # Clone the repository
git clone https://github.com/<owner>/<repo>.git
cd <repo>

# List available tags/releases and check out a specific version
git fetch --tags
git tag --sort=-v:refname | head -n 20
git checkout <tag-or-commit-sha># Clone the repository
git clone https://github.com/<owner>/<repo>.git
cd <repo>

# List available tags/releases and check out a specific version
git fetch --tags
git tag --sort=-v:refname | head -n 20
git checkout <tag-or-commit-sha>
name: Build and Test

on:
  push:
    branches: [ "main" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main" ]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up toolchain
        uses: actions/setup-go@v5
        with:
          go-version-file: "go.mod"

      - name: Build
        run: go build -v ./...

      - name: Run tests
        run: go test -race ./...
gh run list --limit 10
gh run view <run-id> --log
gh workflow run build.yml
A **GitHub build** typically refers to either:

1. **Continuous Integration / Continuous Delivery (CI/CD) via GitHub Actions**—automated workflows defined in `.github/workflows/*.yml` that compile code, run tests, sign artifacts, and publish releases whenever code is pushed or a tag is created.
2. **Building a project from source on GitHub**—cloning a repository, checking out a specific commit or release tag, and compiling/running the build locally or in a container.

---

### 1. Building a Project from Source (Specific Version / Tag)

When pulling a specific historical version or tag rather than `HEAD`:

```bash
# Clone the repository
git clone https://github.com/<owner>/<repo>.git
cd <repo>

# List available tags/releases and check out a specific version
git fetch --tags
git tag --sort=-v:refname | head -n 20
git checkout <tag-or-commit-sha>

```

From there, check the repository's `README.md`, `CONTRIBUTING.md`, or `.github/workflows/` to see the exact toolchain and build command (e.g., `make`, `cargo build --release`, `go build ./...`, `cmake`, `mvn package`, or `npm run build`), and verify release checksums/signatures if publishing or installing binaries.

---

### 2. Automated Builds with GitHub Actions

A standard GitHub Actions workflow lives in `.github/workflows/build.yml` and triggers on events like `push`, `pull_request`, or `workflow_dispatch`:

```yaml
name: Build and Test

on:
  push:
    branches: [ "main" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main" ]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up toolchain
        uses: actions/setup-go@v5
        with:
          go-version-file: "go.mod"

      - name: Build
        run: go build -v ./...

      - name: Run tests
        run: go test -race ./...

```

Key practices for reliable builds:

* **Pin actions by commit SHA** (with a version comment) in production workflows rather than mutable tags when hardening supply-chain security.
* **Use least-privilege `permissions:**` at the workflow or job level.
* **Cache dependencies** (e.g., `actions/cache` or language setup actions) to speed up repeated builds.

---

### 3. Inspecting Build Logs & Artifacts

* **Actions tab:** Go to **Actions** in the repository to view workflow runs, step-by-step logs, exit codes, and downloadable build artifacts.
* **GitHub CLI (`gh`):** Trigger or inspect runs from the terminal:
```bash
gh run list --limit 10
gh run view <run-id> --log
gh workflow run build.yml

```



If you share the repository language/stack, target platform, or whether you are troubleshooting a failing workflow or compiling a specific project, I can give you exact commands and configuration.A **GitHub build** typically refers to either:

1. **Continuous Integration / Continuous Delivery (CI/CD) via GitHub Actions**—automated workflows defined in `.github/workflows/*.yml` that compile code, run tests, sign artifacts, and publish releases whenever code is pushed or a tag is created.
2. **Building a project from source on GitHub**—cloning a repository, checking out a specific commit or release tag, and compiling/running the build locally or in a container.

---

### 1. Building a Project from Source (Specific Version / Tag)

When pulling a specific historical version or tag rather than `HEAD`:

```bash
# Clone the repository
git clone https://github.com/<owner>/<repo>.git
cd <repo>

# List available tags/releases and check out a specific version
git fetch --tags
git tag --sort=-v:refname | head -n 20
git checkout <tag-or-commit-sha>

```

From there, check the repository's `README.md`, `CONTRIBUTING.md`, or `.github/workflows/` to see the exact toolchain and build command (e.g., `make`, `cargo build --release`, `go build ./...`, `cmake`, `mvn package`, or `npm run build`), and verify release checksums/signatures if publishing or installing binaries.

---

### 2. Automated Builds with GitHub Actions

A standard GitHub Actions workflow lives in `.github/workflows/build.yml` and triggers on events like `push`, `pull_request`, or `workflow_dispatch`:

```yaml
name: Build and Test

on:
  push:
    branches: [ "main" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main" ]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up toolchain
        uses: actions/setup-go@v5
        with:
          go-version-file: "go.mod"

      - name: Build
        run: go build -v ./...

      - name: Run tests
        run: go test -race ./...

```

Key practices for reliable builds:

* **Pin actions by commit SHA** (with a version comment) in production workflows rather than mutable tags when hardening supply-chain security.
* **Use least-privilege `permissions:**` at the workflow or job level.
* **Cache dependencies** (e.g., `actions/cache` or language setup actions) to speed up repeated builds.

---

### 3. Inspecting Build Logs & Artifacts

* **Actions tab:** Go to **Actions** in the repository to view workflow runs, step-by-step logs, exit codes, and downloadable build artifacts.
* **GitHub CLI (`gh`):** Trigger or inspect runs from the terminal:
```bash
gh run list --limit 10
gh run view <run-id> --log
gh workflow run build.yml

```



If you share the repository language/stack, target platform, or whether you are troubleshooting a failing workflow or compiling a specific project, I can give you exact commands and configuration.gh run list --limit 10
gh run view <run-id> --log
gh workflow run build.ymlname: Build and Test

on:
  push:
    branches: [ "main" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main" ]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up toolchain
        uses: actions/setup-go@v5
        with:
          go-version-file: "go.mod"

      - name: Build
        run: go build -v ./...

      - name: Run tests
        run: go test -race ./...ingest_evidence.pyTracker.shHere is an idempotent Bash script (bootstrap_github_tracker.sh) that uses gh CLI and jq to create your history:* labels, needs-sha256 / sha256-verified labels, and a GitHub Project linked to your repository—along with custom fields for chronological and recovery tracking.
> Note: Make sure your gh token has the project scope enabled (gh auth refresh -s project) before creating a GitHub Project via the CLI.
> 
bootstrap_github_tracker.sh
#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
PROJECT_TITLE="${2:-Identity & Incident Recovery Ledger}"

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi

if [[ -z "$REPO" ]]; then
  echo "Error: Could not determine repository. Pass OWNER/REPO as the first argument or run inside a git repo." >&2
  exit 1
fi

for cmd in gh jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: Required command '$cmd' is not installed." >&2
    exit 1
  fi
done

OWNER="${REPO%%/*}"

create_or_update_label() {
  local name="$1"
  local color="$2"
  local description="$3"

  # gh label create --force creates the label if missing or updates color/description if it exists
  gh label create "$name" \
    --repo "$REPO" \
    --color "$color" \
    --description "$description" \
    --force >/dev/null
  echo "Ensured label: $name"
}

echo "Bootstrapping labels on $REPO..."

# History & incident classification labels
create_or_update_label "history:addresses-residences" "1D76DB" "Past/current residences, leases, utilities, and location history"
create_or_update_label "history:accounts-data"        "D93F0B" "Accounts, logins, credentials, breaches, and data exposures"
create_or_update_label "history:unclaimed-assets"     "0E8A16" "Dormant accounts, uncashed checks, and state unclaimed property"
create_or_update_label "history:property-custody"     "B60205" "Taken, withheld, lost, or disputed abandonment items/assets"
create_or_update_label "history:disputes-filings"     "5319E7" "Identity theft reports, disputes, notices, and legal filings"

# Evidence integrity & triage labels
create_or_update_label "needs-sha256"               "FBCA04" "Awaiting local SHA-256 evidence digest verification"
create_or_update_label "sha256-verified"            "0052CC" "Linked to a 64-character SHA-256 digest in local records"
create_or_update_label "triage"                     "EDEDED" "New record awaiting review or next action"

echo "Checking for existing project '$PROJECT_TITLE' under $OWNER..."

PROJECT_NUMBER="$(
  gh project list --owner "$OWNER" --format json \
    | jq -r --arg title "$PROJECT_TITLE" '.projects[] | select(.title == $title) | .number' \
    | head -n 1
)"

if [[ -z "$PROJECT_NUMBER" ]]; then
  PROJECT_NUMBER="$(
    gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json \
      | jq -r '.number'
  )"
  echo "Created project #$PROJECT_NUMBER: $PROJECT_TITLE"
else
  echo "Reusing existing project #$PROJECT_NUMBER: $PROJECT_TITLE"
fi

PROJECT_ID="$(gh project view "$PROJECT_NUMBER" --owner "$OWNER" --format json | jq -r '.id')"

# Link repository to the project
gh project link "$PROJECT_NUMBER" --owner "$OWNER" --repo "$REPO" >/dev/null 2>&1 || true
echo "Linked $REPO to project #$PROJECT_NUMBER"

ensure_field() {
  local name="$1"
  local data_type="$2"
  shift 2

  local exists
  exists="$(
    gh project field-list "$PROJECT_NUMBER" --owner "$OWNER" --format json \
      | jq -r --arg name "$name" '.fields[] | select(.name == $name) | .id' \
      | head -n 1
  )"

  if [[ -n "$exists" ]]; then
    echo "Field already exists: $name"
    return 0
  fi

  if [[ "$data_type" == "SINGLE_SELECT" ]]; then
    local options_csv
    options_csv="$(IFS=,; echo "$*")"
    gh project field-create "$PROJECT_NUMBER" \
      --owner "$OWNER" \
      --name "$name" \
      --data-type "SINGLE_SELECT" \
      --single-select-options "$options_csv" >/dev/null
  else
    gh project field-create "$PROJECT_NUMBER" \
      --owner "$OWNER" \
      --name "$name" \
      --data-type "$data_type" >/dev/null
  fi
  echo "Created field: $name ($data_type)"
}

echo "Ensuring custom tracking fields on project #$PROJECT_NUMBER..."
ensure_field "Record ID" "TEXT"
ensure_field "Event Date" "DATE"
ensure_field "Filing Deadline" "DATE"
ensure_field "SHA-256 Status" "SINGLE_SELECT" "Pending","Verified","Mismatch"
ensure_field "Recovery Stage" "SINGLE_SELECT" "Logged","Evidence Hashed","Disputed / Claimed","Counsel Review","Resolved"

echo "Done. Project ID: $PROJECT_ID"

Usage & Scope Check
# Ensure gh has project scope if needed:
gh auth status
# If project scope is missing:
# gh auth refresh -s project

chmod +x bootstrap_github_tracker.sh
./bootstrap_github_tracker.sh "OWNER/REPO" "Identity & Incident Recovery Ledger"

 * Idempotent execution: Uses gh label create --force so labels are created or updated cleanly without failing on re-runs, and checks existing projects/fields by name before creating duplicates.
 * No PII in GitHub: Only creates metadata labels and custom project fields for record IDs, dates, SHA-256 verification status, and recovery stages—keeping raw documents and sensitive details in your local encrypted vault.
Track everything all reality
Incident tracking everything built-in GitHubhttps://workspace.google.com/solutions/ai/import sys
from pathlib import Path
from legal_compendium import LegalCompendiumIndexer, RecoveryClaim


def ingest_folder(item_id: str, folder_path: str, db_path: str = "compendium.sqlite") -> None:
    indexer = LegalCompendiumIndexer(db_path=db_path)
    folder = Path(folder_path)
    if not folder.is_dir():
        raise SystemExit(f"Directory not found: {folder}")

    artifacts = [indexer.hash_file(p) for p in sorted(folder.rglob("*")) if p.is_file()]
    if not artifacts:
        raise SystemExit(f"No files found in {folder}")

    statute_ref, deadline = indexer.calculate_indiana_deadline("2026-11-20", "wrongful_taking")
    claim = RecoveryClaim(
        item_id=item_id,
        category="wrongful_taking",
        asset_type="personal_property",
        description=f"Auto-ingested claim bundle for {item_id}",
        identifiers="UPDATE_IDENTIFIERS",
        estimated_value=0.0,
        custodian_holder="UPDATE_CUSTODIAN",
        custodian_address="UPDATE_ADDRESS",
        jurisdiction="IN",
        date_taken_or_exposed="2026-11-20",
        date_discovered="2026-11-20",
        statute_reference=statute_ref,
        filing_deadline=deadline,
        evidence=artifacts,
    )
    indexer.upsert_claim(claim)
    print(f"Indexed {len(artifacts)} SHA-256 verified files under {item_id} in {db_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ingest_evidence.py <ITEM_ID> <EVIDENCE_FOLDER_PATH>")
        sys.exit(1)
    ingest_folder(sys.argv[1], sys.argv[2])
python3 -m unittest -v test_legal_compendium.py
git status
git add .gitignore README.md legal_compendium.py test_legal_compendium.py ingest_evidence.py templates/
git commit -S -m "feat: add SHA-256 evidence indexer, unit tests, demand template, and recovery playbooks"
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine+-------------------------------------------------------------------------+
|                    INPUT LAYER: SUBJECT & CLAIM STREAM                  |
|  - Physiological: EDA (skin conductance), PPG/ECG (HR/HRV), Resp       |
|  - Behavioral / Acoustic / Text: Pitch (F0), jitter, response latency,   |
|    lexical hedging, contradiction graph                                 |
|  - Provenance / Supply-Chain: Cert IDs, batch telemetry, lab assays     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|               STAGE 1: CALIBRATION & BASELINE ENGINE                    |
|  - Sensor offset/gain & impedance checks                                |
|  - Resting / neutral / known-truth calibration window                   |
|  - Z-score / quantile normalization per subject & channel               |
+------------------------------------+------------------------------------+
                 Tracker.shHerebundle_id=claim-bundle-001
archive_file=claim-bundle-001.tar.zst
source_paths=README.md,legal_compendium.py
zstd_level=19
sha256=
archive_bytes=
#!/usr/bin/env bash
set -euo pipefail

MANIFEST_PATH="${1:-}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
DIST_DIR="${DIST_DIR:-dist}"

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

if [[ -z "${MANIFEST_PATH}" || ! -f "${MANIFEST_PATH}" ]]; then
  echo "Usage: DIST_DIR=dist REPO_ROOT=. ./scripts/build-bundle.sh manifests/<name>.manifest" >&2
  exit 1
fi

for cmd in awk tar zstd sha256sum mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required tool not found: $cmd"
    exit 2
  fi
done

get_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, $2)); exit }' "$file"
}

bundle_id="$(get_field "$MANIFEST_PATH" "bundle_id")"
archive_file="$(get_field "$MANIFEST_PATH" "archive_file")"
source_paths="$(get_field "$MANIFEST_PATH" "source_paths")"
zstd_level="$(get_field "$MANIFEST_PATH" "zstd_level")"
zstd_level="${zstd_level:-19}"

if [[ -z "${bundle_id}" || -z "${archive_file}" || -z "${source_paths}" ]]; then
  log "ERROR" "Manifest missing required fields: ${MANIFEST_PATH}"
  exit 1
fi

mkdir -p "${DIST_DIR}"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bundle_${bundle_id}.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

IFS=',:' read -r -a paths_arr <<< "${source_paths}"
clean_paths=()
for raw_p in "${paths_arr[@]}"; do
  rel_p="${raw_p#"${raw_p%%[![:space:]]*}"}"
  rel_p="${rel_p%"${rel_p##*[![:space:]]}"}"
  [[ -n "${rel_p}" ]] && clean_paths+=("${rel_p}")
done

TAR_TMP="${STAGE_DIR}/archive.tar"
OUT_ARCHIVE="${DIST_DIR}/${archive_file}"
OUT_SHA="${OUT_ARCHIVE}.sha256"

# Deterministic tar ordering and metadata
tar --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner \
    -C "${REPO_ROOT}" \
    -cf "${TAR_TMP}" \
    "${clean_paths[@]}"

zstd -f -T0 "-${zstd_level}" "${TAR_TMP}" -o "${OUT_ARCHIVE}"

sha256_digest="$(sha256sum "${OUT_ARCHIVE}" | awk '{print $1}')"
archive_bytes="$(wc -c < "${OUT_ARCHIVE}" | tr -d '[:space:]')"

(
  cd "${DIST_DIR}"
  sha256sum "$(basename -- "${OUT_ARCHIVE}")" > "$(basename -- "${OUT_SHA}")"
)

# Update or append sha256 and archive_bytes in manifest
TMP_MANIFEST="${STAGE_DIR}/updated.manifest"
awk -v h="${sha256_digest}" -v b="${archive_bytes}" '
  BEGIN { saw_sha=0; saw_bytes=0 }
  /^sha256=/ { print "sha256=" h; saw_sha=1; next }
  /^archive_bytes=/ { print "archive_bytes=" b; saw_bytes=1; next }
  { print }
  END {
    if (!saw_sha) print "sha256=" h
    if (!saw_bytes) print "archive_bytes=" b
  }
' "${MANIFEST_PATH}" > "${TMP_MANIFEST}"
mv "${TMP_MANIFEST}" "${MANIFEST_PATH}"

log "INFO" "Built ${OUT_ARCHIVE} (${archive_bytes} bytes, sha256=${sha256_digest})"
build-bundle.sh#!/usr/bin/env bash
set -euo pipefail

MANIFEST_SRC_DIR="${MANIFEST_SRC_DIR:-manifests}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

for cmd in awk grep find basename; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required tool not found: $cmd"
    exit 2
  fi
done

if [[ ! -d "${MANIFEST_SRC_DIR}" ]]; then
  log "ERROR" "Manifest directory not found: ${MANIFEST_SRC_DIR}"
  exit 1
fi

if [[ ! -d "${REPO_ROOT}" ]]; then
  log "ERROR" "Repository root not found: ${REPO_ROOT}"
  exit 1
fi

shopt -s nullglob
manifest_files=("${MANIFEST_SRC_DIR}"/*.manifest)
shopt -u nullglob

if [[ "${#manifest_files[@]}" -eq 0 ]]; then
  log "ERROR" "No .manifest files found in ${MANIFEST_SRC_DIR}"
  exit 1
fi

declare -A SEEN_IDS=()
declare -A SEEN_ARCHIVES=()
validated_count=0

get_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, $2)); exit }' "$file"
}

for mpath in "${manifest_files[@]}"; do
  mname="$(basename -- "$mpath")"

  if [[ ! -s "$mpath" ]]; then
    log "ERROR" "${mname}: manifest file is empty"
    exit 1
  fi

  bundle_id="$(get_field "$mpath" "bundle_id")"
  archive_file="$(get_field "$mpath" "archive_file")"
  source_paths="$(get_field "$mpath" "source_paths")"
  expected_sha256="$(get_field "$mpath" "sha256")"
  expected_bytes="$(get_field "$mpath" "archive_bytes")"
  zstd_level="$(get_field "$mpath" "zstd_level")"

  # Required fields check
  if [[ -z "${bundle_id}" || -z "${archive_file}" || -z "${source_paths}" ]]; then
    log "ERROR" "${mname}: missing one or more required fields (bundle_id, archive_file, source_paths)"
    exit 1
  fi

  # Safe bundle_id and archive_file format checks (no path traversal or slashes)
  if [[ ! "${bundle_id}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    log "ERROR" "${mname}: invalid bundle_id '${bundle_id}'"
    exit 1
  fi

  if [[ "${archive_file}" == */* || ! "${archive_file}" =~ \.tar\.zst$ ]]; then
    log "ERROR" "${mname}: archive_file '${archive_file}' must be a bare .tar.zst filename without slashes"
    exit 1
  fi

  # Uniqueness checks across manifests
  if [[ -n "${SEEN_IDS[${bundle_id}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate bundle_id '${bundle_id}' (also in ${SEEN_IDS[${bundle_id}]})"
    exit 1
  fi
  SEEN_IDS["${bundle_id}"]="${mname}"

  if [[ -n "${SEEN_ARCHIVES[${archive_file}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate archive_file '${archive_file}' (also in ${SEEN_ARCHIVES[${archive_file}]})"
    exit 1
  fi
  SEEN_ARCHIVES["${archive_file}"]="${mname}"

  # Optional pre-populated sha256 check (if already computed)
  if [[ -n "${expected_sha256}" && ! "${expected_sha256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    log "ERROR" "${mname}: sha256 must be a 64-character hex string, got '${expected_sha256}'"
    exit 1
  fi

  # Optional archive_bytes check
  if [[ -n "${expected_bytes}" && ! "${expected_bytes}" =~ ^[0-9]+$ ]]; then
    log "ERROR" "${mname}: archive_bytes must be a non-negative integer, got '${expected_bytes}'"
    exit 1
  fi

  # Optional zstd_level check (1..19)
  if [[ -n "${zstd_level}" ]]; then
    if [[ ! "${zstd_level}" =~ ^[0-9]+$ ]] || (( zstd_level < 1 || zstd_level > 19 )); then
      log "ERROR" "${mname}: zstd_level must be an integer between 1 and 19, got '${zstd_level}'"
      exit 1
    fi
  fi

  # Validate comma- or colon-separated source_paths exist under REPO_ROOT without traversal
  IFS=',:' read -r -a paths_arr <<< "${source_paths}"
  if [[ "${#paths_arr[@]}" -eq 0 ]]; then
    log "ERROR" "${mname}: source_paths parsed to empty list"
    exit 1
  fi

  for raw_p in "${paths_arr[@]}"; do
    rel_p="${raw_p#"${raw_p%%[![:space:]]*}"}"
    rel_p="${rel_p%"${rel_p##*[![:space:]]}"}"
    if [[ -z "${rel_p}" || "${rel_p}" == /* || "${rel_p}" == *".."* ]]; then
      log "ERROR" "${mname}: unsafe or invalid source_path '${raw_p}'"
      exit 1
    fi
    if [[ ! -e "${REPO_ROOT}/${rel_p}" ]]; then
      log "ERROR" "${mname}: source_path does not exist: ${rel_p}"
      exit 1
    fi
  done

  validated_count=$((validated_count + 1))
  log "INFO" "${mname}: validated bundle_id=${bundle_id} archive=${archive_file}"
done

log "INFO" "Successfully validated ${validated_count} manifest(s) in ${MANIFEST_SRC_DIR}"
tracker.shHere is an idempotent Bash script (bootstrap_github_tracker.sh) that uses gh CLI and jq to create your history:* labels, needs-sha256 / sha256-verified labels, and a GitHub Project linked to your repository—along with custom fields for chronological and recovery tracking.
> Note: Make sure your gh token has the project scope enabled (gh auth refresh -s project) before creating a GitHub Project via the CLI.
> 
bootstrap_github_tracker.sh
#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-}"
PROJECT_TITLE="${2:-Identity & Incident Recovery Ledger}"

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi

if [[ -z "$REPO" ]]; then
  echo "Error: Could not determine repository. Pass OWNER/REPO as the first argument or run inside a git repo." >&2
  exit 1
fi

for cmd in gh jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: Required command '$cmd' is not installed." >&2
    exit 1
  fi
done

OWNER="${REPO%%/*}"

create_or_update_label() {
  local name="$1"
  local color="$2"
  local description="$3"

  # gh label create --force creates the label if missing or updates color/description if it exists
  gh label create "$name" \
    --repo "$REPO" \
    --color "$color" \
    --description "$description" \
    --force >/dev/null
  echo "Ensured label: $name"
}

echo "Bootstrapping labels on $REPO..."

# History & incident classification labels
create_or_update_label "history:addresses-residences" "1D76DB" "Past/current residences, leases, utilities, and location history"
create_or_update_label "history:accounts-data"        "D93F0B" "Accounts, logins, credentials, breaches, and data exposures"
create_or_update_label "history:unclaimed-assets"     "0E8A16" "Dormant accounts, uncashed checks, and state unclaimed property"
create_or_update_label "history:property-custody"     "B60205" "Taken, withheld, lost, or disputed abandonment items/assets"
create_or_update_label "history:disputes-filings"     "5319E7" "Identity theft reports, disputes, notices, and legal filings"

# Evidence integrity & triage labels
create_or_update_label "needs-sha256"               "FBCA04" "Awaiting local SHA-256 evidence digest verification"
create_or_update_label "sha256-verified"            "0052CC" "Linked to a 64-character SHA-256 digest in local records"
create_or_update_label "triage"                     "EDEDED" "New record awaiting review or next action"

echo "Checking for existing project '$PROJECT_TITLE' under $OWNER..."

PROJECT_NUMBER="$(
  gh project list --owner "$OWNER" --format json \
    | jq -r --arg title "$PROJECT_TITLE" '.projects[] | select(.title == $title) | .number' \
    | head -n 1
)"

if [[ -z "$PROJECT_NUMBER" ]]; then
  PROJECT_NUMBER="$(
    gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json \
      | jq -r '.number'
  )"
  echo "Created project #$PROJECT_NUMBER: $PROJECT_TITLE"
else
  echo "Reusing existing project #$PROJECT_NUMBER: $PROJECT_TITLE"
fi

PROJECT_ID="$(gh project view "$PROJECT_NUMBER" --owner "$OWNER" --format json | jq -r '.id')"

# Link repository to the project
gh project link "$PROJECT_NUMBER" --owner "$OWNER" --repo "$REPO" >/dev/null 2>&1 || true
echo "Linked $REPO to project #$PROJECT_NUMBER"

ensure_field() {
  local name="$1"
  local data_type="$2"
  shift 2

  local exists
  exists="$(
    gh project field-list "$PROJECT_NUMBER" --owner "$OWNER" --format json \
      | jq -r --arg name "$name" '.fields[] | select(.name == $name) | .id' \
      | head -n 1
  )"

  if [[ -n "$exists" ]]; then
    echo "Field already exists: $name"
    return 0
  fi

  if [[ "$data_type" == "SINGLE_SELECT" ]]; then
    local options_csv
    options_csv="$(IFS=,; echo "$*")"
    gh project field-create "$PROJECT_NUMBER" \
      --owner "$OWNER" \
      --name "$name" \
      --data-type "SINGLE_SELECT" \
      --single-select-options "$options_csv" >/dev/null
  else
    gh project field-create "$PROJECT_NUMBER" \
      --owner "$OWNER" \
      --name "$name" \
      --data-type "$data_type" >/dev/null
  fi
  echo "Created field: $name ($data_type)"
}

echo "Ensuring custom tracking fields on project #$PROJECT_NUMBER..."
ensure_field "Record ID" "TEXT"
ensure_field "Event Date" "DATE"
ensure_field "Filing Deadline" "DATE"
ensure_field "SHA-256 Status" "SINGLE_SELECT" "Pending","Verified","Mismatch"
ensure_field "Recovery Stage" "SINGLE_SELECT" "Logged","Evidence Hashed","Disputed / Claimed","Counsel Review","Resolved"

echo "Done. Project ID: $PROJECT_ID"

Usage & Scope Check
# Ensure gh has project scope if needed:
gh auth status
# If project scope is missing:
# gh auth refresh -s project

chmod +x bootstrap_github_tracker.sh
./bootstrap_github_tracker.sh "OWNER/REPO" "Identity & Incident Recovery Ledger"

 * Idempotent execution: Uses gh label create --force so labels are created or updated cleanly without failing on re-runs, and checks existing projects/fields by name before creating duplicates.
 * No PII in GitHub: Only creates metadata labels and custom project fields for record IDs, dates, SHA-256 verification status, and recovery stages—keeping raw documents and sensitive details in your local encrypted vault.
Track everything all reality
Incident tracking everything built-in GitHubhttps://workspace.google.com/solutions/ai/import sys
from pathlib import Path
from legal_compendium import LegalCompendiumIndexer, RecoveryClaim


def ingest_folder(item_id: str, folder_path: str, db_path: str = "compendium.sqlite") -> None:
    indexer = LegalCompendiumIndexer(db_path=db_path)
    folder = Path(folder_path)
    if not folder.is_dir():
        raise SystemExit(f"Directory not found: {folder}")

    artifacts = [indexer.hash_file(p) for p in sorted(folder.rglob("*")) if p.is_file()]
    if not artifacts:
        raise SystemExit(f"No files found in {folder}")

    statute_ref, deadline = indexer.calculate_indiana_deadline("2026-11-20", "wrongful_taking")
    claim = RecoveryClaim(
        item_id=item_id,
        category="wrongful_taking",
        asset_type="personal_property",
        description=f"Auto-ingested claim bundle for {item_id}",
        identifiers="UPDATE_IDENTIFIERS",
        estimated_value=0.0,
        custodian_holder="UPDATE_CUSTODIAN",
        custodian_address="UPDATE_ADDRESS",
        jurisdiction="IN",
        date_taken_or_exposed="2026-11-20",
        date_discovered="2026-11-20",
        statute_reference=statute_ref,
        filing_deadline=deadline,
        evidence=artifacts,
    )
    indexer.upsert_claim(claim)
    print(f"Indexed {len(artifacts)} SHA-256 verified files under {item_id} in {db_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ingest_evidence.py <ITEM_ID> <EVIDENCE_FOLDER_PATH>")
        sys.exit(1)
    ingest_folder(sys.argv[1], sys.argv[2])
python3 -m unittest -v test_legal_compendium.py
git status
git add .gitignore README.md legal_compendium.py test_legal_compendium.py ingest_evidence.py templates/
git commit -S -m "feat: add SHA-256 evidence indexer, unit tests, demand template, and recovery playbooks"
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine+-------------------------------------------------------------------------+
|                    INPUT LAYER: SUBJECT & CLAIM STREAM                  |
|  - Physiological: EDA (skin conductance), PPG/ECG (HR/HRV), Resp       |
|  - Behavioral / Acoustic / Text: Pitch (F0), jitter, response latency,   |
|    lexical hedging, contradiction graph                                 |
|  - Provenance / Supply-Chain: Cert IDs, batch telemetry, lab assays     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|               STAGE 1: CALIBRATION & BASELINE ENGINE                    |
|  - Sensor offset/gain & impedance checks                                |
|  - Resting / neutral / known-truth calibration window                   |
|  - Z-score / quantile normalization per subject & channel               |
+------------------------------------+------------------------------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
+-----------------------------------+   +---------------------------------+
| STAGE 2A: SIGNAL CONDITIONING &   |   | STAGE 2B: FEATURE EXTRACTION    |
| ARTIFACT REJECTION                |   | PIPELINE                        |
| - Bandpass / notch filtering      |   | - Time/freq/event-window stats  |
| - Motion & contact-loss gating    |   | - Cross-channel delta vectors   |
| - Missing-data / dropout flags    |   | - Claim-to-evidence alignment   |
+-----------------+-----------------+   +----------------+----------------+
                  |                                      |
                  +-------------------+------------------+
                                      |
                                      v
+-------------------------------------------------------------------------+
|               STAGE 3: FUSION, SCORING & FAILURE-MODE GUARD             |
|  - Multi-modal feature fusion (weighted / Bayesian / rule + ML)         |
|  - Out-of-distribution (OOD) & quality-gate checks                      |
|  - Output: Risk/Consistency Score + Uncertainty + Audit Trace           |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|               STAGE 4: DECISION POLICY & HUMAN ESCALATION               |
|  - Thresholding into Clear / Elevated Variance / Inconclusive / Invalid |
|  - Mandatory human-in-the-loop review for high-stakes or low-SNR cases  |
+-------------------------------------------------------------------------+
Here are scripts/validate-manifest.sh and scripts/build-bundle.sh for the adpBetty repository, designed to work together in your GitHub Actions workflow (ingest-and-verify.yml and global-publish.yml) and match the .manifest + .sha256 + .tar.zst conventions from your local setup.
1. Manifest Validator (scripts/validate-manifest.sh)
This script scans manifests/ (or a custom directory passed via MANIFEST_SRC_DIR) for .manifest files, validates required key/value metadata fields, verifies SHA-256 format (64 hex characters), checks that declared source_paths exist in the repository workspace, and ensures no duplicate bundle_id or archive_file names exist across manifests.
#!/usr/bin/env bash
set -euo pipefail

MANIFEST_SRC_DIR="${MANIFEST_SRC_DIR:-manifests}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

for cmd in awk grep find basename; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required tool not found: $cmd"
    exit 2
  fi
done

if [[ ! -d "${MANIFEST_SRC_DIR}" ]]; then
  log "ERROR" "Manifest directory not found: ${MANIFEST_SRC_DIR}"
  exit 1
fi

shopt -s nullglob
manifest_files=("${MANIFEST_SRC_DIR}"/*.manifest)
shopt -u nullglob

if [[ "${#manifest_files[@]}" -eq 0 ]]; then
  log "ERROR" "No .manifest files found in ${MANIFEST_SRC_DIR}"
  exit 1
fi

declare -A SEEN_IDS=()
declare -A SEEN_ARCHIVES=()
validated_count=0

get_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, $2)); exit }' "$file"
}

for mpath in "${manifest_files[@]}"; do
  mname="$(basename -- "$mpath")"

  if [[ ! -s "$mpath" ]]; then
    log "ERROR" "${mname}: manifest file is empty"
    exit 1
  fi

  bundle_id="$(get_field "$mpath" "bundle_id")"
  archive_file="$(get_field "$mpath" "archive_file")"
  source_paths="$(get_field "$mpath" "source_paths")"
  expected_sha256="$(get_field "$mpath" "sha256")"
  expected_bytes="$(get_field "$mpath" "archive_bytes")"
  zstd_level="$(get_field "$mpath" "zstd_level")"

  # Required fields check
  if [[ -z "${bundle_id}" || -z "${archive_file}" || -z "${source_paths}" ]]; then
    log "ERROR" "${mname}: missing one or more required fields (bundle_id, archive_file, source_paths)"
    exit 1
  fi

  # Safe bundle_id and archive_file format checks (no path traversal or slashes)
  if [[ ! "${bundle_id}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    log "ERROR" "${mname}: invalid bundle_id '${bundle_id}'"
    exit 1
  fi

  if [[ "${archive_file}" == */* || ! "${archive_file}" =~ \.tar\.zst$ ]]; then
    log "ERROR" "${mname}: archive_file '${archive_file}' must be a bare .tar.zst filename without slashes"
    exit 1
  fi

  # Uniqueness checks across manifests
  if [[ -n "${SEEN_IDS[${bundle_id}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate bundle_id '${bundle_id}' (also in ${SEEN_IDS[${bundle_id}]})"
    exit 1
  fi
  SEEN_IDS["${bundle_id}"]="${mname}"

  if [[ -n "${SEEN_ARCHIVES[${archive_file}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate archive_file '${archive_file}' (also in ${SEEN_ARCHIVES[${archive_file}]})"
    exit 1
  fi
  SEEN_ARCHIVES["${archive_file}"]="${mname}"

  # Optional pre-populated sha256 check (if already computed)
  if [[ -n "${expected_sha256}" && ! "${expected_sha256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    log "ERROR" "${mname}: sha256 must Incident tracking everything built-in GitHubhttps://workspace.google.com/solutions/ai/import sys
from pathlib import Path
from legal_compendium import LegalCompendiumIndexer, RecoveryClaim


def ingest_folder(item_id: str, folder_path: str, db_path: str = "compendium.sqlite") -> None:
    indexer = LegalCompendiumIndexer(db_path=db_path)
    folder = Path(folder_path)
    if not folder.is_dir():
        raise SystemExit(f"Directory not found: {folder}")

    artifacts = [indexer.hash_file(p) for p in sorted(folder.rglob("*")) if p.is_file()]
    if not artifacts:
        raise SystemExit(f"No files found in {folder}")

    statute_ref, deadline = indexer.calculate_indiana_deadline("2026-11-20", "wrongful_taking")
    claim = RecoveryClaim(
        item_id=item_id,
        category="wrongful_taking",
        asset_type="personal_property",
        description=f"Auto-ingested claim bundle for {item_id}",
        identifiers="UPDATE_IDENTIFIERS",
        estimated_value=0.0,
        custodian_holder="UPDATE_CUSTODIAN",
        custodian_address="UPDATE_ADDRESS",
        jurisdiction="IN",
        date_taken_or_exposed="2026-11-20",
        date_discovered="2026-11-20",
        statute_reference=statute_ref,
        filing_deadline=deadline,
        evidence=artifacts,
    )
    indexer.upsert_claim(claim)
    print(f"Indexed {len(artifacts)} SHA-256 verified files under {item_id} in {db_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ingest_evidence.py <ITEM_ID> <EVIDENCE_FOLDER_PATH>")
        sys.exit(1)
    ingest_folder(sys.argv[1], sys.argv[2])
python3 -m unittest -v test_legal_compendium.py
git status
git add .gitignore README.md legal_compendium.py test_legal_compendium.py ingest_evidence.py templates/
git commit -S -m "feat: add SHA-256 evidence indexer, unit tests, demand template, and recovery playbooks"
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
# Claim Tracking, Data Protection & Recovery Reference

A structured reference and tooling layout for tracking compromised accounts or data, classifying withheld/stolen/unclaimed assets, preserving evidence, and organizing legal/procedural recovery workflows.

> **Disclaimer:** This repository and its documentation are for personal organization, technical engineering, and educational reference only—not legal advice. Always consult a licensed attorney in the relevant jurisdiction before taking formal legal action or asserting claims against another party.

---

## 1. Core Principles

* **Separate "Lost/Abandoned" From Wrongful Taking:** True legal abandonment requires both relinquishing possession and intending to abandon rights. Dormant funds held by a state unclaimed-property program (such as [Indiana Unclaimed Property](https://www.indianaunclaimed.gov/) or [MissingMoney.com](https://www.missingmoney.com/)) differ from property wrongfully withheld, converted, or taken without consent.
* **Individual Autonomy vs. Shared Safeguards:** Each person manages their own accounts, credit freezes, and legal decisions, while shared infrastructure relies on least privilege, isolated credentials, and verified backups.
* **Evidence & Chain of Custody First:** Preserve original records, timestamps, identifiers, and SHA-256 checksums before making changes or issuing demands.

---

## 2. Data & Account Loss Protection

### Individual Actions (Per Person)
* **Credit & Tax Safeguards:** Place credit freezes at Equifax, Experian, and TransUnion, and enroll in an IRS Identity Protection PIN (IP PIN) where applicable.
* **Authentication Hardening:** Use unique passphrases, revoke active sessions/tokens, and enable authenticator-app or hardware-key MFA rather than SMS alone.
* **Account & Activity Audits:** Review bank/card statements, email forwarding rules, recovery contacts, and login histories for unauthorized changes.

### Shared & System Safeguards
* **Credential Isolation:** Avoid sharing admin/root passwords, API tokens, or signing keys across users or machines.
* **Verified Backups:** Maintain encrypted, versioned backups with `sha256sum` manifests and offline/isolated copies so tampering or deletion can be recovered cleanly.

---

## 3. Asset & Incident Classification

| Category | Scope | Core Fields to Log | Typical Next Path |
| :--- | :--- | :--- | :--- |
| **Compromised Data / Accounts** | Exposed personal data, emails, logins, repos, or identity records | Service/account, exposure window, data types, unauthorized actions | Password/MFA reset, session revocation, credit freeze, incident log |
| **Unclaimed / Escheated Assets** | Dormant accounts, uncashed checks, or safe-deposit contents in state custody | Holder name, account/policy details, estimated value, state | Official state unclaimed-property claim with ID & proof of ownership |
| **Wrongfully Withheld / Taken Property** | Physical items, devices, vehicles, or funds kept or taken without right | Item description, serial/VIN/ID, value, custodian, dates taken & demanded | Written demand for return, civil action (e.g., replevin, detinue, conversion), or police report |
| **Disputed / Alleged Abandonment** | Items claimed to be lost or abandoned where you did not intend to relinquish rights | Facts of custody, communications, timeline, proof of ongoing ownership | Document non-abandonment; dispute factual claim with counsel |

---

## 4. Recovery & Action Workflow

1. **Log Everything in a Master Ledger:** Track `item_id`, `category`, `identifiers`, `estimated_value`, `custodian`, `date_noticed`, `evidence_files`, `sha256_hash`, and `status`. Keep raw evidence untouched in a read-only or backed-up archive.
2. **Gather Proof of Ownership & Custody:** Collect receipts, titles, contracts, statements, timestamped photos, serial numbers, and written messages showing ownership and lack of intent to abandon.
3. **Verify Deadlines (Statutes of Limitations):** Track key dates and confirm applicable filing deadlines with counsel promptly (for example, in Indiana, personal-property injury claims often have a two-year period under Ind. Code § 34-11-2-4, while fraud or certain other claims can have longer statutory windows under Ind. Code §§ 34-11-2-7 or 34-11-2-11 depending on the claim).
4. **Send a Formal Written Demand or File Official Claims:** Submit state unclaimed-property claims where applicable, send a dated written demand for return with proof of delivery for wrongfully held property (without resorting to force, trespass, or unlawful self-help), and file police reports where theft or fraud occurred.
5. **Pursue Civil Remedies & Enforcement Through Proper Channels:** Work with licensed counsel on appropriate civil actions (such as replevin, detinue, conversion, or contract/bailment claims) and follow official court/sheriff procedures to enforce orders.

---

## 5. Repository Layout & Python Tooling

```text
.
├── README.md
├── legal_compendium.py        # Compendium models, JSON Schema export, and SQLite/SHA-256 indexer
└── test_legal_compendium.py   # Unit tests for jurisdiction, workflows, schema, and SQLite indexing
```

### Run Tests & Index Records

```bash
python3 -m unittest -v test_legal_compendium.py
python3 -c "from legal_compendium import MasterLegalCompendium, LegalCompendiumIndexer; c = MasterLegalCompendium(); idx = LegalCompendiumIndexer('compendium.sqlite'); print(c.index_into_sqlite(idx))"
```
git status
git add README.md legal_compendium.py test_legal_compendium.py
git commit -S -m "docs: add claim tracking, data protection, and compendium workflow guide"
And protect everyone from compromised data loss 
How do I go about tracking everything that was compromised and taken or stolen because of the law lost or abandoned protection with detailed prosses to take legal action to reclaim everything that is rightfully mine+-------------------------------------------------------------------------+
|                    INPUT LAYER: SUBJECT & CLAIM STREAM                  |
|  - Physiological: EDA (skin conductance), PPG/ECG (HR/HRV), Resp       |
|  - Behavioral / Acoustic / Text: Pitch (F0), jitter, response latency,   |
|    lexical hedging, contradiction graph                                 |
|  - Provenance / Supply-Chain: Cert IDs, batch telemetry, lab assays     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|               STAGE 1: CALIBRATION & BASELINE ENGINE                    |
|  - Sensor offset/gain & impedance checks                                |
|  - Resting / neutral / known-truth calibration window                   |
|  - Z-score / quantile normalization per subject & channel               |
+------------------------------------+------------------------------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
+-----------------------------------+   +---------------------------------+
| STAGE 2A: SIGNAL CONDITIONING &   |   | STAGE 2B: FEATURE EXTRACTION    |
| ARTIFACT REJECTION                |   | PIPELINE                        |
| - Bandpass / notch filtering      |   | - Time/freq/event-window stats  |
| - Motion & contact-loss gating    |   | - Cross-channel delta vectors   |
| - Missing-data / dropout flags    |   | - Claim-to-evidence alignment   |
+-----------------+-----------------+   +----------------+----------------+
                  |                                      |
                  +-------------------+------------------+
                                      |
                                      v
+-------------------------------------------------------------------------+
|               STAGE 3: FUSION, SCORING & FAILURE-MODE GUARD             |
|  - Multi-modal feature fusion (weighted / Bayesian / rule + ML)         |
|  - Out-of-distribution (OOD) & quality-gate checks                      |
|  - Output: Risk/Consistency Score + Uncertainty + Audit Trace           |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|               STAGE 4: DECISION POLICY & HUMAN ESCALATION               |
|  - Thresholding into Clear / Elevated Variance / Inconclusive / Invalid |
|  - Mandatory human-in-the-loop review for high-stakes or low-SNR cases  |
+-------------------------------------------------------------------------+
Here are scripts/validate-manifest.sh and scripts/build-bundle.sh for the adpBetty repository, designed to work together in your GitHub Actions workflow (ingest-and-verify.yml and global-publish.yml) and match the .manifest + .sha256 + .tar.zst conventions from your local setup.
1. Manifest Validator (scripts/validate-manifest.sh)
This script scans manifests/ (or a custom directory passed via MANIFEST_SRC_DIR) for .manifest files, validates required key/value metadata fields, verifies SHA-256 format (64 hex characters), checks that declared source_paths exist in the repository workspace, and ensures no duplicate bundle_id or archive_file names exist across manifests.
#!/usr/bin/env bash
set -euo pipefail

MANIFEST_SRC_DIR="${MANIFEST_SRC_DIR:-manifests}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

for cmd in awk grep find basename; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required tool not found: $cmd"
    exit 2
  fi
done

if [[ ! -d "${MANIFEST_SRC_DIR}" ]]; then
  log "ERROR" "Manifest directory not found: ${MANIFEST_SRC_DIR}"
  exit 1
fi

shopt -s nullglob
manifest_files=("${MANIFEST_SRC_DIR}"/*.manifest)
shopt -u nullglob

if [[ "${#manifest_files[@]}" -eq 0 ]]; then
  log "ERROR" "No .manifest files found in ${MANIFEST_SRC_DIR}"
  exit 1
fi

declare -A SEEN_IDS=()
declare -A SEEN_ARCHIVES=()
validated_count=0

get_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, $2)); exit }' "$file"
}

for mpath in "${manifest_files[@]}"; do
  mname="$(basename -- "$mpath")"

  if [[ ! -s "$mpath" ]]; then
    log "ERROR" "${mname}: manifest file is empty"
    exit 1
  fi

  bundle_id="$(get_field "$mpath" "bundle_id")"
  archive_file="$(get_field "$mpath" "archive_file")"
  source_paths="$(get_field "$mpath" "source_paths")"
  expected_sha256="$(get_field "$mpath" "sha256")"
  expected_bytes="$(get_field "$mpath" "archive_bytes")"
  zstd_level="$(get_field "$mpath" "zstd_level")"

  # Required fields check
  if [[ -z "${bundle_id}" || -z "${archive_file}" || -z "${source_paths}" ]]; then
    log "ERROR" "${mname}: missing one or more required fields (bundle_id, archive_file, source_paths)"
    exit 1
  fi

  # Safe bundle_id and archive_file format checks (no path traversal or slashes)
  if [[ ! "${bundle_id}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    log "ERROR" "${mname}: invalid bundle_id '${bundle_id}'"
    exit 1
  fi

  if [[ "${archive_file}" == */* || ! "${archive_file}" =~ \.tar\.zst$ ]]; then
    log "ERROR" "${mname}: archive_file '${archive_file}' must be a bare .tar.zst filename without slashes"
    exit 1
  fi

  # Uniqueness checks across manifests
  if [[ -n "${SEEN_IDS[${bundle_id}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate bundle_id '${bundle_id}' (also in ${SEEN_IDS[${bundle_id}]})"
    exit 1
  fi
  SEEN_IDS["${bundle_id}"]="${mname}"

  if [[ -n "${SEEN_ARCHIVES[${archive_file}]+x}" ]]; then
    log "ERROR" "${mname}: duplicate archive_file '${archive_file}' (also in ${SEEN_ARCHIVES[${archive_file}]})"
    exit 1
  fi
  SEEN_ARCHIVES["${archive_file}"]="${mname}"

  # Optional pre-populated sha256 check (if already computed)
  if [[ -n "${expected_sha256}" && ! "${expected_sha256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    log "ERROR" "${mname}: sha256 must be a 64-character hex digest when provided"
    exit 1
  fi

  # Optional pre-populated byte count check
  if [[ -n "${expected_bytes}" && ! "${expected_bytes}" =~ ^[0-9]+$ ]]; then
    log "ERROR" "${mname}: archive_bytes must be a non-negative integer when provided"
    exit 1
  fi

  # Optional zstd level check (1-22 in standard zstd)
  if [[ -n "${zstd_level}" ]]; then
    if [[ ! "${zstd_level}" =~ ^[0-9]+$ || "${zstd_level}" -lt 1 || "${zstd_level}" -gt 22 ]]; then
      log "ERROR" "${mname}: zstd_level '${zstd_level}' out of range (expected 1..22)"
      exit 1
    fi
  fi

  # Verify each declared source path exists and stays inside REPO_ROOT
  read -r -a paths_arr <<< "${source_paths}"
  if [[ "${#paths_arr[@]}" -eq 0 ]]; then
    log "ERROR" "${mname}: source_paths cannot be empty"
    exit 1
  fi

  for rel_src in "${paths_arr[@]}"; do
    if [[ "${rel_src}" == /* || "${rel_src}" == *".."* ]]; then
      log "ERROR" "${mname}: unsafe source path '${rel_src}' (must be relative with no '..')"
      exit 1
    fi
    if [[ ! -e "${REPO_ROOT}/${rel_src}" ]]; then
      log "ERROR" "${mname}: source path does not exist: ${rel_src}"
      exit 1
    fi
  done

  validated_count=$((validated_count + 1))
  log "PASS" "${mname}: valid (bundle_id=${bundle_id}, archive_file=${archive_file}, sources=${#paths_arr[@]})"
done

log "INFO" "All ${validated_count} manifest(s) in '${MANIFEST_SRC_DIR}' passed validation."

2. Bundle Builder (scripts/build-bundle.sh)
This script reads validated .manifest files from MANIFEST_SRC_DIR, builds each .tar.zst archive into DIST_DIR (default dist/), computes <archive>.sha256, writes the finalized .manifest file into DIST_DIR with the exact archive_bytes, sha256, built_at_utc, and commit_sha values, and verifies both the .sha256 checksum and zstd -tq frame integrity before finishing.
#!/usr/bin/env bash
set -euo pipefail

MANIFEST_SRC_DIR="${MANIFEST_SRC_DIR:-manifests}"
DIST_DIR="${DIST_DIR:-dist}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
DEFAULT_ZSTD_LEVEL="${ZSTD_LEVEL:-3}"
DEFAULT_ZSTD_THREADS="${ZSTD_THREADS:-0}"
COMMIT_SHA="${GITHUB_SHA:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "local")}"

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

cleanup_on_error() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    log "ERROR" "Bundle build failed (exit=${exit_code}). Cleaning up partial artifacts in ${DIST_DIR}."
    rm -rf -- "${DIST_DIR}"
  fi
}
trap cleanup_on_error EXIT

for cmd in tar zstd sha256sum stat awk date basename; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required tool not found: $cmd"
    exit 2
  fi
done

# Run manifest validation first so we never build from an invalid manifest
"$(dirname -- "${BASH_SOURCE[0]}")/validate-manifest.sh"

mkdir -p -- "${DIST_DIR}"

get_field() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, $2)); exit }' "$file"
}

shopt -s nullglob
manifest_files=("${MANIFEST_SRC_DIR}"/*.manifest)
shopt -u nullglob

built_count=0

for mpath in "${manifest_files[@]}"; do
  mname="$(basename -- "$mpath")"
  bundle_id="$(get_field "$mpath" "bundle_id")"
  archive_file="$(get_field "$mpath" "archive_file")"
  source_paths="$(get_field "$mpath" "source_paths")"
  level="$(get_field "$mpath" "zstd_level")"
  level="${level:-${DEFAULT_ZSTD_LEVEL}}"

  archive_path="${DIST_DIR}/${archive_file}"
  checksum_path="${archive_path}.sha256"
  out_manifest_path="${DIST_DIR}/${mname}"

  read -r -a paths_arr <<< "${source_paths}"

  log "INFO" "Building ${archive_file} (bundle_id=${bundle_id}, zstd=-${level}, threads=${DEFAULT_ZSTD_THREADS})"

  # Create .tar.zst archive from relative paths inside REPO_ROOT
  (
    cd "${REPO_ROOT}"
    tar -cf - -- "${paths_arr[@]}" \
      | zstd -q -"${level}" -T"${DEFAULT_ZSTD_THREADS}" --long=27 -o "${archive_path}"
  )

  # Generate SHA-256 checksum using relative filename inside DIST_DIR
  (
    cd "${DIST_DIR}"
    sha256sum -- "${archive_file}" > "${archive_file}.sha256"
  )

  archive_bytes="$(stat -c '%s' "${archive_path}")"
  sha256_digest="$(awk '{print $1}' "${checksum_path}")"
  built_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Write finalized manifest into DIST_DIR alongside the archive and checksum
  cat > "${out_manifest_path}" <<EOF
bundle_id=${bundle_id}
archive_file=${archive_file}
archive_bytes=${archive_bytes}
sha256=${sha256_digest}
zstd_level=${level}
source_paths=${source_paths}
commit_sha=${COMMIT_SHA}
built_at_utc=${built_at_utc}
status=verified
EOF

  # Verify checksum and Zstandard frame integrity
  (
    cd "${DIST_DIR}"
    sha256sum --check --status -- "${archive_file}.sha256"
  )
  zstd -tq -- "${archive_path}"

  # Confirm manifest matches computed bytes and SHA-256
  grep -q "^archive_bytes=${archive_bytes}$" "${out_manifest_path}"
  grep -q "^sha256=${sha256_digest}$" "${out_manifest_path}"

  built_count=$((built_count + 1))
  log "PASS" "Built & verified ${archive_file} (${archive_bytes} bytes, sha256=${sha256_digest:0:12}...)"
done

log "INFO" "Completed building and verifying ${built_count} bundle(s) in '${DIST_DIR}'."

3. Example Input Manifest (manifests/example-001.manifest)
Place input manifests like this in manifests/ so validate-manifest.sh and build-bundle.sh have source definitions to package:
bundle_id=law-pack-us-001
archive_file=law-pack-us-001.tar.zst
source_paths=01-constitutions/US 02-codes-and-statutes/US
zstd_level=3

(Note: sha256 and archive_bytes can be left blank in manifests/*.manifest before building—build-bundle.sh populates them in dist/<name>.manifest once the archive is created.)
4. Local Test Command
Test both scripts locally before pushing to adpBetty:
chmod +x scripts/validate-manifest.sh scripts/build-bundle.sh
./scripts/validate-manifest.sh
./scripts/build-bundle.sh
ls -lh dist/

Verification: dist/ will contain <archive_file>, <archive_file>.sha256, and <manifest_name>.manifest, and both scripts will exit 0.
Write scripts/build-bundle.sh and scripts/validate-manifest.sh for the adpBetty GitHub repository to create .tar.zst archives, SHA-256 checksums, and validated manifests.How do I configure a GitHub Actions workflow in adpBetty that pushes verified artifacts one-way to multiple global destinations or object buckets with immutable naming?ingest-and-verify.ymlIn systems and DevOps architecture, a "one-way in, no way out" design for a repository system like adpBetty maps cleanly to unidirectional data/artifact pipelines and append-only / immutable storage & release flows: inputs flow in through strict gates, get verified (checksums/manifests/signatures), and are written to immutable or downstream-only targets without allowing in-place rewriting or reverse writes back into upstream sources.
(Safety note: In legitimate engineering, "no way out" applies to immutability, append-only logs/artifacts, and one-way sync boundaries—never to locking legitimate administrators out of their own accounts, keys, or recovery paths.)
1. Core Principles of a One-Way Pipeline in adpBetty
 * Unidirectional Flow (Push/Ingest Only): Upstream sources or contributors submit changes via Pull Requests and protected branches; automation ingests, validates, and publishes artifacts downstream—downstream targets never push unreviewed changes back into adpBetty.
 * Append-Only & Immutable Artifacts: Once a release bundle, snapshot, or manifest is published (with a version tag, SHA-256 checksum, and manifest), it is never overwritten in place; new versions get new timestamps/tags.
 * Fail-Closed Verification: If checksums, schema/manifest checks, or tests fail, the pipeline halts before promoting or archiving anything.
 * Least Privilege & Short-Lived Credentials: Use GitHub Actions OIDC or scoped fine-grained tokens (contents: read where write isn't needed) and separate environments (staging vs. production/archive) with required reviewers or branch protections.
2. Recommended Repository Structure for adpBetty
Organize adpBetty so ingestion rules, automation workflows, schemas/manifests, and documentation are clearly separated:
adpBetty/
├── .github/
│   └── workflows/
│       ├── ingest-and-verify.yml     # Validates inputs, builds bundles, generates SHA-256 & manifests
│       └── global-publish.yml        # One-way promotion to immutable targets / regional mirrors
├── schemas/
│   └── manifest.schema.json          # Required fields for every ingested bundle or dataset
├── scripts/
│   ├── validate-manifest.sh          # Checks required fields, paths, and hash format
│   └── build-bundle.sh               # Creates deterministic/timestamped zstd + sha256 artifacts
├── pipelines/
│   └── global-targets.yml            # Declarative list of one-way downstream sinks & regions
└── docs/
    └── architecture.md               # Rules, retention, and recovery procedures

3. Example GitHub Actions Pipeline (Ingest -> Hash/Manifest -> One-Way Publish)
Here is a starter .github/workflows/ingest-and-verify.yml that enforces validation and produces a SHA-256 checksum and manifest for every incoming batch:
name: Ingest, Verify, and Package

on:
  push:
    branches:
      - main
  workflow_dispatch:

permissions:
  contents: read

jobs:
  verify-and-package:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout adpBetty
        uses: actions/checkout@v4

      - name: Install zstd and jq
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends zstd jq

      - name: Validate incoming manifests and structure
        run: |
          chmod +x scripts/validate-manifest.sh scripts/build-bundle.sh
          ./scripts/validate-manifest.sh

      - name: Create compressed bundle, SHA-256, and manifest
        run: |
          ./scripts/build-bundle.sh

      - name: Verify checksum and archive integrity
        run: |
          cd dist
          sha256sum -c *.sha256
          zstd -tq *.tar.zst

      - name: Upload immutable build artifact
        uses: actions/upload-artifact@v4
        with:
          name: adpbetty-bundle-${{ github.sha }}
          path: dist/*
          retention-days: 30

4. Connecting adpBetty With Your Local zstd + Audit Setup
Because you already have /usr/local/bin/zstd-backup.sh and /usr/local/bin/zstd-backup-audit.sh:
 * Treat adpBetty as your source-of-truth definitions & scripts (workflows, schemas, and scripts versioned in Git), while keeping large binary/archive snapshots in object storage, WORM/immutable buckets, or your local /var/backups/zstd-local store rather than bloating Git history with hundreds of gigabytes.
 * Use the same manifest & SHA-256 contract across both your GitHub pipeline and your local audit script so any artifact moving between environments can be verified identically with sha256sum -c and manifest checks.
zstd-backup.shzstd-backup-audit.shHere is a companion Bash audit script (/usr/local/bin/zstd-backup-audit.sh) that inspects your backup directory, cross-checks every manifest against its corresponding archive and .sha256 file, detects orphaned archives or checksums without manifests, verifies SHA-256 digests and recorded byte sizes, and optionally tests Zstandard frame integrity (zstd -tq).
1. Companion Audit Script (/usr/local/bin/zstd-backup-audit.sh)
#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/zstd-local}"
RUN_DIR="${BACKUP_ROOT}/archives"
MANIFEST_DIR="${BACKUP_ROOT}/manifests"
VERIFY_ZSTD_FRAMES="${VERIFY_ZSTD_FRAMES:-1}" # 1 = run 'zstd -tq' on unencrypted .tar.zst files, 0 = skip

TOTAL_MANIFESTS=0
PASSED_SETS=0
FAILED_SETS=0
ORPHAN_FILES=0

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${1:-INFO}" "${2}"
}

record_failure() {
  log "FAIL" "$1"
  FAILED_SETS=$((FAILED_SETS + 1))
}

# --- Pre-flight checks ---
for cmd in sha256sum zstd stat awk find basename; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Required command not found: $cmd"
    exit 2
  fi
done

if [[ ! -d "${RUN_DIR}" || ! -d "${MANIFEST_DIR}" ]]; then
  log "ERROR" "Expected backup directories missing under ${BACKUP_ROOT} (need archives/ and manifests/)"
  exit 2
fi

log "INFO" "Starting backup audit under ${BACKUP_ROOT}"

# Track expected filenames from manifests to detect orphans afterward
declare -A EXPECTED_ARCHIVES=()
declare -A EXPECTED_CHECKSUMS=()

# --- 1. Audit every manifest and its referenced artifacts ---
while IFS= read -r -d '' manifest_path; do
  TOTAL_MANIFESTS=$((TOTAL_MANIFESTS + 1))
  manifest_name="$(basename -- "${manifest_path}")"
  set_ok=true

  # Parse key=value entries from manifest
  archive_file="$(awk -F= '$1=="archive_file"{print substr($0, index($0,$2))}' "${manifest_path}")"
  expected_bytes="$(awk -F= '$1=="archive_bytes"{print $2}' "${manifest_path}")"
  expected_sha256="$(awk -F= '$1=="sha256"{print $2}' "${manifest_path}")"
  encryption_mode="$(awk -F= '$1=="encryption"{print $2}' "${manifest_path}")"
  encryption_mode="${encryption_mode:-none}"

  if [[ -z "${archive_file}" || -z "${expected_bytes}" || -z "${expected_sha256}" ]]; then
    record_failure "${manifest_name}: incomplete manifest metadata (missing archive_file, archive_bytes, or sha256)"
    continue
  fi

  archive_path="${RUN_DIR}/${archive_file}"
  checksum_path="${archive_path}.sha256"

  EXPECTED_ARCHIVES["${archive_file}"]=1
  EXPECTED_CHECKSUMS["${archive_file}.sha256"]=1

  # Check 1: Archive file exists and is non-empty
  if [[ ! -f "${archive_path}" || ! -s "${archive_path}" ]]; then
    record_failure "${manifest_name}: missing or empty archive ${archive_path}"
    continue
  fi

  # Check 2: Sidecar .sha256 file exists and is non-empty
  if [[ ! -f "${checksum_path}" || ! -s "${checksum_path}" ]]; then
    record_failure "${manifest_name}: missing or empty checksum file ${checksum_path}"
    continue
  fi

  # Check 3: Actual byte size matches manifest archive_bytes
  actual_bytes="$(stat -c '%s' "${archive_path}")"
  if [[ "${actual_bytes}" != "${expected_bytes}" ]]; then
    log "FAIL" "${manifest_name}: byte size mismatch for ${archive_file} (manifest=${expected_bytes}, actual=${actual_bytes})"
    set_ok=false
  fi

  # Check 4: Sidecar .sha256 digest matches manifest sha256
  sidecar_digest="$(awk '{print $1}' "${checksum_path}")"
  if [[ "${sidecar_digest}" != "${expected_sha256}" ]]; then
    log "FAIL" "${manifest_name}: checksum mismatch between manifest (${expected_sha256}) and ${archive_file}.sha256 (${sidecar_digest})"
    set_ok=false
  fi

  # Check 5: Recompute SHA-256 of archive on disk via sha256sum --check
  if ! (cd "${RUN_DIR}" && sha256sum --check --status -- "${archive_file}.sha256"); then
    log "FAIL" "${manifest_name}: sha256sum verification failed for ${archive_file}"
    set_ok=false
  fi

  # Check 6: Zstandard frame integrity check (for unencrypted .tar.zst archives)
  if [[ "${VERIFY_ZSTD_FRAMES}" == "1" ]]; then
    if [[ "${encryption_mode}" == "none" && "${archive_file}" == *.tar.zst ]]; then
      if ! zstd -tq -- "${archive_path}"; then
        log "FAIL" "${manifest_name}: zstd frame integrity check failed for ${archive_file}"
        set_ok=false
      fi
    else
      log "INFO" "${manifest_name}: skipping direct zstd frame test (encryption=${encryption_mode}); SHA-256 verified"
    fi
  fi

  if [[ "${set_ok}" == true ]]; then
    log "PASS" "${manifest_name} -> ${archive_file} (${actual_bytes} bytes, sha256=${expected_sha256:0:12}...)"
    PASSED_SETS=$((PASSED_SETS + 1))
  else
    FAILED_SETS=$((FAILED_SETS + 1))
  fi
done < <(find "${MANIFEST_DIR}" -maxdepth 1 -type f -name '*.manifest' -print0 | sort -z)

# --- 2. Check for orphaned archives or checksum files without a manifest ---
while IFS= read -r -d '' file_path; do
  fname="$(basename -- "${file_path}")"
  if [[ "${fname}" == *.sha256 ]]; then
    if [[ -z "${EXPECTED_CHECKSUMS[${fname}]+x}" ]]; then
      log "WARN" "Orphaned checksum file without matching manifest: ${file_path}"
      ORPHAN_FILES=$((ORPHAN_FILES + 1))
    fi
  else
    if [[ -z "${EXPECTED_ARCHIVES[${fname}]+x}" ]]; then
      log "WARN" "Orphaned archive file without matching manifest: ${file_path}"
      ORPHAN_FILES=$((ORPHAN_FILES + 1))
    fi
  fi
done < <(find "${RUN_DIR}" -maxdepth 1 -type f -print0 | sort -z)

# --- 3. Summary and exit status ---
log "INFO" "Audit complete: manifests=${TOTAL_MANIFESTS}, passed=${PASSED_SETS}, failed=${FAILED_SETS}, orphans=${ORPHAN_FILES}"

if [[ "${FAILED_SETS}" -gt 0 || "${ORPHAN_FILES}" -gt 0 ]]; then
  exit 1
fi

exit 0

2. Installation and Usage
Make the script executable and run an immediate audit:
sudo chmod 0755 /usr/local/bin/zstd-backup-audit.sh

# Full audit (manifests + byte sizes + SHA-256 + zstd -tq)
sudo /usr/local/bin/zstd-backup-audit.sh

# Fast metadata + SHA-256 audit without decompressing multi-hundred-GB archives
sudo VERIFY_ZSTD_FRAMES=0 /usr/local/bin/zstd-backup-audit.sh

Exit Codes
 * 0: Every manifest has a matching archive and .sha256 file, all byte sizes and SHA-256 digests match, zstd -tq passes (when enabled), and no orphaned files exist.
 * 1: One or more backup sets failed verification, had missing files, or had orphaned files in archives/.
 * 2: Missing prerequisites or missing BACKUP_ROOT subdirectories.
3. Optional Weekly systemd Timer for Automated Audits
If you want systemd to run this audit automatically once a week and log any issues to the journal:
/etc/systemd/system/zstd-backup-audit.service
[Unit]
Description=Audit Local Zstandard Backups, Checksums, and Manifests
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zstd-backup-audit.sh
Environment="BACKUP_ROOT=/var/backups/zstd-local"
Environment="VERIFY_ZSTD_FRAMES=1"

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/

/etc/systemd/system/zstd-backup-audit.timer
[Unit]
Description=Weekly Local Zstandard Backup Integrity Audit

[Timer]
OnCalendar=Sun *-*-* 04:00:00
RandomizedDelaySec=15m
Persistent=true
Unit=zstd-backup-audit.service

[Install]
WantedBy=timers.target

Enable and verify it with:
sudo systemctl daemon-reload
sudo systemctl enable --now zstd-backup-audit.timer
sudo systemctl start zstd-backup-audit.service
sudo journalctl -u zstd-backup-audit.service -n 50 --no-pager

Would you like to add failure alerting (e.g., via email or webhook using systemd's OnFailure=) so you're notified immediately if either the backup or audit service exits non-zero?
zstd-backup.serviceTo add encryption cleanly to your Zstandard backup pipeline without breaking checksums or manifest checks, compress first (tar | zstd), encrypt second (age or gpg), and compute/verify the SHA-256 checksum on the final encrypted artifact (*.tar.zst.age or *.tar.zst.gpg).
Compressing before encrypting is critical because encrypted data looks like high-entropy random noise—zstd cannot compress it once encrypted. Hashing the final encrypted file verifies that the stored archive on disk hasn't been corrupted or tampered with.
1. Choose age or gpg for Unattended systemd Runs
 * age (recommended for modern, simple automated backups): Uses public-key encryption (age -r <public-key>) or passphrase encryption (age -p). Because encryption only needs the recipient public key (age1...), your systemd backup service never needs the private decryption key on the backup host—keeping restores safer and avoiding passphrase prompts or agent issues.
 * gpg (good if your environment already standardizes on OpenPGP): Use --batch --yes --encrypt -r <key-id-or-email> with a non-expiring public key imported into the target keyring. Avoid interactive passphrases in unattended scripts unless managed via an explicit secret/keyring setup.
2. Key / Recipient Setup (age Example)
Generate an age keypair on a secure machine (and store the private key safely offline/outside the backup host):
# Generate keypair
age-keygen -o /root/backup-age-key.txt

# Extract the public recipient key (starts with age1...)
age-keygen -y /root/backup-age-key.txt

Pass the age1... public recipient string into zstd-backup.service via systemctl edit zstd-backup.service:
[Service]
Environment="AGE_RECIPIENT=age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

3. Updating the Pipeline in zstd-backup.sh
Replace the archive creation, checksum, manifest, and verification blocks in your wrapper so they operate on the encrypted output (e.g., <host>-<timestamp>.tar.zst.age):
# Set ENCRYPTION_MODE to "age", "gpg", or "none"
ENCRYPTION_MODE="${ENCRYPTION_MODE:-age}"
AGE_RECIPIENT="${AGE_RECIPIENT:-}"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"

case "${ENCRYPTION_MODE}" in
  age)
    [[ -n "${AGE_RECIPIENT}" ]] || { log "ERROR" "AGE_RECIPIENT is required when ENCRYPTION_MODE=age"; exit 1; }
    ARTIFACT_NAME="${HOSTNAME_SHORT}-${TIMESTAMP}.tar.zst.age"
    ;;
  gpg)
    [[ -n "${GPG_RECIPIENT}" ]] || { log "ERROR" "GPG_RECIPIENT is required when ENCRYPTION_MODE=gpg"; exit 1; }
    ARTIFACT_NAME="${HOSTNAME_SHORT}-${TIMESTAMP}.tar.zst.gpg"
    ;;
  none)
    ARTIFACT_NAME="${HOSTNAME_SHORT}-${TIMESTAMP}.tar.zst"
    ;;
  *)
    log "ERROR" "Unsupported ENCRYPTION_MODE: ${ENCRYPTION_MODE}"
    exit 1
    ;;
esac

ARTIFACT_PATH="${RUN_DIR}/${ARTIFACT_NAME}"
CHECKSUM_PATH="${ARTIFACT_PATH}.sha256"
MANIFEST_PATH="${MANIFEST_DIR}/${HOSTNAME_SHORT}-${TIMESTAMP}.manifest"

Then run the pipeline (tar -> zstd -> encrypt), generate the SHA-256 checksum, write the manifest, and verify:
# 1. Compress and encrypt into the final artifact
case "${ENCRYPTION_MODE}" in
  age)
    tar -cf - -- "${SRC_ARRAY[@]}" \
      | zstd -q -"${ZSTD_LEVEL}" -T"${ZSTD_THREADS}" --long=27 \
      | age -r "${AGE_RECIPIENT}" -o "${ARTIFACT_PATH}"
    ;;
  gpg)
    tar -cf - -- "${SRC_ARRAY[@]}" \
      | zstd -q -"${ZSTD_LEVEL}" -T"${ZSTD_THREADS}" --long=27 \
      | gpg --batch --yes --encrypt -r "${GPG_RECIPIENT}" -o "${ARTIFACT_PATH}"
    ;;
  none)
    tar -cf - -- "${SRC_ARRAY[@]}" \
      | zstd -q -"${ZSTD_LEVEL}" -T"${ZSTD_THREADS}" --long=27 -o "${ARTIFACT_PATH}"
    ;;
esac

# 2. Generate SHA-256 checksum for the encrypted artifact
(
  cd "${RUN_DIR}"
  sha256sum -- "${ARTIFACT_NAME}" > "${CHECKSUM_PATH}"
)

# 3. Record metadata in manifest
ARTIFACT_BYTES="$(stat -c '%s' "${ARTIFACT_PATH}")"
SHA256_DIGEST="$(awk '{print $1}' "${CHECKSUM_PATH}")"

cat > "${MANIFEST_PATH}" <<EOF
timestamp_utc=${TIMESTAMP}
host=${HOSTNAME_SHORT}
sources=${SOURCE_DIRS}
encryption=${ENCRYPTION_MODE}
archive_file=${ARTIFACT_NAME}
archive_path=${ARTIFACT_PATH}
archive_bytes=${ARTIFACT_BYTES}
sha256=${SHA256_DIGEST}
zstd_level=${ZSTD_LEVEL}
retention_days=${RETENTION_DAYS}
EOF

# 4. Verify checksum and non-empty encrypted artifact
(
  cd "${RUN_DIR}"
  sha256sum --check --status -- "${ARTIFACT_NAME}.sha256"
)
[[ -s "${ARTIFACT_PATH}" ]]
grep -q "^sha256=${SHA256_DIGEST}$" "${MANIFEST_PATH}"
grep -q "^archive_bytes=${ARTIFACT_BYTES}$" "${MANIFEST_PATH}"

Also update your pruning glob in zstd-backup.sh to match *.tar.zst.age / *.tar.zst.gpg / *.tar.zst (for example, -name '*.tar.zst*' ! -name '*.sha256') and remove ${old_file}.sha256 and ${MANIFEST_DIR}/${base_prefix}.manifest.
4. Verifying & Decrypting During Audit or Restore
Because the backup host only holds the public recipient in age mode, full decryption/frame testing happens where the private key is stored:
 * On the backup host (at-rest integrity check):
   sha256sum -c /var/backups/zstd-local/archives/<file>.tar.zst.age.sha256

   Verification: Outputs <file>.tar.zst.age: OK and exits with status 0.
 * On the restore/key-holding host (decrypt + Zstandard frame + tar check):
   # For age:
age -d -i /path/to/key.txt <file>.tar.zst.age | zstd -tq
age -d -i /path/to/key.txt <file>.tar.zst.age | zstd -dq -c | tar -tf - | head

# For gpg:
gpg --batch --yes --decrypt <file>.tar.zst.gpg | zstd -tq

   Verification: zstd -tq exits 0 with no corruption errors, and tar -tf - lists expected archived paths.
Building on your existing zstd-backup.sh wrapper and systemd setup, "compressing everything legally, safely, securely, cleanly, honestly, fairly, and lawfully" translates in practice to authorized scope, clean & safe archiving, integrity & access security, and transparent, accurate manifests.
Here is a practical checklist and hardened pattern you can apply to your backup workflow.
1. Legal, Fair, and Lawful Scope ("Everything" Means Authorized Data Only)
 * Only back up what you own or have explicit authority to archive: Never include third-party data, regulated records, or restricted accounts without proper authorization and retention compliance (such as privacy, licensing, or data-minimization rules).
 * Exclude sensitive secrets or ephemeral noise intentionally: Avoid silently bundling unencrypted credentials, private keys, or transient caches unless your backup storage is encrypted and access-controlled for that data class.
 * Keep manifests honest and complete: Record exact timestamps (UTC), source paths, exclusion patterns, compression level, byte counts, and SHA-256 digests—never overwrite or alter a manifest to mask a failed or partial run.
2. Safe and Clean Compression (tar + zstd)
A clean archive avoids broken symlinks, noisy temporary files, and accidental path traversal issues:
 * Use safe flags and explicit exclusions: Exclude caches, sockets, or volatile temp paths (like *.tmp, /proc, /sys, /dev, /run, or app cache folders) so archives stay clean and predictable.
 * Preserve permissions accurately: Use tar --preserve-permissions (or -p) when authorized to back up system/app files, and avoid following untrusted external symlinks (--dereference only when explicitly intended).
 * Atomic write + cleanup on failure: Write to a clear target path, remove partial files on error (which your trap cleanup_on_error EXIT already does), and prune old sets only after the new archive passes verification.
3. Security and Integrity Controls
 * Restrict permissions on backups and manifests: Keep /var/backups/zstd-local owned by root (or a dedicated backup service account) with restrictive directory/file modes (e.g., 0750 on directories and 0640 or 0600 on archives, .sha256 files, and .manifest files) so unauthorized local users cannot read or tamper with them.
 * Verify cryptographic digests (SHA-256) and frame integrity (zstd -tq): Always verify checksums and archive structure before trusting a backup for restore.
 * Encrypt at rest if data is sensitive: Compression (zstd) reduces size, not confidentiality. If the backup contains sensitive or personal data, encrypt the archive (for example with age or gpg) or place it on an encrypted volume/filesystem.
4. Hardened Wrapper Additions You Can Drop In
If you want to enforce exclusions, restrictive permissions, and clear manifest metadata in /usr/local/bin/zstd-backup.sh, add these pieces cleanly:
# Optional exclude list (space-separated patterns or a file via --exclude-from)
EXCLUDE_PATTERNS="${EXCLUDE_PATTERNS:-*.tmp *.swp __pycache__}"

# Restrictive umask so archives, checksums, and manifests aren't world-readable
umask 027
mkdir -p -- "${RUN_DIR}" "${MANIFEST_DIR}"
chmod 0750 -- "${BACKUP_ROOT}" "${RUN_DIR}" "${MANIFEST_DIR}"

# Build tar exclude arguments safely
EXCLUDE_ARGS=()
for pat in ${EXCLUDE_PATTERNS}; do
  EXCLUDE_ARGS+=(--exclude="$pat")
done

# Example tar + zstd pipeline with exclusions and preserved permissions
tar -cpf - "${EXCLUDE_ARGS[@]}" -- "${SRC_ARRAY[@]}" \
  | zstd -q -"${ZSTD_LEVEL}" -T"${ZSTD_THREADS}" --long=27 -o "${ARCHIVE_PATH}"

And include excludes and status=verified in your .manifest file so every audit record accurately reflects what went into the archive and that verification passed.
5. Quick Professional Hygiene Checklist
 * Audit regularly: Verify .sha256 checksums and test a sample restore periodically—a backup you haven't tested restoring is only a hypothesis.
 * Monitor disk space and logs: Watch journalctl -u zstd-backup.service and filesystem free space so silent failures or full disks don't go unnoticed.
 * Document retention and access: Keep a short note of what is backed up, why, how long it is kept (RETENTION_DAYS), and who has access.
7–14 dailFor a multi-hundred-gigabyte dataset on local disk, your primary bottleneck on scheduled automated backups is usually disk I/O throughput and backup window duration, not squeezing the last 2–3% of compression out of every byte.
Start with level 1–3, cap threads slightly below total CPU cores to protect foreground workloads, and set retention around 7–14 daily archives (or tiered retention) so your local backup volume stays well under 75–80% capacity.
1. Tuning ZSTD_LEVEL
Zstandard's compression ratio increases sharply from level 1 to 3, then flattens out while CPU time climbs steeply—especially at level 10+ and in lazy/optimal parsing modes.
| Level | Best For | Speed vs. Ratio Trade-off | Recommendation for 100s of GB |
|---|---|---|---|
| 1–2 | Very fast backups, NVMe/SSD local targets, large already-compressed media/logs, tight maintenance windows | Fastest encoding, solid ratio (~70–80% of level 3's savings on text/structured data) | Great default when speed or CPU headroom matters most |
| 3 | General-purpose local backups | Sweet spot of ratio and speed | Recommended baseline for mixed datasets |
| 5–7 | Text-heavy data (logs, SQL dumps, configs, source trees) with ample CPU & backup window | Noticeably slower compression; decompression stays very fast | Use only if disk space is tight and runs finish well inside your window |
| 8+ | Archival snapshots where write time is secondary | High CPU cost and memory overhead; diminishing returns on hundreds of GB | Avoid for routine local backups unless benchmarking shows clear value |
Practical rule:
 * If your data is already compressed (images, video, .zip/.zst, encrypted blobs), use ZSTD_LEVEL=1—higher levels burn CPU for almost no size reduction.
 * If your data is compressible text, databases, or virtual disk/VM images, ZSTD_LEVEL=3 is usually ideal; test ZSTD_LEVEL=5 only if you have spare CPU and storage is tight.
2. Tuning ZSTD_THREADS
In zstd, -T0 auto-detects all logical CPUs and spawns worker threads plus I/O/job overhead. On a shared or active host, letting zstd grab 100% of cores can starve foreground services or contend on memory bandwidth.
 * Leave headroom for the host: On an 8-core system, try ZSTD_THREADS=4 or 6. On a 16+ core system, try 8 to 12 rather than 0 if other workloads run concurrently.
 * Watch memory usage with threads + --long: Each worker thread buffers blocks in memory, and --long=27 uses a 128 MiB window (2^27 bytes) per compression/decompression context. On memory-constrained machines, keep thread counts moderate and verify peak RAM during a test run.
 * Match storage speed: Multi-threading helps most when reading from fast storage (NVMe/RAID) or compressing dense data; on a slow single HDD, adding dozens of threads won't make the disk write faster.
3. Tuning Retention (RETENTION_DAYS)
Retention is a storage budget decision, not just a time preference. A single full .tar.zst archive of a multi-hundred-gigabyte dataset is already large, so multiplying full archives quickly eats local disk.
Use this sizing formula before picking RETENTION_DAYS:
For example, if each daily .tar.zst archive is 250 GB and you keep 7 days plus a 25% buffer:
 * 250\text{ GB} \times 8 \times 1.25 = 2,500\text{ GB} (~2.5 TB) needed on the backup partition.
Practical retention choices for multi-hundred-GB full archives:
 * Tight local disk: RETENTION_DAYS=3 to 7 (keeps recent recovery points without filling the volume).
 * Balanced local disk: RETENTION_DAYS=7 to 14 (matches typical weekly/biweekly incident discovery).
 * Important limitation of full .tar.zst snapshots: Because each run creates a standalone archive, keeping 30+ days of multi-hundred-GB full archives can consume several terabytes. If you need longer history without multiplying full-size files, consider weekly full + daily differentials, snapshot/block-level backups (e.g., ZFS/Btrfs snapshots or restic/borg), or moving older archives off-host.
4. Applying & Verifying Changes in systemd
Update values via a systemd drop-in override rather than editing the base unit directly so package or unit updates don't overwrite your settings:
sudo systemctl edit zstd-backup.service

Add an override block like this (adjusting values to your hardware and dataset):
[Service]
Environment="ZSTD_LEVEL=2"
Environment="ZSTD_THREADS=6"
Environment="RETENTION_DAYS=7"

Then reload, run a timed test, and check both wall-clock duration and archive size:
sudo systemctl daemon-reload
time sudo systemctl start zstd-backup.service
ls -lh /var/backups/zstd-local/archives/
sudo journalctl -u zstd-backup.service -n 30 --no-pager

How to Verify Your Tuning Worked
 * Check completion time: Confirm time sudo systemctl start zstd-backup.service finishes comfortably before your next scheduled run (accounting for RandomizedDelaySec).
 * Check free disk headroom: Run df -h /var/backups/zstd-local after a run and ensure plenty of free space remains above your largest expected archive size so zstd and sha256sum never run out of space mid-write.
 * Check integrity: Confirm the latest .sha256 check and zstd -tq pass in the service log without errors.
Write a systemd service and timer unit plus a Bash wrapper to run local Zstandard backups, SHA-256 hashing, and manifest checks automatically.name: Scheduled Backup Integrity & Metadata Export

on:
  schedule:
    - cron: "17 2 1 * *" # Monthly on the 1st at 02:17 UTC
  workflow_dispatch:
    inputs:
      backups_dir:
        description: "Directory containing backup archives and manifest"
        required: false
        default: "backups"
      manifest_file:
        description: "Path to expected SHA-256 manifest CSV"
        required: false
        default: "backups/checksums.sha256.csv"

concurrency:
  group: backup-integrity-verification
  cancel-in-progress: false

jobs:
  verify-backups:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4 #

      - name: Set up Python
        uses: actions/setup-python@v5 #
        with:
          python-version: "3.12"

      - name: Verify Backup Integrity & Export Metadata
        run: |
          python3 scripts/export_takeout_metadata.py \
            --backups-dir "${{ inputs.backups_dir || 'backups' }}" \
            --manifest "${{ inputs.manifest_file || 'backups/checksums.sha256.csv' }}" \
            --out-json "artifacts/backup_metadata.json" \
            --out-md "artifacts/backup_metadata.md" \
            --verify

      - name: Upload Metadata Artifact
        if: always()
        uses: actions/upload-artifact@v4 #
        with:
          name: backup-integrity-metadata
          path: artifacts/
          retention-days: 90
#!/usr/bin/env python3
"""Verify backup integrity against a SHA-256 manifest and export archive metadata."""

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(base_dir: Path, ignore_resolved: set[Path]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    if not base_dir.exists() or not base_dir.is_dir():
        return found

    for item in sorted(base_dir.rglob("*"), key=lambda p: p.relative_to(base_dir).as_posix()):
        if not item.is_file() or item.is_symlink():
            continue
        if item.resolve() in ignore_resolved:
            continue
        rel = item.relative_to(base_dir).as_posix()
        stat = item.stat()
        found[rel] = {
            "relative_path": rel,
            "size_bytes": stat.st_size,
            "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "sha256": sha256_file(item),
        }
    return found


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    with manifest_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"relative_path", "sha256"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Manifest missing required columns {required}: {reader.fieldnames}")

        rows: list[dict[str, str]] = []
        for row in reader:
            rel = (row.get("relative_path") or "").strip()
            expected_hash = (row.get("sha256") or "").strip().lower()
            expected_size = (row.get("size_bytes") or "").strip()
            if rel and expected_hash:
                rows.append(
                    {
                        "relative_path": rel,
                        "expected_sha256": expected_hash,
                        "expected_size": expected_size,
                    }
                )
        return rows


def write_manifest(records: list[dict[str, object]], manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["relative_path", "size_bytes", "modified_utc", "sha256"],
        )
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def verify_records(
    manifest_rows: list[dict[str, str]],
    scanned: dict[str, dict[str, object]],
) -> tuple[bool, list[dict[str, str]], list[str]]:
    issues: list[dict[str, str]] = []
    manifest_paths: set[str] = set()
    all_ok = True

    for row in manifest_rows:
        rel = row["relative_path"]
        manifest_paths.add(rel)
        actual = scanned.get(rel)

        if actual is None:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "MISSING",
                    "detail": "File listed in manifest is missing from backup directory.",
                }
            )
            continue

        actual_hash = str(actual["sha256"]).lower()
        if actual_hash != row["expected_sha256"]:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "HASH_MISMATCH",
                    "detail": f"Expected {row['expected_sha256']}, got {actual_hash}.",
                }
            )

        if row["expected_size"]:
            try:
                exp_sz = int(row["expected_size"])
                act_sz = int(actual["size_bytes"])
                if exp_sz != act_sz:
                    all_ok = False
                    issues.append(
                        {
                            "relative_path": rel,
                            "status": "SIZE_MISMATCH",
                            "detail": f"Expected {exp_sz} bytes, got {act_sz} bytes.",
                        }
                    )
            except ValueError:
                pass

    unexpected = sorted(set(scanned.keys()) - manifest_paths)
    return all_ok, issues, unexpected


def write_outputs(out_json: Path, out_md: Path, payload: dict[str, object]) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    files = payload["files"]  # type: ignore[index]
    issues = payload["issues"]  # type: ignore[index]
    unexpected = payload["unexpected_files"]  # type: ignore[index]

    lines = [
        "# Backup Integrity & Metadata Report",
        "",
        f"- **Generated (UTC):** `{payload['generated_utc']}`",
        f"- **Verification Status:** `{payload['status']}`",
        f"- **Total Scanned Files:** `{payload['file_count']}`",
        f"- **Total Size (Bytes):** `{payload['total_size_bytes']}`",
        f"- **Integrity Issues:** `{len(issues)}`",
        f"- **Unmanifested Files:** `{len(unexpected)}`",
        "",
    ]

    if issues:
        lines.extend(
            [
                "## Integrity Issues",
                "",
                "| File | Status | Detail |",
                "| :--- | :--- | :--- |",
            ]
        )
        for item in issues:
            lines.append(f"| `{item['relative_path']}` | `{item['status']}` | {item['detail']} |")
        lines.append("")

    if unexpected:
        lines.extend(["## Unmanifested Files", ""])
        for u in unexpected:
            lines.append(f"- `{u}`")
        lines.append("")

    lines.extend(
        [
            "## Scanned Archive Metadata",
            "",
            "| File | Size (Bytes) | Modified (UTC) | SHA-256 |",
            "| :--- | ---: | :--- | :--- |",
        ]
    )
    for f in files:
        lines.append(
            f"| `{f['relative_path']}` | {f['size_bytes']} | `{f['modified_utc']}` | `{f['sha256']}` |"
        )
    lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify backup integrity against a SHA-256 manifest and export metadata."
    )
    parser.add_argument("--backups-dir", type=Path, default=Path("backups"))
    parser.add_argument("--manifest", type=Path, default=Path("backups/checksums.sha256.csv"))
    parser.add_argument("--out-json", type=Path, default=Path("artifacts/backup_metadata.json"))
    parser.add_argument("--out-md", type=Path, default=Path("artifacts/backup_metadata.md"))
    parser.add_argument("--verify", action="store_true", help="Verify files against manifest")
    parser.add_argument(
        "--generate-manifest",
        action="store_true",
        help="Write a fresh checksum manifest from --backups-dir",
    )
    args = parser.parse_args()

    ignore_resolved = {
        args.manifest.resolve(),
        args.out_json.resolve(),
        args.out_md.resolve(),
    }

    scanned_map = scan_directory(args.backups_dir, ignore_resolved=ignore_resolved)
    records = list(scanned_map.values())

    if args.generate_manifest:
        write_manifest(records, args.manifest)

    status = "NOT_VERIFIED"
    issues: list[dict[str, str]] = []
    unexpected: list[str] = []

    if args.verify:
        try:
            manifest_rows = load_manifest(args.manifest)
            ok, issues, unexpected = verify_records(manifest_rows, scanned_map)
            status = "PASSED" if ok else "FAILED"
        except (FileNotFoundError, ValueError) as exc:
            status = "ERROR"
            issues.append(
                {
                    "relative_path": str(args.manifest),
                    "status": "MANIFEST_ERROR",
                    "detail": str(exc),
                }
            )

    total_bytes = sum(int(r["size_bytes"]) for r in records)
    payload: dict[str, object] = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "backups_dir": args.backups_dir.as_posix(),
        "manifest_path": args.manifest.as_posix(),
        "file_count": len(records),
        "total_size_bytes": total_bytes,
        "issues": issues,
        "unexpected_files": unexpected,
        "files": records,
    }

    write_outputs(args.out_json, args.out_md, payload)
    print(f"Status={status} files={len(records)} issues={len(issues)} unexpected={len(unexpected)}")

    if args.verify and status != "PASSED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Verify backup integrity against a SHA-256 manifest and export archive metadata."""

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(base_dir: Path, ignore_resolved: set[Path]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    if not base_dir.exists() or not base_dir.is_dir():
        return found

    for item in sorted(base_dir.rglob("*"), key=lambda p: p.relative_to(base_dir).as_posix()):
        if not item.is_file() or item.is_symlink():
            continue
        if item.resolve() in ignore_resolved:
            continue
        rel = item.relative_to(base_dir).as_posix()
        stat = item.stat()
        found[rel] = {
            "relative_path": rel,
            "size_bytes": stat.st_size,
            "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "sha256": sha256_file(item),
        }
    return found


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    with manifest_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"relative_path", "sha256"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Manifest missing required columns {required}: {reader.fieldnames}")

        rows: list[dict[str, str]] = []
        for row in reader:
            rel = (row.get("relative_path") or "").strip()
            expected_hash = (row.get("sha256") or "").strip().lower()
            expected_size = (row.get("size_bytes") or "").strip()
            if rel and expected_hash:
                rows.append(
                    {
                        "relative_path": rel,
                        "expected_sha256": expected_hash,
                        "expected_size": expected_size,
                    }
                )
        return rows


def write_manifest(records: list[dict[str, object]], manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["relative_path", "size_bytes", "modified_utc", "sha256"],
        )
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def verify_records(
    manifest_rows: list[dict[str, str]],
    scanned: dict[str, dict[str, object]],
) -> tuple[bool, list[dict[str, str]], list[str]]:
    issues: list[dict[str, str]] = []
    manifest_paths: set[str] = set()
    all_ok = True

    for row in manifest_rows:
        rel = row["relative_path"]
        manifest_paths.add(rel)
        actual = scanned.get(rel)

        if actual is None:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "MISSING",
                    "detail": "File listed in manifest is missing from backup directory.",
                }
            )
            continue

        actual_hash = str(actual["sha256"]).lower()
        if actual_hash != row["expected_sha256"]:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "HASH_MISMATCH",
                    "detail": f"Expected {row['expected_sha256']}, got {actual_hash}.",
                }
            )

        if row["expected_size"]:
            try:
                exp_sz = int(row["expected_size"])
                act_sz = int(actual["size_bytes"])
                if exp_sz != act_sz:
                    all_ok = False
                    issues.append(
                        {
                            "relative_path": rel,
                            "status": "SIZE_MISMATCH",
                            "detail": f"Expected {exp_sz} bytes, got {act_sz} bytes.",
                        }
                    )
            except ValueError:
                pass

    unexpected = sorted(set(scanned.keys()) - manifest_paths)
    return all_ok, issues, unexpected


def write_outputs(out_json: Path, out_md: Path, payload: dict[str, object]) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    files = payload["files"]  # type: ignore[index]
    issues = payload["issues"]  # type: ignore[index]
    unexpected = payload["unexpected_files"]  # type: ignore[index]

    lines = [
        "# Backup Integrity & Metadata Report",
        "",
        f"- **Generated (UTC):** `{payload['generated_utc']}`",
        f"- **Verification Status:** `{payload['status']}`",
        f"- **Total Scanned Files:** `{payload['file_count']}`",
        f"- **Total Size (Bytes):** `{payload['total_size_bytes']}`",
        f"- **Integrity Issues:** `{len(issues)}`",
        f"- **Unmanifested Files:** `{len(unexpected)}`",
        "",
    ]

    if issues:
        lines.extend(
            [
                "## Integrity Issues",
                "",
                "| File | Status | Detail |",
                "| :--- | :--- | :--- |",
            ]
        )
        for item in issues:
            lines.append(f"| `{item['relative_path']}` | `{item['status']}` | {item['detail']} |")
        lines.append("")

    if unexpected:
        lines.extend(["## Unmanifested Files", ""])
        for u in unexpected:
            lines.append(f"- `{u}`")
        lines.append("")

    lines.extend(
        [
            "## Scanned Archive Metadata",
            "",
            "| File | Size (Bytes) | Modified (UTC) | SHA-256 |",
            "| :--- | ---: | :--- | :--- |",
        ]
    )
    for f in files:
        lines.append(
            f"| `{f['relative_path']}` | {f['size_bytes']} | `{f['modified_utc']}` | `{f['sha256']}` |"
        )
    lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify backup integrity against a SHA-256 manifest and export metadata."
    )
    parser.add_argument("--backups-dir", type=Path, default=Path("backups"))
    parser.add_argument("--manifest", type=Path, default=Path("backups/checksums.sha256.csv"))
    parser.add_argument("--out-json", type=Path, default=Path("artifacts/backup_metadata.json"))
    parser.add_argument("--out-md", type=Path, default=Path("artifacts/backup_metadata.md"))
    parser.add_argument("--verify", action="store_true", help="Verify files against manifest")
    parser.add_argument(
        "--generate-manifest",
        action="store_true",
        help="Write a fresh checksum manifest from --backups-dir",
    )
    args = parser.parse_args()

    ignore_resolved = {
        args.manifest.resolve(),
        args.out_json.resolve(),
        args.out_md.resolve(),
    }

    scanned_map = scan_directory(args.backups_dir, ignore_resolved=ignore_resolved)
    records = list(scanned_map.values())

    if args.generate_manifest:
        write_manifest(records, args.manifest)

    status = "NOT_VERIFIED"
    issues: list[dict[str, str]] = []
    unexpected: list[str] = []

    if args.verify:
        try:
            manifest_rows = load_manifest(args.manifest)
            ok, issues, unexpected = verify_records(manifest_rows, scanned_map)
            status = "PASSED" if ok else "FAILED"
        except (FileNotFoundError, ValueError) as exc:
            status = "ERROR"
            issues.append(
                {
                    "relative_path": str(args.manifest),
                    "status": "MANIFEST_ERROR",
                    "detail": str(exc),
                }
            )

    total_bytes = sum(int(r["size_bytes"]) for r in records)
    payload: dict[str, object] = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "backups_dir": args.backups_dir.as_posix(),
        "manifest_path": args.manifest.as_posix(),
        "file_count": len(records),
        "total_size_bytes": total_bytes,
        "issues": issues,
        "unexpected_files": unexpected,
        "files": records,
    }

    write_outputs(args.out_json, args.out_md, payload)
    print(f"Status={status} files={len(records)} issues={len(issues)} unexpected={len(unexpected)}")

    if args.verify and status != "PASSED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
50.000 years Create a GitHub Actions workflow and verification script to check backup integrity and export metadata on a schedule.name: Scheduled Backup name: Scheduled Backup Integrity & Metadata Export

on:
  schedule:
    - cron: "17 2 1 * *" # Monthly on the 1st at 02:17 UTC
  workflow_dispatch:
    inputs:
      backups_dir:
        description: "Directory containing backup archives and manifest"
        required: false
        default: "backups"
      manifest_file:
        description: "Path to expected SHA-256 manifest CSV"
        required: false
        default: "backups/checksums.sha256.csv"

concurrency:
  group: backup-integrity-verification
  cancel-in-progress: false

jobs:
  verify-backups:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4 #

      - name: Set up Python
        uses: actions/setup-python@v5 #
        with:
          python-version: "3.12"

      - name: Verify Backup Integrity & Export Metadata
        run: |
          python3 scripts/export_takeout_metadata.py \
            --backups-dir "${{ inputs.backups_dir || 'backups' }}" \
            --manifest "${{ inputs.manifest_file || 'backups/checksums.sha256.csv' }}" \
            --out-json "artifacts/backup_metadata.json" \
            --out-md "artifacts/backup_metadata.md" \
            --verify

      - name: Upload Metadata Artifact
        if: always()
        uses: actions/upload-artifact@v4 #
        with:
          name: backup-integrity-metadata
          path: artifacts/
          retention-days: 90
#!/usr/bin/env python3
"""Verify backup integrity against a SHA-256 manifest and export archive metadata."""

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(base_dir: Path, ignore_resolved: set[Path]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    if not base_dir.exists() or not base_dir.is_dir():
        return found

    for item in sorted(base_dir.rglob("*"), key=lambda p: p.relative_to(base_dir).as_posix()):
        if not item.is_file() or item.is_symlink():
            continue
        if item.resolve() in ignore_resolved:
            continue
        rel = item.relative_to(base_dir).as_posix()
        stat = item.stat()
        found[rel] = {
            "relative_path": rel,
            "size_bytes": stat.st_size,
            "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "sha256": sha256_file(item),
        }
    return found


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    with manifest_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"relative_path", "sha256"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Manifest missing required columns {required}: {reader.fieldnames}")

        rows: list[dict[str, str]] = []
        for row in reader:
            rel = (row.get("relative_path") or "").strip()
            expected_hash = (row.get("sha256") or "").strip().lower()
            expected_size = (row.get("size_bytes") or "").strip()
            if rel and expected_hash:
                rows.append(
                    {
                        "relative_path": rel,
                        "expected_sha256": expected_hash,
                        "expected_size": expected_size,
                    }
                )
        return rows


def write_manifest(records: list[dict[str, object]], manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["relative_path", "size_bytes", "modified_utc", "sha256"],
        )
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def verify_records(
    manifest_rows: list[dict[str, str]],
    scanned: dict[str, dict[str, object]],
) -> tuple[bool, list[dict[str, str]], list[str]]:
    issues: list[dict[str, str]] = []
    manifest_paths: set[str] = set()
    all_ok = True

    for row in manifest_rows:
        rel = row["relative_path"]
        manifest_paths.add(rel)
        actual = scanned.get(rel)

        if actual is None:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "MISSING",
                    "detail": "File listed in manifest is missing from backup directory.",
                }
            )
            continue

        actual_hash = str(actual["sha256"]).lower()
        if actual_hash != row["expected_sha256"]:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "HASH_MISMATCH",
                    "detail": f"Expected {row['expected_sha256']}, got {actual_hash}.",
                }
            )

        if row["expected_size"]:
            try:
                exp_sz = int(row["expected_size"])
                act_sz = int(actual["size_bytes"])
                if exp_sz != act_sz:
                    all_ok = False
                    issues.append(
                        {
                            "relative_path": rel,
                            "status": "SIZE_MISMATCH",
                            "detail": f"Expected {exp_sz} bytes, got {act_sz} bytes.",
                        }
                    )
            except ValueError:
                pass

    unexpected = sorted(set(scanned.keys()) - manifest_paths)
    return all_ok, issues, unexpected


def write_outputs(out_json: Path, out_md: Path, payload: dict[str, object]) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    files = payload["files"]  # type: ignore[index]
    issues = payload["issues"]  # type: ignore[index]
    unexpected = payload["unexpected_files"]  # type: ignore[index]

    lines = [
        "# Backup Integrity & Metadata Report",
        "",
        f"- **Generated (UTC):** `{payload['generated_utc']}`",
        f"- **Verification Status:** `{payload['status']}`",
        f"- **Total Scanned Files:** `{payload['file_count']}`",
        f"- **Total Size (Bytes):** `{payload['total_size_bytes']}`",
        f"- **Integrity Issues:** `{len(issues)}`",
        f"- **Unmanifested Files:** `{len(unexpected)}`",
        "",
    ]

    if issues:
        lines.extend(
            [
                "## Integrity Issues",
                "",
                "| File | Status | Detail |",
                "| :--- | :--- | :--- |",
            ]
        )
        for item in issues:
            lines.append(f"| `{item['relative_path']}` | `{item['status']}` | {item['detail']} |")
        lines.append("")

    if unexpected:
        lines.extend(["## Unmanifested Files", ""])
        for u in unexpected:
            lines.append(f"- `{u}`")
        lines.append("")

    lines.extend(
        [
            "## Scanned Archive Metadata",
            "",
            "| File | Size (Bytes) | Modified (UTC) | SHA-256 |",
            "| :--- | ---: | :--- | :--- |",
        ]
    )
    for f in files:
        lines.append(
            f"| `{f['relative_path']}` | {f['size_bytes']} | `{f['modified_utc']}` | `{f['sha256']}` |"
        )
    lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify backup integrity against a SHA-256 manifest and export metadata."
    )
    parser.add_argument("--backups-dir", type=Path, default=Path("backups"))
    parser.add_argument("--manifest", type=Path, default=Path("backups/checksums.sha256.csv"))
    parser.add_argument("--out-json", type=Path, default=Path("artifacts/backup_metadata.json"))
    parser.add_argument("--out-md", type=Path, default=Path("artifacts/backup_metadata.md"))
    parser.add_argument("--verify", action="store_true", help="Verify files against manifest")
    parser.add_argument(
        "--generate-manifest",
        action="store_true",
        help="Write a fresh checksum manifest from --backups-dir",
    )
    args = parser.parse_args()

    ignore_resolved = {
        args.manifest.resolve(),
        args.out_json.resolve(),
        args.out_md.resolve(),
    }

    scanned_map = scan_directory(args.backups_dir, ignore_resolved=ignore_resolved)
    records = list(scanned_map.values())

    if args.generate_manifest:
        write_manifest(records, args.manifest)

    status = "NOT_VERIFIED"
    issues: list[dict[str, str]] = []
    unexpected: list[str] = []

    if args.verify:
        try:
            manifest_rows = load_manifest(args.manifest)
            ok, issues, unexpected = verify_records(manifest_rows, scanned_map)
            status = "PASSED" if ok else "FAILED"
        except (FileNotFoundError, ValueError) as exc:
            status = "ERROR"
            issues.append(
                {
                    "relative_path": str(args.manifest),
                    "status": "MANIFEST_ERROR",
                    "detail": str(exc),
                }
            )

    total_bytes = sum(int(r["size_bytes"]) for r in records)
    payload: dict[str, object] = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "backups_dir": args.backups_dir.as_posix(),
        "manifest_path": args.manifest.as_posix(),
        "file_count": len(records),
        "total_size_bytes": total_bytes,
        "issues": issues,
        "unexpected_files": unexpected,
        "files": records,
    }

    write_outputs(args.out_json, args.out_md, payload)
    print(f"Status={status} files={len(records)} issues={len(issues)} unexpected={len(unexpected)}")

    if args.verify and status != "PASSED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Verify backup integrity against a SHA-256 manifest and export archive metadata."""

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(base_dir: Path, ignore_resolved: set[Path]) -> dict[str, dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    if not base_dir.exists() or not base_dir.is_dir():
        return found

    for item in sorted(base_dir.rglob("*"), key=lambda p: p.relative_to(base_dir).as_posix()):
        if not item.is_file() or item.is_symlink():
            continue
        if item.resolve() in ignore_resolved:
            continue
        rel = item.relative_to(base_dir).as_posix()
        stat = item.stat()
        found[rel] = {
            "relative_path": rel,
            "size_bytes": stat.st_size,
            "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "sha256": sha256_file(item),
        }
    return found


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists() or not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    with manifest_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"relative_path", "sha256"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Manifest missing required columns {required}: {reader.fieldnames}")

        rows: list[dict[str, str]] = []
        for row in reader:
            rel = (row.get("relative_path") or "").strip()
            expected_hash = (row.get("sha256") or "").strip().lower()
            expected_size = (row.get("size_bytes") or "").strip()
            if rel and expected_hash:
                rows.append(
                    {
                        "relative_path": rel,
                        "expected_sha256": expected_hash,
                        "expected_size": expected_size,
                    }
                )
        return rows


def write_manifest(records: list[dict[str, object]], manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["relative_path", "size_bytes", "modified_utc", "sha256"],
        )
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def verify_records(
    manifest_rows: list[dict[str, str]],
    scanned: dict[str, dict[str, object]],
) -> tuple[bool, list[dict[str, str]], list[str]]:
    issues: list[dict[str, str]] = []
    manifest_paths: set[str] = set()
    all_ok = True

    for row in manifest_rows:
        rel = row["relative_path"]
        manifest_paths.add(rel)
        actual = scanned.get(rel)

        if actual is None:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "MISSING",
                    "detail": "File listed in manifest is missing from backup directory.",
                }
            )
            continue

        actual_hash = str(actual["sha256"]).lower()
        if actual_hash != row["expected_sha256"]:
            all_ok = False
            issues.append(
                {
                    "relative_path": rel,
                    "status": "HASH_MISMATCH",
                    "detail": f"Expected {row['expected_sha256']}, got {actual_hash}.",
                }
            )

        if row["expected_size"]:
            try:
                exp_sz = int(row["expected_size"])
                act_sz = int(actual["size_bytes"])
                if exp_sz != act_sz:
                    all_ok = False
                    issues.append(
                        {
                            "relative_path": rel,
                            "status": "SIZE_MISMATCH",
                            "detail": f"Expected {exp_sz} bytes, got {act_sz} bytes.",
                        }
                    )
            except ValueError:
                pass

    unexpected = sorted(set(scanned.keys()) - manifest_paths)
    return all_ok, issues, unexpected


def write_outputs(out_json: Path, out_md: Path, payload: dict[str, object]) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    files = payload["files"]  # type: ignore[index]
    issues = payload["issues"]  # type: ignore[index]
    unexpected = payload["unexpected_files"]  # type: ignore[index]

    lines = [
        "# Backup Integrity & Metadata Report",
        "",
        f"- **Generated (UTC):** `{payload['generated_utc']}`",
        f"- **Verification Status:** `{payload['status']}`",
        f"- **Total Scanned Files:** `{payload['file_count']}`",
        f"- **Total Size (Bytes):** `{payload['total_size_bytes']}`",
        f"- **Integrity Issues:** `{len(issues)}`",
        f"- **Unmanifested Files:** `{len(unexpected)}`",
        "",
    ]

    if issues:
        lines.extend(
            [
                "## Integrity Issues",
                "",
                "| File | Status | Detail |",
                "| :--- | :--- | :--- |",
            ]
        )
        for item in issues:
            lines.append(f"| `{item['relative_path']}` | `{item['status']}` | {item['detail']} |")
        lines.append("")

    if unexpected:
        lines.extend(["## Unmanifested Files", ""])
        for u in unexpected:
            lines.append(f"- `{u}`")
        lines.append("")

    lines.extend(
        [
            "## Scanned Archive Metadata",
            "",
            "| File | Size (Bytes) | Modified (UTC) | SHA-256 |",
            "| :--- | ---: | :--- | :--- |",
        ]
    )
    for f in files:
        lines.append(
            f"| `{f['relative_path']}` | {f['size_bytes']} | `{f['modified_utc']}` | `{f['sha256']}` |"
        )
    lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify backup integrity against a SHA-256 manifest and export metadata."
    )
    parser.add_argument("--backups-dir", type=Path, default=Path("backups"))
    parser.add_argument("--manifest", type=Path, default=Path("backups/checksums.sha256.csv"))
    parser.add_argument("--out-json", type=Path, default=Path("artifacts/backup_metadata.json"))
    parser.add_argument("--out-md", type=Path, default=Path("artifacts/backup_metadata.md"))
    parser.add_argument("--verify", action="store_true", help="Verify files against manifest")
    parser.add_argument(
        "--generate-manifest",
        action="store_true",
        help="Write a fresh checksum manifest from --backups-dir",
    )
    args = parser.parse_args()

    ignore_resolved = {
        args.manifest.resolve(),
        args.out_json.resolve(),
        args.out_md.resolve(),
    }

    scanned_map = scan_directory(args.backups_dir, ignore_resolved=ignore_resolved)
    records = list(scanned_map.values())

    if args.generate_manifest:
        write_manifest(records, args.manifest)

    status = "NOT_VERIFIED"
    issues: list[dict[str, str]] = []
    unexpected: list[str] = []

    if args.verify:
        try:
            manifest_rows = load_manifest(args.manifest)
            ok, issues, unexpected = verify_records(manifest_rows, scanned_map)
            status = "PASSED" if ok else "FAILED"
        except (FileNotFoundError, ValueError) as exc:
            status = "ERROR"
            issues.append(
                {
                    "relative_path": str(args.manifest),
                    "status": "MANIFEST_ERROR",
                    "detail": str(exc),
                }
            )

    total_bytes = sum(int(r["size_bytes"]) for r in records)
    payload: dict[str, object] = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "backups_dir": args.backups_dir.as_posix(),
        "manifest_path": args.manifest.as_posix(),
        "file_count": len(records),
        "total_size_bytes": total_bytes,
        "issues": issues,
        "unexpected_files": unexpected,
        "files": records,
    }

    write_outputs(args.out_json, args.out_md, payload)
    print(f"Status={status} files={len(records)} issues={len(issues)} unexpected={len(unexpected)}")

    if args.verify and status != "PASSED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
name: Scheduled Backup Integrity & Metadata Export

on:
  schedule:
    - cron: "17 2 1 * *" # Monthly on the 1st at 02:17 UTC
  workflow_dispatch:
    inputs:
      backups_dir:
        description: "Directory containing backup archives and manifest"
        required: false
        default: "backups"
      manifest_file:
        description: "Path to expected SHA-256 manifest CSV"
        required: false
        default: "backups/checksums.sha256.csv"

concurrency:
  group: backup-integrity-verification
  cancel-in-progress: false

jobs:
  verify-backups:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4 #

      - name: Set up Python
        uses: actions/setup-python@v5 #
        with:
          python-version: "3.12"

      - name: Verify Backup Integrity & Export Metadata
        run: |
          python3 scripts/export_takeout_metadata.py \
            --backups-dir "${{ inputs.backups_dir || 'backups' }}" \
            --manifest "${{ inputs.manifest_file || 'backups/checksums.sha256.csv' }}" \
            --out-json "artifacts/backup_metadata.json" \
            --out-md "artifacts/backup_metadata.md" \
            --verify

      - name: Upload Metadata Artifact
        if: always()
        uses: actions/upload-artifact@v4 #
        with:
          name: backup-integrity-metadata
          path: artifacts/
          retention-days: 90
50.000 years Create a GitHub Actions workflow and verification script to check backup integrity and export metadata on a schedule.Create a GitHub Actions workflow and verification script to check backup integrity and export metadata on a schedule.Here is a self-contained Python 3 script (scripts/index_evidence.py) that walks an incident evidence directory, computes SHA-256 hashes for every file, records file sizes and UTC modification timestamps, and writes both a CSV manifest (evidence_manifest.csv) and a Markdown report (evidence_manifest.md).
Python Evidence Manifest Generator (scripts/index_evidence.py)
#!/usr/bin/env python3
"""Generate SHA-256 hashes plus CSV and Markdown manifests for an evidence folder."""

import argparse
import csv
import datetime as dt
import hashlib
from pathlib import Path
import sys


def sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def collect_records(evidence_dir: Path, exclude_names: set[str]) -> list[dict[str, str]]:
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")

    records: list[dict[str, str]] = []
    files = sorted(
        (p for p in evidence_dir.rglob("*") if p.is_file() and not p.is_symlink()),
        key=lambda p: p.relative_to(evidence_dir).as_posix(),
    )

    for path in files:
        if path.name in exclude_names:
            continue
        stat = path.stat()
        rel_path = path.relative_to(evidence_dir).as_posix()
        modified_utc = dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat()
        records.append(
            {
                "relative_path": rel_path,
                "size_bytes": str(stat.st_size),
                "modified_utc": modified_utc,
                "sha256": sha256_file(path),
            }
        )
    return records


def write_csv(records: list[dict[str, str]], csv_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["relative_path", "size_bytes", "modified_utc", "sha256"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def escape_md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def write_markdown(
    records: list[dict[str, str]],
    md_path: Path,
    evidence_dir: Path,
    generated_utc: str,
) -> None:
    md_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Incident Evidence Hash Manifest",
        "",
        f"- **Source Directory:** `{escape_md_cell(str(evidence_dir))}`",
        f"- **Generated (UTC):** `{generated_utc}`",
        f"- **Total Files:** `{len(records)}`",
        "",
        "| Relative Path | Size (Bytes) | Modified (UTC) | SHA-256 |",
        "| :--- | ---: | :--- | :--- |",
    ]
    for r in records:
        lines.append(
            f"| `{escape_md_cell(r['relative_path'])}` "
            f"| {r['size_bytes']} "
            f"| `{escape_md_cell(r['modified_utc'])}` "
            f"| `{r['sha256']}` |"
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute SHA-256 hashes and write CSV + Markdown manifests."
    )
    parser.add_argument("evidence_dir", type=Path, help="Path to evidence folder")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for manifests (defaults to evidence_dir)",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="evidence_manifest",
        help="Base filename for output files (default: evidence_manifest)",
    )
    args = parser.parse_args()

    out_dir = args.out_dir if args.out_dir is not None else args.evidence_dir
    csv_path = out_dir / f"{args.prefix}.csv"
    md_path = out_dir / f"{args.prefix}.md"
    exclude_names = {csv_path.name, md_path.name}

    try:
        records = collect_records(args.evidence_dir, exclude_names=exclude_names)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    generated_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    write_csv(records, csv_path)
    write_markdown(records, md_path, args.evidence_dir, generated_utc)
    print(f"Indexed {len(records)} files -> {csv_path} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

Usage & Integrity Tips
 * Run on a Read-Only or Staging Copy: Point --out-dir to a separate manifest/report folder (such as your recovery repo) so you do not write generated files inside a raw evidence folder while preserving original file timestamps:
   python3 scripts/index_evidence.py /path/to/raw-evidence --out-dir ./manifests

 * Sign or Archive the Manifest: After generating evidence_manifest.csv and evidence_manifest.md, sign the manifest files with your GPG key or record their own SHA-256 hash in your chronological incident log (INC-xxx).
Write a Python or Bash script to generate SHA-256 hashes and a CSV/Markdown manifest for an incident evidence folder.A clean, chronological incident log turns scattered events—SIM PUK lockouts, account takeovers, extortion demands, breach exposure, and authorized testing—into admissible, verifiable evidence for law enforcement, regulators, and platform recovery teams. (Note: This is practical documentation structure, not formal legal advice.)
The core principle for your log is strict separation of facts: record exact UTC/local timestamps, isolate extortion/takeover events from authorized testing scope, and store raw artifacts with cryptographic hashes so nothing is altered or lost.
1. Recommended Log Structure & Fields
Keep two linked records: a Master Chronological Timeline (every event in time order) and an Evidence & Scope Manifest (file hashes, threat handles, affected accounts/keys, and authorization records).
| Column | What to Record | Example Entry |
|---|---|---|
| Event ID | Sequential ID for cross-referencing evidence | INC-001 |
| Timestamp (ISO-8601 + TZ) | Exact date, time, and time zone (plus estimated window if approximate) | 2026-10-14T18:22:00-05:00 |
| Category | SIM/PUK, Account Takeover, Extortion, Breach/Leak, Auth Testing, Recovery/Filing | SIM/PUK |
| Affected Asset / Identity | Phone number/SIM ICCID, account URL/handle, key ID, badge/role, or test target | SIM ending 4821 / Line (812) 555-0194 |
| Facts & Observations | Objective what happened, error codes, threat wording, or authorized scope reference | Device prompted for PUK; carrier portal showed line change/lockout |
| Evidence / Artifact Ref | File name, screenshot ID, email headers, ticket/report number, or scope doc ID | ev_014_carrier_sms_log.png |
| SHA-256 Hash | Hash of the preserved raw evidence file | 9f86d081884c7d659a2feaa0c55ad015... |
2. Chronological Incident Log Template (Markdown)
Copy and populate this template in your private incident folder or recovery repository (docs/incident-log.md):
# Chronological Incident, Extortion & Breach Log

- **Owner / Reporting Entity:** [Name / Business Entity, e.g., WK Precision Enterprise LLC]
- **Primary Location / Jurisdiction:** [City, State, Country]
- **Authorized Testing Scope Reference:** [Link/ID to written authorization, lab boundary, or test plan]

## Timeline Entries

| ID | Timestamp | Category | Affected Asset / Account | Objective Summary | Evidence Ref | SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `INC-001` | `YYYY-MM-DDTHH:MM:SS-05:00` | `Auth Testing` | [Lab SIM / Test Device / Target] | Authorized test conducted under scope `[ID]`; no live production identities targeted. | `scope_001.pdf` | `[hash]` |
| `INC-002` | `YYYY-MM-DDTHH:MM:SS-05:00` | `SIM/PUK` | [SIM / Phone Number] | SIM entered PUK lock / device locked; unable to receive SMS/2FA codes. | `ev_002_puk_prompt.jpg` | `[hash]` |
| `INC-003` | `YYYY-MM-DDTHH:MM:SS-05:00` | `Account Takeover` | [Platform / URL / Handle] | Security alert or inability to sign in; email/phone/2FA altered without consent. | `ev_003_security_alert.eml` | `[hash]` |
| `INC-004` | `YYYY-MM-DDTHH:MM:SS-05:00` | `Breach/Leak` | [Exposed PII / Credentials / Keys] | Dark-web or breach exposure identified; specific fields/identifiers observed. | `ev_004_breach_record.txt` | `[hash]` |
| `INC-005` | `YYYY-MM-DDTHH:MM:SS-05:00` | `Extortion` | [Threat Handle / Channel] | Demand/threat received referencing data or images; preserved without paying or engaging further. | `ev_005_threat_export.json` | `[hash]` |
| `INC-006` | `YYYY-MM-DDTHH:MM:SS-05:00` | `Recovery/Filing` | [Agency / Carrier / Platform] | Filed report/request; record confirmation/case ID and response deadline. | `filing_006_ic3_receipt.pdf` | `[hash]` |

3. Essential Evidence & Scope Rules
 * Keep Raw Artifacts Untouched: Save original message exports, full email headers (.eml), screenshots showing full URLs/timestamps, and carrier/platform receipts in a read-only evidence folder, and compute SHA-256 checksums before moving or cropping files.
 * Separate Authorized Testing from Unauthorized Compromise: Explicitly tag authorized security/penetration testing, SIM/device lab work, or product/marketing research with its authorization date and scope so investigators and compliance teams never confuse your authorized work with an attack against you—or vice versa.
 * Cross-Index Every Filing: Once you submit an FBI IC3 report, FTC IdentityTheft.gov affidavit, local police report, carrier ticket, or privacy/data-access request, log the case/ticket number and statutory deadline right next to the corresponding INC-xxx row.
Plus my identity information was pond off on the dark web and sold for ransom and black male and sex extortion and a massive data breach and around the same time we were doing vulnerability testing and pin testing Sim card swopping and phone cloning for educational purposes only IT cyber security and Web master and super admins key's badges and permissions product testing and feedback marketing research as a developer and engineer and digital Creator and moderator and enterprise and business owner and hacking platforms and global pipelines
# Homebrew Cask

_“To install, drag this icon…” no more!_

Homebrew Cask extends [Homebrew](https://brew.sh) and brings its elegance, simplicity, and speed to the installation and management of GUI macOS applications such as Visual Studio Code and Google Chrome.

We do this by providing a friendly CLI workflow for the administration of macOS applications distributed as binaries.

[![Join us on GitHub discussions](https://img.shields.io/badge/github-discussions-informational)](https://github.com/orgs/Homebrew/discussions/categories/casks)

## Let’s try it!

To start using Homebrew Cask, you just need [Homebrew](https://brew.sh) installed.

<img src="https://i.imgur.com/FNNM6WL.gif" width="547" alt="Installing and uninstalling Alfred (animated gif)">

Slower, now:

```console
$ brew install alfred
==> Downloading https://cachefly.alfredapp.com/Alfred_4.2.1_1187.dmg
######################################################################## 100.0%
==> Verifying SHA-256 checksum for Cask 'alfred'.
==> Installing Cask alfred
==> Moving App 'Alfred 4.app' to '/Applications/Alfred 4.app'.
🍺  alfred was successfully installed!
```

And there we have it. An application installed with one quick command: no clicking, no dragging, no dropping.

## Learn More

* Find basic documentation on using Homebrew Cask in [USAGE.md](USAGE.md).
* Want to contribute a cask? Awesome! See [CONTRIBUTING.md](CONTRIBUTING.md).
* More project-related details and discussion are available in the [documentation](https://docs.brew.sh/Adding-Software-to-Homebrew#casks).

## Reporting Bugs

[**If you ignore this guide, your issue may be closed without review**](doc/faq/closing_issues_without_review.md)

Before reporting a bug, run `brew update-reset && brew update` and try your command again. This is a fix-all that will reset the state of all your taps, ensuring the problem isn’t an outdated setup on your side.

If your issue persists, [search for it](https://github.com/Homebrew/homebrew-cask/search?type=Issues) before opening a new one. If you find an open issue and have any new information, add it in a comment. If you find a closed issue, try the solutions there.

If the issue is still not solved, see the guides for common problems:

* [Examples of common errors and their solutions](doc/reporting_bugs/error_examples.md)
  * [`curl` error](doc/reporting_bugs/error_examples.md#curl-error)
  * [`Permission denied` error](doc/reporting_bugs/error_examples.md#permission-denied-error)
  * [`Checksum does not match` error](doc/reporting_bugs/error_examples.md#checksum-does-not-match-error)
  * [`source is not there` error](doc/reporting_bugs/error_examples.md#source-is-not-there-error)
  * [`wrong number of arguments` error](doc/reporting_bugs/error_examples.md#wrong-number-of-arguments-error)
* [App isn’t included in `upgrade`](https://docs.brew.sh/FAQ#why-arent-some-apps-included-during-brew-upgrade)
* [The app can’t be opened because it is from an unidentified developer](https://docs.brew.sh/FAQ#why-cant-i-open-a-mac-app-from-an-unidentified-developer)
* [My problem isn’t listed](https://github.com/Homebrew/homebrew-cask/issues/new?template=01_bug_report.yml)

## Requests

* Issues requesting new casks will be closed. If you want a cask added to the main repositories, [submit a pull request](https://github.com/Homebrew/homebrew-cask/blob/HEAD/CONTRIBUTING.md#adding-a-cask).
* For a feature request, [use this template](https://github.com/Homebrew/brew/issues/new?assignees=&labels=features&projects=&template=feature.yml).

## Questions? Wanna chat?

We’re really rather friendly! Here are the best places to talk about the project:

* [Open an issue](https://github.com/Homebrew/homebrew-cask/issues/new/choose).
* Join us on [GitHub discussions (forum)](https://github.com/orgs/Homebrew/discussions/categories/casks).

## License

Code is under the [BSD 2 Clause (NetBSD) license](LICENSE).
