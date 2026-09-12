"""Read-only Windows security observations, never configuration changes.

Hotfix history is inventory, not proof that Windows is fully patched. Third-
party antivirus may legitimately disable Defender; inaccessible facts remain
unknown rather than being represented as secure or compromised.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from .common import utc_now

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$result = [ordered]@{}
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $result.defender = @{
        available = $true
        antivirus_enabled = [bool]$status.AntivirusEnabled
        realtime_enabled = [bool]$status.RealTimeProtectionEnabled
        signature_age_days = $status.AntivirusSignatureAge
        signature_updated_at = [string]$status.AntivirusSignatureLastUpdated
    }
} catch { $result.defender = @{ available = $false; reason = 'Defender status unavailable' } }
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled)
    $result.firewall = @{ available = $true; profiles = $profiles }
} catch { $result.firewall = @{ available = $false; reason = 'Firewall status unavailable' } }
try {
    $latest = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $result.updates = @{
        available = $true
        latest_hotfix_id = [string]$latest.HotFixID
        latest_installed_at = [string]$latest.InstalledOn
        pending_updates_checked = $false
    }
} catch { $result.updates = @{ available = $false; reason = 'Hotfix history unavailable' } }
$result | ConvertTo-Json -Depth 6 -Compress
"""


class SystemInspector:
    def inspect(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "timestamp": utc_now(), "platform": platform.system(),
            "supported": platform.system() == "Windows", "checks": {},
            "note": "Read-only observations; update history does not establish patch compliance.",
        }
        if not result["supported"]:
            result["error"] = "Windows 10 and Windows 11 are required for system security inspection."
            return result
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        try:
            completed = subprocess.run(
                [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=15, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode:
                result["error"] = "The read-only PowerShell inspection failed."
                return result
            checks = json.loads(completed.stdout.lstrip("\ufeff"))
            if not isinstance(checks, dict):
                raise ValueError("Unexpected inspection response")
            result["checks"] = checks
        except subprocess.TimeoutExpired:
            result["error"] = "The system inspection exceeded its 15-second timeout."
        except (OSError, ValueError):
            result["error"] = "PowerShell or its inspection response is unavailable."
        return result
