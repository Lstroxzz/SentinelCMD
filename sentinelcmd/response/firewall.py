"""Local Windows Firewall rules, limited to SentinelCMD's own rule group.

No DNS lookups, probing, remote sessions, firewall disablement or global policy
changes are performed. Elevated rights are required to add/remove local rules.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess


RULE_PREFIX = "SentinelCMD-"
RULE_GROUP = "SentinelCMD"
RULE_PATTERN = re.compile(r"SentinelCMD-[0-9a-f]{32}\Z")
_PREAMBLE = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module NetSecurity -ErrorAction Stop
"""

_LIST_SCRIPT = (
    _PREAMBLE
    + """
$owned = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Where-Object { $_.Name -cmatch '^SentinelCMD-[0-9a-f]{32}$' -and $_.Group -ceq 'SentinelCMD' })
$result = @($owned | ForEach-Object {
    $r = $_
    $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
    [PSCustomObject]@{ id = $r.Name; name = $r.DisplayName; group = $r.Group;
        direction = [string]$r.Direction; action = [string]$r.Action;
        enabled = [string]$r.Enabled; remote_addresses = @($addresses.RemoteAddress);
        description = $r.Description }
})
ConvertTo-Json -InputObject @($result) -Depth 5 -Compress
"""
)

_BLOCK_SCRIPT = (
    _PREAMBLE
    + """
$name = $env:SENTINEL_RULE_ID
$ip = $env:SENTINEL_REMOTE_IP
$existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Where-Object { $_.Name -ceq $name })
$created = $false
if ($existing.Count -gt 1) { throw 'Ambiguous firewall rule identity.' }
if ($existing.Count -eq 1) {
    $r = $existing[0]
    if ($r.Group -cne 'SentinelCMD') { throw 'Refusing to change a foreign firewall rule.' }
    $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
    $remote = @($addresses.RemoteAddress)
    if ([string]$r.Direction -ne 'Outbound' -or [string]$r.Action -ne 'Block' -or
        [string]$r.Profile -ne 'Any' -or
        [string]$r.Enabled -ne 'True' -or $remote.Count -ne 1 -or
        [IPAddress]::Parse([string]$remote[0]) -ne [IPAddress]::Parse($ip)) {
        throw 'An existing rule has different settings; manual investigation is required.'
    }
} else {
    New-NetFirewallRule -Name $name -DisplayName ('SentinelCMD block ' + $ip) `
        -Group 'SentinelCMD' -Description $env:SENTINEL_RULE_REASON `
        -Direction Outbound -Action Block -RemoteAddress $ip -Protocol Any `
        -Profile Any -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
    $created = $true
}
[PSCustomObject]@{ status = 'blocked'; id = $name; ip = $ip; direction = 'Outbound';
    action = 'Block'; created = $created; group = 'SentinelCMD' } | ConvertTo-Json -Compress
"""
)

_REMOVE_SCRIPT = (
    _PREAMBLE
    + """
$name = $env:SENTINEL_RULE_ID
$existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
    Where-Object { $_.Name -ceq $name })
if ($existing.Count -gt 1) { throw 'Ambiguous firewall rule identity.' }
if ($existing.Count -eq 0) {
    [PSCustomObject]@{ status = 'not_found'; id = $name; removed = $false } | ConvertTo-Json -Compress
} else {
    $r = $existing[0]
    if ($r.Group -cne 'SentinelCMD' -or $r.Name -cnotmatch '^SentinelCMD-[0-9a-f]{32}$') {
        throw 'Refusing to remove a foreign firewall rule.'
    }
    $r | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop
    [PSCustomObject]@{ status = 'removed'; id = $name; removed = $true } | ConvertTo-Json -Compress
}
"""
)


def validate_public_ip(value: str) -> str:
    """Accept only one literal, globally routable, unicast IP; never resolve DNS."""
    if not isinstance(value, str) or "%" in value or "/" in value:
        raise ValueError("Use one public IP literal without a scope or network prefix.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("Invalid IP address; hostnames are not accepted.") from error
    if (
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_private
    ):
        raise ValueError("Only public global unicast IP addresses may be blocked.")
    # Translation/tunneling addresses have ambiguous IPv4 policy semantics.
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None
    ):
        raise ValueError("Mapped/tunneled IPv6 addresses are not supported.")
    return str(address)


class FirewallManager:
    """Explicit outgoing blocks persisted in Windows Firewall.

    ``blocked`` means a local enabled block rule exists, not that all traffic was
    intercepted: Windows Firewall must remain enabled and domain policy may
    override local rules. This does not disconnect an entire endpoint.
    """

    def __init__(self, timeout: float = 20):
        self.timeout = timeout

    def _run(self, script: str, parameters: dict[str, str] | None = None):
        if os.name != "nt":
            raise OSError("Windows Firewall management is available only on Windows.")
        executable = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        environment = os.environ.copy()
        environment.update(parameters or {})
        command = [
            str(executable),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(script.encode("utf-16le")).decode("ascii"),
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                shell=False,
                env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as error:
            raise OSError("Firewall operation timed out; inspect owned rules before retrying.") from error
        if result.returncode:
            raise OSError(f"Windows Firewall operation failed: {result.stderr.strip()[:2000]}")
        try:
            return json.loads(result.stdout.lstrip("\ufeff").strip())
        except json.JSONDecodeError as error:
            raise OSError(
                "Windows Firewall returned an invalid response; verify the local rule state."
            ) from error

    def list_rules(self) -> list[dict]:
        result = self._run(_LIST_SCRIPT)
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise OSError("Windows Firewall returned an unexpected rule list.")
        return [
            item
            for item in result
            if RULE_PATTERN.fullmatch(str(item.get("id", ""))) and item.get("group") == RULE_GROUP
        ]

    def block_ip(self, ip: str, reason: str = "") -> dict:
        address = validate_public_ip(ip)
        rule_id = RULE_PREFIX + hashlib.sha256(("outbound:" + address).encode("ascii")).hexdigest()[:32]
        result = self._run(
            _BLOCK_SCRIPT,
            {
                "SENTINEL_RULE_ID": rule_id,
                "SENTINEL_REMOTE_IP": address,
                "SENTINEL_RULE_REASON": str(reason).replace("\x00", "")[:512],
            },
        )
        if (
            not isinstance(result, dict)
            or result.get("status") != "blocked"
            or result.get("id") != rule_id
            or result.get("ip") != address
            or result.get("group") != RULE_GROUP
        ):
            raise OSError("Firewall result could not be verified; inspect owned rules.")
        return result

    def remove_rule(self, rule_id: str) -> dict:
        if not isinstance(rule_id, str) or not RULE_PATTERN.fullmatch(rule_id):
            raise ValueError("Only exact SentinelCMD rule IDs may be removed.")
        result = self._run(_REMOVE_SCRIPT, {"SENTINEL_RULE_ID": rule_id})
        if (
            not isinstance(result, dict)
            or result.get("id") != rule_id
            or result.get("status") not in {"removed", "not_found"}
        ):
            raise OSError("Firewall removal result could not be verified; inspect owned rules.")
        return result
