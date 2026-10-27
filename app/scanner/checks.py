"""Read-only Linux security configuration checks."""

import re
import shutil
import subprocess
from pathlib import Path

SCANNER_NAME = "Linux Security Configuration Auditor"
SCANNER_VERSION = "0.3.0"


def run_command(command: list[str]) -> str | None:
    """Run a read-only command and return output on success."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def finding(
    check_id: str,
    title: str,
    status: str,
    severity: str,
    evidence: str,
    recommendation: str,
) -> dict:
    """Build a consistent security finding."""
    return {
        "check_id": check_id,
        "title": title,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def check_firewall() -> dict:
    """Check firewall indicators without assuming missing tools mean no firewall."""
    if shutil.which("ufw"):
        output = run_command(["ufw", "status"])
        if output:
            first_line = output.splitlines()[0].strip().lower()

            if first_line == "status: active":
                return finding(
                    "LINUX-001", "Host firewall", "REVIEW", "MEDIUM",
                    "UFW reports an active firewall; rule effectiveness has not been evaluated.",
                    "Inspect the active rules, default policies, allowed traffic, and IPv6 configuration.",
           )

            if first_line == "status: inactive":
                return finding(
                    "LINUX-001", "Host firewall", "REVIEW", "MEDIUM",
                    "UFW reports inactive; another firewall may still provide protection.",
                    "Inspect other firewall layers and confirm the intended policy.",
                )

    if shutil.which("firewall-cmd"):
        state = run_command(["firewall-cmd", "--state"])
        if state == "running":
            return finding(
                "LINUX-001", "Host firewall", "REVIEW", "MEDIUM",
                "firewalld is running; active zones and rule effectiveness have not been evaluated.",
                "Inspect active zones, firewall rules, default policies, and allowed traffic.",
         )

    if shutil.which("nft"):
        output = run_command(["nft", "list", "ruleset"])
        if output:
            return finding(
                "LINUX-001", "Host firewall", "REVIEW", "MEDIUM",
                "An nftables ruleset is readable; its effectiveness has not been evaluated.",
                "Review rules, default policies, and allowed traffic.",
            )

    if shutil.which("iptables"):
        output = run_command(["iptables", "-S"])
        if output:
            rules = [
                line for line in output.splitlines()
                if line.startswith(("-A ", "-P "))
            ]
            if rules:
                return finding(
                    "LINUX-001", "Host firewall", "REVIEW", "MEDIUM",
                    f"iptables returned {len(rules)} policy or rule entries.",
                    "Review default policies, rules, and IPv6 firewall configuration.",
                )

    return finding(
        "LINUX-001", "Host firewall", "UNKNOWN", "MEDIUM",
        "Firewall protection could not be verified using available supported tools.",
        "Inspect host and network firewall protection. In WSL, consider the Windows host firewall too.",
    )


def check_ssh_setting(setting: str, check_id: str, title: str) -> dict:
    """Inspect effective SSH daemon configuration when available."""
    sshd = shutil.which("sshd")

    if not sshd:
        return finding(
            check_id, title, "UNKNOWN", "MEDIUM",
            "The sshd executable was not found; an SSH server may not be installed.",
            "If this host runs an SSH server, inspect its configuration. Otherwise, document this check as not applicable.",
        )

    output = run_command([sshd, "-T"])
    if not output:
        return finding(
            check_id, title, "UNKNOWN", "MEDIUM",
            "The effective SSH configuration could not be read.",
            "Check the server configuration and rerun with appropriate permissions.",
        )

    settings = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip().lower()

    value = settings.get(setting)
    if value is None:
        return finding(
            check_id, title, "UNKNOWN", "MEDIUM",
            f"The effective setting {setting!r} was not reported.",
            "Inspect the effective SSH configuration manually.",
        )

    if setting == "permitrootlogin":
        if value == "no":
            return finding(
                check_id, title, "PASS", "INFO",
                f"Effective {setting}: {value}",
                "Maintain the restriction on direct root SSH access.",
            )

        if value in {"prohibit-password", "without-password"}:
            return finding(
                check_id, title, "REVIEW", "MEDIUM",
                f"Effective {setting}: {value}. Password-based root login is restricted, "
                "but public-key root login may still be allowed.",
                "Review whether direct root SSH access is required. Prefer disabling it "
                "with PermitRootLogin no when appropriate for your access policy.",
           )

        passed = False
        recommendation = "Review and restrict direct root SSH access where appropriate."
    elif setting == "passwordauthentication":
        passed = value == "no"
        recommendation = (
            "Verify alternative administrative access and recovery methods."
            if passed else
            "Review whether key-based authentication is appropriate before changing settings."
        )
    else:
        return finding(
            check_id, title, "UNKNOWN", "MEDIUM",
            f"No evaluation rule exists for {setting!r}.",
            "Review this setting manually.",
        )

    return finding(
        check_id, title,
        "PASS" if passed else "FAIL",
        "INFO" if passed else "HIGH",
        f"Effective {setting}: {value}",
        recommendation,
    )


def read_apt_setting(path: str, setting: str) -> str | None:
    """Read an APT setting from a typical apt.conf.d file."""
    try:
        content = Path(path).read_text(errors="replace")
    except OSError:
        return None

    pattern = (
        r"^\s*" + re.escape(setting)
        + r'\s+"?([^";\s]+)"?\s*;'
    )
    matches = re.findall(pattern, content, flags=re.MULTILINE)
    return matches[-1] if matches else None


def check_automatic_updates() -> dict:
    """Inspect common APT automatic-update configuration."""
    config = "/etc/apt/apt.conf.d/20auto-upgrades"

    if not Path(config).is_file():
        return finding(
            "LINUX-004", "Automatic security updates", "UNKNOWN", "MEDIUM",
            "The common APT automatic-update configuration file was not found.",
            "Identify the distribution's update mechanism and inspect its security-update policy.",
        )

    package_lists = read_apt_setting(
        config, "APT::Periodic::Update-Package-Lists"
    )
    unattended = read_apt_setting(
        config, "APT::Periodic::Unattended-Upgrade"
    )

    if package_lists == "1" and unattended == "1":
        return finding(
            "LINUX-004", "Automatic security updates", "PASS", "INFO",
            "APT package-list updates and unattended upgrades are enabled in the inspected configuration; successful installation was not verified.",
            "Check update logs and verify that security updates install successfully.",
        )

    return finding(
        "LINUX-004", "Automatic security updates", "REVIEW", "MEDIUM",
        f"APT Update-Package-Lists={package_lists!r}; Unattended-Upgrade={unattended!r}.",
        "Review automatic-update configuration and patching policy.",
    )


def check_sensitive_file_permissions() -> dict:
    """Check ownership and permission bits on sensitive account files."""
    paths = ["/etc/passwd", "/etc/shadow"]
    details = []

    for name in paths:
        try:
            info = Path(name).stat()
        except OSError:
            return finding(
                "LINUX-005",
                "Sensitive file permissions",
                "UNKNOWN",
                "MEDIUM",
                f"Could not inspect {name}.",
                "Check that the file exists and can be inspected with appropriate permissions.",
            )

        mode = info.st_mode & 0o777
        owner = info.st_uid
        details.append(
            f"{name}: mode={mode:04o}, owner_uid={owner}"
        )

        if owner != 0:
            return finding(
                "LINUX-005",
                "Sensitive file permissions",
                "REVIEW",
                "HIGH",
                "; ".join(details)
                + f"; {name} is not owned by root.",
                "Investigate unexpected ownership and compare with distribution security guidance.",
            )

        if name == "/etc/passwd":
            if mode & 0o022:
                return finding(
                    "LINUX-005",
                    "Sensitive file permissions",
                    "FAIL",
                    "HIGH",
                    "; ".join(details)
                    + "; /etc/passwd is group- or world-writable.",
                    "Investigate the writable permissions and compare them with distribution security guidance.",
                )

        elif name == "/etc/shadow":
            if mode & 0o007:
                return finding(
                    "LINUX-005",
                    "Sensitive file permissions",
                    "FAIL",
                    "HIGH",
                    "; ".join(details)
                    + "; /etc/shadow grants permissions to other users.",
                    "Restrict access to /etc/shadow according to distribution security guidance.",
                )

            if mode & 0o020:
                return finding(
                    "LINUX-005",
                    "Sensitive file permissions",
                    "FAIL",
                    "HIGH",
                    "; ".join(details)
                    + "; /etc/shadow is group-writable.",
                    "Investigate group-write access and compare with distribution security guidance.",
                )

    return finding(
        "LINUX-005",
        "Sensitive file permissions",
        "PASS",
        "INFO",
        "; ".join(details)
        + "; ownership and selected permission checks passed.",
        "Continue monitoring sensitive account files and compare their permissions with distribution security guidance.",
    )


def check_failed_login_records() -> dict:
    """Inspect recent failed-login messages when system logs are available."""
    journalctl = shutil.which("journalctl")

    if not journalctl:
        return finding(
            "LINUX-006", "Failed login records", "UNKNOWN", "MEDIUM",
            "journalctl is unavailable; failed-login records could not be inspected using the supported method.",
            "Inspect the distribution's authentication logs or configure an approved log source.",
        )

    output = run_command([
        journalctl, "--no-pager", "-n", "300", "-o", "cat",
        "SYSLOG_IDENTIFIER=sshd",
    ])

    if output is None:
        return finding(
            "LINUX-006", "Failed login records", "UNKNOWN", "MEDIUM",
            "SSH journal records could not be read. Logs may be unavailable or access may be restricted.",
            "Check journal availability and permissions. Do not interpret missing records as proof that no failed logins occurred.",
        )

    lines = [
        line for line in output.splitlines()
        if re.search(r"failed password|authentication failure|invalid user", line, re.I)
    ]

    return finding(
        "LINUX-006", "Failed login records", "REVIEW" if lines else "UNKNOWN",
        "MEDIUM",
        (
            f"Found {len(lines)} matching failed-login or invalid-user messages among the available SSH journal records."
            if lines else
            "No matching messages were found in the available SSH journal records; this does not prove that no failed logins occurred."
        ),
        "Investigate repeated failures and enable suitable authentication logging. This check does not identify unique attackers or prove an attack.",
    )


def check_listening_ports() -> dict:
    """List listening TCP/UDP sockets without assuming they are vulnerabilities."""
    ss = shutil.which("ss")

    if not ss:
        return finding(
            "LINUX-007", "Listening network ports", "UNKNOWN", "MEDIUM",
            "The ss utility is unavailable, so listening sockets could not be inspected.",
            "Install or provide an approved socket-inspection utility, then rerun the audit.",
        )

    output = run_command([ss, "-H", "-lntu"])
    if output is None:
        return finding(
            "LINUX-007", "Listening network ports", "UNKNOWN", "MEDIUM",
            "The listening-socket query failed.",
            "Check utility availability and rerun the audit.",
        )

    lines = output.splitlines()
    sample = "; ".join(lines[:10])
    if len(lines) > 10:
        sample += f"; and {len(lines) - 10} more entries"

    return finding(
        "LINUX-007", "Listening network ports", "REVIEW", "LOW",
        f"Found {len(lines)} listening TCP/UDP socket entries."
        + (f" Sample: {sample}" if sample else " No listening sockets were reported."),
        "Verify that each listening service is expected and appropriately restricted. A listening port alone is not proof of a vulnerability.",
    )


def check_disk_space() -> dict:
    """Check available space on the root filesystem."""
    try:
        usage = shutil.disk_usage("/")
    except OSError as exc:
        return finding(
            "LINUX-008", "Root filesystem space", "UNKNOWN", "LOW",
            f"Disk usage could not be inspected: {exc.__class__.__name__}.",
            "Check filesystem availability and rerun the audit.",
        )

    total = usage.total
    free = usage.free
    used_percent = ((total - free) / total * 100) if total else 0
    free_percent = (free / total * 100) if total else 0
    evidence = (
        f"Root filesystem: {used_percent:.1f}% used, "
        f"{free_percent:.1f}% available ({free // (1024 ** 3)} GiB free)."
    )

    if free_percent < 5:
        return finding(
            "LINUX-008", "Root filesystem space", "FAIL", "HIGH",
            evidence,
            "Investigate disk usage and safely free space; ensure security logs can continue to be written.",
        )

    if free_percent < 15:
        return finding(
            "LINUX-008", "Root filesystem space", "REVIEW", "MEDIUM",
            evidence,
            "Monitor disk usage and plan safe cleanup or capacity expansion.",
        )

    return finding(
        "LINUX-008", "Root filesystem space", "PASS", "INFO",
        evidence,
        "Continue monitoring disk usage to protect service and logging availability.",
    )


def run_security_checks() -> dict:
    """Run checks and summarize their results."""
    checks = [
        check_firewall(),
        check_ssh_setting(
            "permitrootlogin", "LINUX-002", "SSH root login restriction"
        ),
        check_ssh_setting(
            "passwordauthentication", "LINUX-003", "SSH password authentication"
        ),
        check_automatic_updates(),
        check_sensitive_file_permissions(),
        check_failed_login_records(),
        check_listening_ports(),
        check_disk_space(),
    ]

    return {
        "scanner": SCANNER_NAME,
        "version": SCANNER_VERSION,
        "checks_run": len(checks),
        "summary": {
            status.lower(): sum(
                item["status"] == status for item in checks
            )
            for status in ("PASS", "FAIL", "REVIEW", "UNKNOWN")
        },
        "findings": checks,
    }
