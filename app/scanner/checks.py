"""Read-only Linux security configuration checks."""

import re
import shutil
import subprocess
from pathlib import Path


SCANNER_NAME = "Linux Security Configuration Auditor"
SCANNER_VERSION = "0.2.0"


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
    # UFW is commonly used on Ubuntu.
    if shutil.which("ufw"):
        output = run_command(["ufw", "status"])

        if output:
            first_line = output.splitlines()[0]

            if first_line.strip().lower() == "status: active":
                return finding(
                    "LINUX-001",
                    "Host firewall",
                    "PASS",
                    "INFO",
                    "UFW reports an active firewall.",
                    "Review the active rules periodically and verify that they match your security policy.",
                )

            if first_line.strip().lower() == "status: inactive":
                return finding(
                    "LINUX-001",
                    "Host firewall",
                    "REVIEW",
                    "MEDIUM",
                    "UFW reports inactive. This alone does not establish whether another firewall is protecting the host.",
                    "Inspect other firewall layers and confirm the intended host firewall policy.",
                )

    # firewalld is used by some Linux distributions.
    if shutil.which("firewall-cmd"):
        state = run_command(["firewall-cmd", "--state"])

        if state == "running":
            return finding(
                "LINUX-001",
                "Host firewall",
                "PASS",
                "INFO",
                "firewalld reports that it is running.",
                "Inspect the active zones and rules to confirm the intended protection.",
            )

    # nft can provide evidence that nftables rules are configured.
    if shutil.which("nft"):
        output = run_command(["nft", "list", "ruleset"])

        if output:
            if "table " in output and "chain " in output:
                return finding(
                    "LINUX-001",
                    "Host firewall",
                    "REVIEW",
                    "MEDIUM",
                    "An nftables ruleset is present. Its effectiveness has not been evaluated.",
                    "Review the ruleset, default policies, and allowed traffic before deciding whether the firewall meets policy.",
                )

            return finding(
                "LINUX-001",
                "Host firewall",
                "REVIEW",
                "MEDIUM",
                "The nftables ruleset was readable, but no clear table-and-chain structure was detected.",
                "Inspect the active ruleset and confirm whether firewall rules are required.",
            )

    # iptables is available on some systems.
    if shutil.which("iptables"):
        output = run_command(["iptables", "-S"])

        if output:
            rules = [
                line for line in output.splitlines()
                if line.startswith(("-A ", "-P "))
            ]

            if rules:
                return finding(
                    "LINUX-001",
                    "Host firewall",
                    "REVIEW",
                    "MEDIUM",
                    f"iptables returned {len(rules)} policy or rule entries. Their effectiveness has not been evaluated.",
                    "Review default policies and rules, including any IPv6 firewall configuration.",
                )

    return finding(
        "LINUX-001",
        "Host firewall",
        "UNKNOWN",
        "MEDIUM",
        "The scanner could not verify firewall protection using its available supported tools. This does not prove that no firewall exists.",
        "Inspect the host firewall and any additional network protection. In WSL, consider the separate Windows host firewall as well.",
    )


def check_ssh_setting(setting: str, check_id: str, title: str) -> dict:
    """Inspect the effective SSH daemon configuration when available."""
    sshd = shutil.which("sshd")

    if not sshd:
        return finding(
            check_id,
            title,
            "UNKNOWN",
            "MEDIUM",
            "The OpenSSH server executable (sshd) was not found. An SSH server may not be installed; the SSH client can exist independently.",
            "If this machine is intended to run an SSH server, install and inspect the server configuration. Otherwise, document this check as not applicable to the current role.",
        )

    output = run_command([sshd, "-T"])

    if not output:
        return finding(
            check_id,
            title,
            "UNKNOWN",
            "MEDIUM",
            "The effective SSH server configuration could not be read. The command may require additional permissions or valid configuration.",
            "Check the SSH server installation and configuration, then rerun the audit with appropriate permissions.",
        )

    settings = {}

    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip().lower()

    value = settings.get(setting)

    if value is None:
        return finding(
            check_id,
            title,
            "UNKNOWN",
            "MEDIUM",
            f"The effective setting '{setting}' was not reported.",
            "Review the effective SSH server configuration and confirm that the setting can be evaluated.",
        )

    if setting == "permitrootlogin":
        passed = value in {
            "no",
            "prohibit-password",
            "without-password",
        }
        evidence = f"Effective PermitRootLogin: {value}"
        recommendation = (
            "Maintain restricted direct root SSH access."
            if passed
            else "Review the need for direct root SSH access and restrict it where appropriate."
        )

    elif setting == "passwordauthentication":
        passed = value == "no"
        evidence = f"Effective PasswordAuthentication: {value}"
        recommendation = (
            "Verify that administrators have working alternative access and recovery methods."
            if passed
            else "Review whether key-based authentication is appropriate. Confirm alternative access before changing settings."
        )

    else:
        return finding(
            check_id,
            title,
            "UNKNOWN",
            "MEDIUM",
            f"No evaluation rule exists for '{setting}'.",
            "Review this setting manually.",
        )

    return finding(
        check_id,
        title,
        "PASS" if passed else "FAIL",
        "INFO" if passed else "HIGH",
        evidence,
        recommendation,
    )


def read_apt_setting(path: str, setting: str) -> str | None:
    """Read an APT setting from a typical apt.conf.d file."""
    try:
        content = Path(path).read_text(errors="replace")
    except OSError:
        return None

    pattern = (
        r"^\s*"
        + re.escape(setting)
        + r'\s+"?([^";\s]+)"?\s*;'
    )

    matches = re.findall(pattern, content, flags=re.MULTILINE)
    return matches[-1] if matches else None


def check_automatic_updates() -> dict:
    """Inspect common APT automatic-update configuration."""
    config = "/etc/apt/apt.conf.d/20auto-upgrades"

    if Path(config).is_file():
        package_lists = read_apt_setting(
            config, "APT::Periodic::Update-Package-Lists"
        )
        unattended = read_apt_setting(
            config, "APT::Periodic::Unattended-Upgrade"
        )

        if package_lists == "1" and unattended == "1":
            return finding(
                "LINUX-004",
                "Automatic security updates",
                "PASS",
                "INFO",
                "APT package-list updates and unattended upgrades are enabled in the inspected configuration. Successful installation has not been verified.",
                "Check update logs and confirm that security updates are being installed successfully.",
            )

        return finding(
            "LINUX-004",
            "Automatic security updates",
            "REVIEW",
            "MEDIUM",
            f"APT Update-Package-Lists={package_lists!r}; Unattended-Upgrade={unattended!r}.",
            "Review the automatic-update configuration and your organization's patching policy.",
        )

    return finding(
        "LINUX-004",
        "Automatic security updates",
        "UNKNOWN",
        "MEDIUM",
        "The common APT automatic-update configuration file was not found.",
        "Identify the distribution's update mechanism and inspect its security-update policy.",
    )


def run_security_checks() -> dict:
    """Run available checks and summarize their results."""
    checks = [
        check_firewall(),
        check_ssh_setting(
            "permitrootlogin",
            "LINUX-002",
            "SSH root login restriction",
        ),
        check_ssh_setting(
            "passwordauthentication",
            "LINUX-003",
            "SSH password authentication",
        ),
        check_automatic_updates(),
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
