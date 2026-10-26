from fastapi.testclient import TestClient

from app.main import app
from app.scanner.checks import (
    finding,
    read_apt_setting,
    run_security_checks,
)

client = TestClient(app)


def test_finding_structure():
    item = finding(
        "TEST-001",
        "Example",
        "PASS",
        "INFO",
        "Evidence",
        "Recommendation",
    )

    assert item["check_id"] == "TEST-001"
    assert item["status"] == "PASS"
    assert item["evidence"] == "Evidence"


def test_scanner_returns_eighthecks():
    result = run_security_checks()

    assert result["scanner"] == "Linux Security Configuration Auditor"
    assert result["checks_run"] == 8
    assert len(result["findings"]) == 8


def test_scanner_statuses_are_valid():
    result = run_security_checks()
    allowed = {"PASS", "FAIL", "REVIEW", "UNKNOWN"}

    for item in result["findings"]:
        assert item["status"] in allowed
        assert item["check_id"]
        assert item["title"]
        assert item["evidence"]
        assert item["recommendation"]


def test_summary_counts_match_findings():
    result = run_security_checks()

    assert sum(result["summary"].values()) == result["checks_run"]


def test_read_apt_setting(tmp_path):
    config = tmp_path / "updates.conf"
    config.write_text(
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
    )

    assert read_apt_setting(
        str(config), "APT::Periodic::Update-Package-Lists"
    ) == "1"

    assert read_apt_setting(
        str(config), "APT::Periodic::Unattended-Upgrade"
    ) == "1"


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_endpoint():
    response = client.get("/api/scan")

    assert response.status_code == 200

    data = response.json()
    assert data["checks_run"] == 8
    assert "scanned_at" in data


def test_homepage():
    response = client.get("/")

    assert response.status_code == 200
    assert "Linux Security Configuration Auditor" in response.text

def test_read_apt_setting_missing_file(tmp_path):
    missing_file = tmp_path / "missing.conf"

    assert read_apt_setting(
        str(missing_file),
        "APT::Periodic::Update-Package-Lists",
    ) is None


def test_run_command_missing_executable():
    from app.scanner.checks import run_command

    assert run_command(
        ["definitely-not-a-real-command-12345"]
    ) is None


def test_scanner_summary_has_all_statuses():
    result = run_security_checks()

    assert set(result["summary"]) == {
        "pass",
        "fail",
        "review",
        "unknown",
    }


def test_scanner_version_is_present():
    result = run_security_checks()

    assert result["version"]
    assert result["checks_run"] == len(result["findings"])
def test_run_command_nonzero_exit():
    from app.scanner.checks import run_command

    result = run_command([
        "python3",
        "-c",
        "import sys; sys.exit(1)",
    ])

    assert result is None


def test_run_command_timeout():
    from app.scanner.checks import run_command

    result = run_command([
        "python3",
        "-c",
        "import time; time.sleep(10)",
    ])

    assert result is None
def test_firewall_returns_unknown_when_tools_missing(monkeypatch):
    from app.scanner.checks import check_firewall

    monkeypatch.setattr(
        "app.scanner.checks.shutil.which",
        lambda command: None,
    )

    result = check_firewall()

    assert result["check_id"] == "LINUX-001"
    assert result["status"] == "UNKNOWN"
    assert result["evidence"]
    assert result["recommendation"]
def test_sensitive_file_permissions_pass_when_files_are_secure(monkeypatch):
    from types import SimpleNamespace
    from app.scanner.checks import check_sensitive_file_permissions

    class FakePath:
        def __init__(self, name):
            self.name = name

        def stat(self):
            modes = {
                "/etc/passwd": 0o644,
                "/etc/shadow": 0o640,
            }
            return SimpleNamespace(
                st_mode=modes[self.name],
                st_uid=0,
            )

    monkeypatch.setattr(
        "app.scanner.checks.Path",
        FakePath,
    )

    result = check_sensitive_file_permissions()

    assert result["check_id"] == "LINUX-005"
    assert result["status"] == "PASS"


def test_sensitive_file_permissions_fail_when_passwd_is_writable(monkeypatch):
    from types import SimpleNamespace
    from app.scanner.checks import check_sensitive_file_permissions

    class FakePath:
        def __init__(self, name):
            self.name = name

        def stat(self):
            mode = 0o666 if self.name == "/etc/passwd" else 0o640
            return SimpleNamespace(
                st_mode=mode,
                st_uid=0,
            )

    monkeypatch.setattr(
        "app.scanner.checks.Path",
        FakePath,
    )

    result = check_sensitive_file_permissions()

    assert result["check_id"] == "LINUX-005"
    assert result["status"] == "FAIL"
    assert "/etc/passwd" in result["evidence"]


def test_sensitive_file_permissions_review_when_shadow_not_root_owned(monkeypatch):
    from types import SimpleNamespace
    from app.scanner.checks import check_sensitive_file_permissions

    class FakePath:
        def __init__(self, name):
            self.name = name

        def stat(self):
            owner = 1000 if self.name == "/etc/shadow" else 0
            mode = 0o644 if self.name == "/etc/passwd" else 0o640
            return SimpleNamespace(
                st_mode=mode,
                st_uid=owner,
            )

    monkeypatch.setattr(
        "app.scanner.checks.Path",
        FakePath,
    )

    result = check_sensitive_file_permissions()

    assert result["check_id"] == "LINUX-005"
    assert result["status"] == "REVIEW"
    assert "not owned by root" in result["evidence"]
def test_sensitive_file_permissions_unknown_when_file_unavailable(monkeypatch):
    from app.scanner.checks import check_sensitive_file_permissions

    class FakePath:
        def __init__(self, name):
            self.name = name

        def stat(self):
            raise PermissionError("Access denied")

    monkeypatch.setattr(
        "app.scanner.checks.Path",
        FakePath,
    )

    result = check_sensitive_file_permissions()

    assert result["check_id"] == "LINUX-005"
    assert result["status"] == "UNKNOWN"
    assert "Could not inspect" in result["evidence"]
def test_shadow_world_readable_permissions_fail(monkeypatch):
    from types import SimpleNamespace
    from app.scanner.checks import check_sensitive_file_permissions

    class FakePath:
        def __init__(self, name):
            self.name = name

        def stat(self):
            mode = 0o644 if self.name == "/etc/shadow" else 0o644
            return SimpleNamespace(
                st_mode=mode,
                st_uid=0,
            )

    monkeypatch.setattr(
        "app.scanner.checks.Path",
        FakePath,
    )

    result = check_sensitive_file_permissions()

    assert result["check_id"] == "LINUX-005"
    assert result["status"] == "FAIL"
    assert "/etc/shadow" in result["evidence"]
def test_ssh_root_login_passes_when_restricted(monkeypatch):
    from app.scanner.checks import check_ssh_setting

    monkeypatch.setattr(
        "app.scanner.checks.shutil.which",
        lambda command: "/usr/sbin/sshd",
    )

    monkeypatch.setattr(
        "app.scanner.checks.run_command",
        lambda command: "permitrootlogin no",
    )

    result = check_ssh_setting(
        "permitrootlogin",
        "LINUX-002",
        "SSH root login restriction",
    )

    assert result["status"] == "PASS"
    assert "permitrootlogin: no" in result["evidence"].lower()


def test_ssh_root_login_fails_when_permitted(monkeypatch):
    from app.scanner.checks import check_ssh_setting

    monkeypatch.setattr(
        "app.scanner.checks.shutil.which",
        lambda command: "/usr/sbin/sshd",
    )

    monkeypatch.setattr(
        "app.scanner.checks.run_command",
        lambda command: "permitrootlogin yes",
    )

    result = check_ssh_setting(
        "permitrootlogin",
        "LINUX-002",
        "SSH root login restriction",
    )

    assert result["status"] == "FAIL"
    assert "permitrootlogin: yes" in result["evidence"].lower()


def test_ssh_setting_unknown_when_server_unavailable(monkeypatch):
    from app.scanner.checks import check_ssh_setting

    monkeypatch.setattr(
        "app.scanner.checks.shutil.which",
        lambda command: None,
    )

    result = check_ssh_setting(
        "permitrootlogin",
        "LINUX-002",
        "SSH root login restriction",
    )

    assert result["status"] == "UNKNOWN"
    assert "sshd" in result["evidence"].lower()
def test_firewall_reviews_when_ufw_is_active(monkeypatch):
    from app.scanner import checks

    monkeypatch.setattr(
        checks.shutil, "which",
        lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
    )
    monkeypatch.setattr(
        checks, "run_command",
        lambda command: "Status: active\nLogging: on",
    )

    result = checks.check_firewall()

    assert result["status"] == "REVIEW"
    assert result["check_id"] == "LINUX-001"
    assert "active" in result["evidence"].lower()
    assert "not been evaluated" in result["evidence"].lower()


def test_firewall_reviews_when_ufw_is_inactive(monkeypatch):
    from app.scanner import checks

    monkeypatch.setattr(
        checks.shutil, "which",
        lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
    )
    monkeypatch.setattr(
        checks, "run_command",
        lambda command: "Status: inactive",
    )

    result = checks.check_firewall()

    assert result["status"] == "REVIEW"
    assert "another firewall" in result["evidence"].lower()


def test_firewall_reviews_when_nftables_rules_are_visible(monkeypatch):
    from app.scanner import checks

    monkeypatch.setattr(
        checks.shutil, "which",
        lambda name: "/usr/sbin/nft" if name == "nft" else None,
    )
    monkeypatch.setattr(
        checks, "run_command",
        lambda command: "table inet filter {\n chain input {\n }\n}",
    )

    result = checks.check_firewall()

    assert result["status"] == "REVIEW"
    assert "effectiveness has not been evaluated" in result["evidence"].lower()


def test_firewall_unknown_when_no_supported_tools_are_available(monkeypatch):
    from app.scanner import checks

    monkeypatch.setattr(checks.shutil, "which", lambda name: None)

    result = checks.check_firewall()

    assert result["status"] == "UNKNOWN"
    assert result["check_id"] == "LINUX-001"
def test_firewalld_running_returns_review(monkeypatch):
    from app.scanner import checks

    monkeypatch.setattr(
        checks.shutil, "which",
        lambda name: "/usr/bin/firewall-cmd"
        if name == "firewall-cmd" else None,
    )

    def fake_run_command(command):
        if command == ["firewall-cmd", "--state"]:
            return "running"
        return None

    monkeypatch.setattr(checks, "run_command", fake_run_command)

    result = checks.check_firewall()

    assert result["status"] == "REVIEW"
    assert result["check_id"] == "LINUX-001"
    assert "firewalld is running" in result["evidence"].lower()
    assert "not been evaluated" in result["evidence"].lower()