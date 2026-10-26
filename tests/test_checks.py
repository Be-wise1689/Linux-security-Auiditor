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

