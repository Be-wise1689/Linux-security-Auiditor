# Linux Security Configuration Auditor

A Python-based defensive cybersecurity tool that checks selected Linux security configurations, reports findings, and provides recommendations through a web dashboard.

## 1. Problem Statement

Linux systems require appropriate security configurations to reduce the risk of unauthorized access and misconfiguration. Manually checking multiple settings can be time-consuming, especially for beginners and small organizations.

The Linux Security Configuration Auditor automates selected read-only checks and presents the results in an accessible dashboard.

## 2. Project Objectives

* Automate selected Linux security configuration checks.
* Identify configurations that pass, fail, require review, or cannot be verified.
* Present evidence and recommendations for each finding.
* Provide a web dashboard and API endpoints.
* Evaluate the implementation with automated tests.

## 3. Features

The auditor performs eight selected checks:

| ID        | Security Check              | Purpose                                                                        |
| --------- | --------------------------- | ------------------------------------------------------------------------------ |
| LINUX-001 | Host firewall               | Checks whether firewall status can be verified using supported tools.          |
| LINUX-002 | SSH root login restriction  | Assesses the SSH configuration for root login restrictions.                    |
| LINUX-003 | SSH password authentication | Checks the SSH password authentication setting.                                |
| LINUX-004 | Automatic security updates  | Examines selected APT automatic-update settings.                               |
| LINUX-005 | Sensitive file permissions  | Checks selected permissions and ownership for `/etc/passwd` and `/etc/shadow`. |
| LINUX-006 | Failed login records        | Examines available records for failed SSH login activity.                      |
| LINUX-007 | Listening network ports     | Reports listening TCP and UDP sockets for review.                              |
| LINUX-008 | Root filesystem space       | Checks filesystem space usage.                                                 |

### Finding statuses

* **PASS:** The selected check passed.
* **FAIL:** The check identified a condition that did not meet its security criteria.
* **REVIEW:** The result needs further investigation.
* **UNKNOWN:** The tool could not verify the condition with the available information.

An UNKNOWN result does not mean that a system is secure or insecure.

## 4. Technology Stack

* Python
* FastAPI
* Uvicorn
* Pytest
* HTTPX
* HTML, CSS, and JavaScript for the dashboard, where implemented

## 5. Requirements

* Python 3
* Python virtual environment support
* Internet access for the initial dependency installation
* A Linux environment for the intended security checks

The application has been developed and tested in Ubuntu running under Windows Subsystem for Linux (WSL). Results describe the Linux environment being scanned, not a complete audit of the Windows host.

## 6. Installation and Startup

Clone the repository:

```bash
git clone git@github.com:Be-wise1689/Linux-security-Auiditor.git
cd Linux-security-Auiditor
```

Create a virtual environment and install dependencies manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the application:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Quick startup

After Python and the required system support are installed, the included launcher can create the virtual environment and install project dependencies when needed:

```bash
chmod +x run.sh
./run.sh
```

Open the dashboard:

http://127.0.0.1:8000

API documentation:

http://127.0.0.1:8000/docs

## 7. API Endpoints

| Endpoint          | Purpose                                       |
| ----------------- | --------------------------------------------- |
| `GET /api/health` | Checks whether the application is responding. |
| `GET /api/scan`   | Runs the security scan and returns findings.  |
| `/docs`           | Displays interactive API documentation.       |

## 8. Testing and Evaluation

The project includes automated tests for scanner findings, result summaries, configuration checks, and API endpoints.

The latest previously recorded test run completed with **29 passing tests**. Run the tests again before submission to confirm the current result:

```bash
python -m pytest -v
```

The application health endpoint previously returned HTTP 200 OK.

One observed scan returned:

| Status  | Number of findings |
| ------- | -----------------: |
| PASS    |                  3 |
| FAIL    |                  0 |
| REVIEW  |                  1 |
| UNKNOWN |                  4 |
| Total   |                  8 |

These are observed results from the development environment, not universal results for all Linux systems.

## 9. Limitations

* The auditor checks selected security settings; it is not a complete security audit.
* Missing utilities, insufficient permissions, or unavailable configuration data may produce UNKNOWN results.
* Firewall detection does not prove that every firewall rule is effective.
* A list of listening ports requires contextual investigation.
* Automatic-update settings do not prove that all security updates have been installed successfully.
* Missing failed-login records do not prove that no failed logins occurred.
* The current implementation reports findings and does not automatically remediate configurations.
* Running under WSL means the results do not represent a complete Windows host security assessment.

## 10. Safe Use

Use the auditor only on systems you own or are authorized to assess. Review findings before making security changes. The tool is designed to inspect configurations rather than automatically modify them.

## 11. Future Improvements

* Add support for more Linux distributions.
* Expand the security checks.
* Improve detection when required tools are missing.
* Export findings to JSON, CSV, or PDF.
* Add scan history and report comparison.
* Add further tests across different Linux environments.

## 12. Conclusion

The Linux Security Configuration Auditor demonstrates how Python, automated testing, and a web interface can help inspect selected Linux security configurations. It provides findings, supporting evidence, and recommendations while communicating when a result cannot be verified.

**Repository:** [Linux Security Configuration Auditor](https://github.com/Be-wise1689/Linux-security-Auiditor)
