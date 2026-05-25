# Vulcan: Passive Web Security Configuration Auditor

Vulcan is a lightweight, high-performance, modular Python-based CLI tool designed to audit web applications passively for common configuration security weaknesses (corresponding to OWASP Top 10 categories, particularly **A05: Security Misconfiguration** and **A07: Identification and Authentication Failures**).

Unlike active vulnerability scanners, Vulcan operates purely passively. It evaluates HTTP security headers, cookies, and public configurations without sending aggressive, intrusive payloads, making it 100% safe, legal, and rapid for system administration and developmental auditing.

---

## 🚀 Key Features

* **🛡️ HTTP Response Header Audits**: Validates the presence and strength of crucial protective directives:
  * `Content-Security-Policy` (CSP)
  * `Strict-Transport-Security` (HSTS)
  * `X-Frame-Options` (Clickjacking defense)
  * `X-Content-Type-Options` (MIME sniffing defense)
  * `Referrer-Policy`
  * `Permissions-Policy`
* **🔍 Information Disclosure Scanner**: Detects exposed web server, OS, or framework signatures in headers like `Server`, `X-Powered-By`, and `X-AspNet-Version`.
* **🍪 Cookie Flag Auditor**: Analyzes set session and application cookies to ensure crucial protection attributes (`HttpOnly`, `Secure`, and `SameSite`) are enforced.
* **🤖 robots.txt Mapping**: Downloads and audits `robots.txt` rules to verify that sensitive endpoints (e.g., admin panels, backups, internal APIs) are not exposed to crawlers.
* **🖥️ Interactive Console UI**: Leverages the `Rich` console library to present beautiful startup logs, animated spinners, and clean, readable audit tables in the terminal.
* **📊 Premium Reporting**: Exports findings concurrently to:
  * Machine-readable **JSON database logs** for integration with automated pipelines.
  * Standalone, responsive, beautifully styled **dark-mode HTML reports** with severity badges and detailed developer remediation guidelines.

---

## 📂 Project Structure

```
custom_vulner/
│
├── auditor.py               # Main CLI orchestrator & banner
├── requirements.txt         # Package dependencies
├── mock_server.py           # Local vulnerable testing target
├── auditor.sh               # Bash launcher for Linux systems
├── README.md                # Documentation guide
│
└── core/                    # Core Auditing Modules
    ├── __init__.py
    ├── headers.py           # Header compliance checks
    ├── cookies.py           # Cookie attribute verification
    ├── robots.py            # Crawler exclusions auditor
    └── reporter.py          # HTML/JSON reporting engines
```

---

## 🛠️ Installation & Setup

Vulcan requires **Python 3.7+** and a couple of standard libraries.

1. Clone or navigate to your project directory:
   ```bash
   cd "custom vulner"
   ```

2. Install dependencies using pip:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage Instructions

### Basic Audit
Run the tool against any web application URL:
```bash
python auditor.py https://example.com
```

### Advanced Options
Customize output paths and time-out periods:
```bash
python auditor.py https://example.com --json my_report.json --html my_report.html --timeout 15
```

### CLI Command Options
* `target`: *(Required)* The target web application URL to audit.
* `--json`: Path to write the JSON database report (Default: `vulcan_report.json`).
* `--html`: Path to write the premium HTML report (Default: `vulcan_report.html`).
* `--timeout`: HTTP request timeout duration in seconds (Default: `10`).

---

## 🧪 Local Integration Testing (Safe Lab Verification)

To see the auditor in action against a target that actually triggers multiple distinct security alerts, you can launch the built-in mock server.

1. **Start the local vulnerable mock server**:
   ```bash
   python mock_server.py
   ```
   *This starts a local server on `http://127.0.0.1:8080` that simulates missing security headers, exposed server frameworks, insecure cookies, and crawl-sensitive exclusions.*

2. **Run Vulcan against the mock server**:
   In another terminal, execute:
   ```bash
   python auditor.py http://127.0.0.1:8080 --json local_audit.json --html local_audit.html
   ```

3. **Check the outputs**:
   Open the generated [local_audit.html](local_audit.html) report in any web browser to see the beautiful dark-themed dashboard.

---

## 🐧 Linux Support

If you transfer this project to a Linux or macOS terminal, a custom shell script wrapper `auditor.sh` is provided.

1. Make the launcher script executable:
   ```bash
   chmod +x auditor.sh
   ```

2. Run native audits:
   ```bash
   ./auditor.sh https://example.com
   ```
   *This wrapper automatically confirms Python is installed and silently sets up any missing package dependencies from `requirements.txt` before launching the audit.*

---

## ⚠️ Disclaimer & Ethical Use

Vulcan is built exclusively for authorized penetration testing, security auditing, posture compliance, and educational purposes. Always obtain explicit authorization from target administrators before scanning web applications. The creators assume no liability for misuse of this tool.
