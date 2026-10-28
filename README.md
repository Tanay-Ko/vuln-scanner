# VulnScan

VulnScan currently provides a reusable GitHub Actions workflow for scanning repository source and
dependencies with Gitleaks and Trivy. For another repository, users add one workflow file; they do
not install this application or its scanner dependencies.

The repository also contains a local-development dashboard for authorized live-site checks. A
production VM deployment path is not documented or provided here yet; the local setup below is
for development only.

## Features

- **Repository Source Security**: GitHub Actions runs Gitleaks on repository source and Git history, and Trivy on dependencies
- **Optional Infrastructure Scan**: Nmap is opt-in for self-hosted infrastructure and is skipped for managed deployments
- **Web Checks**: OWASP ZAP Baseline scans an explicitly authorized website using passive checks
- **Separate Scan Screens**: Source Security explains and links to repository Actions; Live-site Scan shows Nmap and ZAP results
- **CI Gate**: Gitleaks and Trivy run on pull requests, pushes to `master`, and weekly; the workflow can also be reused by another repository
- **Real-time Vulnerability Detection**: Uses online APIs (NVD, CVE Details) to find current vulnerabilities
- **Consolidated Reports**: Pipeline stage cards display status, findings, location, and remediation details
- **Target Policy**: Live-site requests are limited by the backend's exact-host allowlist and scanner timeouts
- **Modern UI**: Responsive React and Tailwind CSS interface with light/dark themes

## Local dashboard architecture

The following describes the local-development dashboard, not a deployed service.

- **Frontend**: React.js with Tailwind CSS
- **Backend**: FastAPI with Python
- **Vulnerability Data**: Real-time online APIs (NVD, CVE Details)
- **Scanning Engine**: Modular scanner adapters and a sequential live-site pipeline orchestrator
- **Source Scanning**: Separate GitHub Actions workflow scans the repository checkout; a website URL is never treated as source code

## Use the scanner in another repository

If you only want Gitleaks and Trivy checks in another GitHub repository, you do **not** need to
install this dashboard, Python, Node.js, Nmap, ZAP, Gitleaks, or Trivy there. Add one caller workflow
file to that repository and GitHub Actions will run the shared workflow on a GitHub-hosted runner.
The repository owner needs GitHub Actions enabled and must commit the file.

Create `.github/workflows/source-security.yml` in the repository:

```yaml
name: Source Security

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  source-security:
    uses: Tanay-Ko/vuln-scanner/.github/workflows/source-security.yml@da19725883ecf1eb5281ff79fbb22002586426c7
```

Change `main` to the branch you want checked, then commit and push this file. The pinned reusable
workflow checks out the calling repository, installs its own pinned Gitleaks and Trivy binaries, and
runs both scans there. No scanner dependencies or workflow copies are needed in the calling
repository. If GitHub Actions policy in your organization restricts reusable workflows, allow
`Tanay-Ko/vuln-scanner` in that repository's Actions settings.

This one-file setup is only for repository source and dependency checks. To run the VulnScan web
dashboard locally, follow the installation instructions below; those install the dashboard's
frontend and backend dependencies.

## Run the dashboard locally (development only)

These requirements are only for developers running the dashboard from this repository. They are
not requirements for a user enabling the GitHub Actions workflow in another repository.

- Node.js (v14 or higher)
- Python 3.8 or higher
- Nmap CLI installed when network scans are enabled
- OWASP ZAP running with its API reachable when web scans are enabled

For local development of the backend's standalone repository-scanner modules on Windows, the
project-local Gitleaks and Trivy binaries can be installed with:

```powershell
.\scripts\install-scanners.ps1
```

They are placed in the ignored `bin\` folder and selected automatically by those local modules.
The deployed URL-based scan does not run these binaries; GitHub Actions installs its own pinned
scanner versions. See [Startup Instructions](./STARTUP_INSTRUCTIONS.md) for details.

### Installing Nmap

**Windows:**

```bash
# Using Chocolatey
choco install nmap

# Or download from https://nmap.org/download.html
```

**macOS:**

```bash
brew install nmap
```

**Linux:**

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap
```

### Install local development dependencies

1. **Clone the repository:**

```bash
git clone <repository-url>
cd vuln-scanner
```

2. **Install dependencies:**

```bash
# Install frontend dependencies
npm install

# Install backend dependencies
pip install -r src/backend/requirements.txt
```

### Run the local dashboard

### Quick Start (Recommended)

```bash
# Start the API and frontend
python start.py
```

This starts the API and frontend. It does not start ZAP or run scans at startup. The pipeline uses ZAP only when a scan is requested and requires a separately running ZAP API. Nmap is opt-in for each live-site run.
The startup script verifies that the backend exposes the pipeline API before reporting it ready;
it will refuse to reuse an older backend that occupies port 8000 but lacks that route.

Open the application at `http://localhost:3000`.

### Manual Start

If you prefer to start services individually:

```bash
# Terminal 1: Start backend
cd src/backend
python -m uvicorn main:app --reload --port 8000

# Terminal 2: Start frontend
npm start
```

### Stop Services

```bash
# Stop all services
python stop.py
```

The stop script targets only processes listening on the application's default frontend and backend
ports (3000 and 8000); it does not terminate other Node.js or Python processes. If those ports are
occupied by an older app instance, stop that instance before starting the current version.

## Usage

1. **Open the application** in your browser at `http://localhost:3000`.
2. Select **Managed Platform** or **Self-Hosted VPS**.
3. Enter a live website target permitted by the backend's exact-host allowlist.
4. Optionally enable Nmap only for a self-hosted system you own or are authorized to assess.
5. Click **Run Security Pipeline** to run the live-site stages. The entered URL is not used to
   retrieve source code. Managed deployments always skip Nmap.
6. Use **Source Security** in the app navigation to open the separate source-scan screen and
   access GitHub Actions; review Nmap/ZAP findings on the **Live-site Scan** screen.

### GitHub Actions source scans

The [Source Security workflow](./.github/workflows/source-security.yml) checks out the repository
and runs Gitleaks and Trivy on that exact checkout. It runs on pull requests, pushes to `master`,
weekly, and when manually dispatched. It is also reusable from another repository through
`workflow_call`. Source files are scanned on GitHub-hosted runners and are not uploaded to this
application's backend. Gitleaks output is redacted; the workflow does not upload scanner report
artifacts.

For this repository, the workflow runs on pull requests, pushes to `master`, weekly, and manual
dispatch. Ensure GitHub Actions are enabled and review results in the **Actions** tab. For a required
merge gate, configure branch protection or a ruleset for `master` to require the **Gitleaks and
Trivy** check.

For another repository, follow the one-file instructions above. The reusable workflow scans the
calling repository's checkout. Automatically adding the caller file without a repository change
would require a separately authorized GitHub App integration.

### Implementation map

- `src/App.js` and `src/components/Navigation.js` select the Live-site Scan, Source Security, and
  Documentation screens.
- `src/components/PipelineRunDashboard.js`, `PipelineStageCard.js`, and `WebScanResults.js` render
  pipeline progress, the optional Nmap switch, and consolidated findings.
- `src/api/client.js` sends the live-scan request to the FastAPI service.
- `src/backend/routes/` defines the scan and vulnerability HTTP routes. `src/backend/validation.py`
  validates live-site input before scanner execution.
- `src/backend/pipeline/` contains configuration, target policy, orchestration, and the Nmap/ZAP
  scanner adapters. Stage failures are reported independently so the other requested stage can run.
- `src/backend/tests/`, `src/components/PipelineRunDashboard.test.js`, and
  `src/api/client.test.js` cover backend behavior, dashboard behavior, and API request formatting.
- `.github/workflows/source-security.yml` runs Gitleaks and Trivy in GitHub Actions. Its scanner
  versions are pinned and release archives are checksum-verified.
- `scripts/install-scanners.ps1` installs local Gitleaks and Trivy binaries for standalone local
  modules; this is separate from the GitHub Actions source workflow.
- `.github/agents/` contains repository-local feature and testing agent profiles.

Generated Python bytecode and per-run scan reports are runtime artifacts, not application source.
Do not include generated `__pycache__` files or local scan data in source commits. The bundled
SQLite database contains application data; only commit database changes when they are intentional.

## API Endpoints

- `POST /api/scan` - Perform a network, web, or combined live-site scan
- `POST /api/pipeline` - Run Nmap and ZAP against the live-site target and return one summary;
  source stages are marked not run here because they run in GitHub Actions
- `GET /api/vulnerabilities` - Get all vulnerabilities from database
- `GET /api/recommendations/{port}` - Get recommendations for specific port

### Scanner configuration

Set these environment variables for the backend:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCAN_ENVIRONMENT` | `self_hosted` | `managed` or `self_hosted`; managed mode bypasses Nmap |
| `GITLEAKS_ENABLED` | `true` | Enable Gitleaks in direct local orchestration; HTTP live-site scans do not run it |
| `TRIVY_ENABLED` | `true` | Enable Trivy in direct local orchestration; HTTP live-site scans do not run it |
| `NMAP_ENABLED` | `true` | Backend-level Nmap availability; the dashboard switch controls whether each run requests it |
| `ZAP_ENABLED` | `true` | Enable or disable the ZAP engine |
| `SCAN_ALLOWED_TARGETS` | `localhost,127.0.0.1,::1,pushups-omega.vercel.app` | Comma-separated exact host allowlist; setting this overrides the defaults |
| `SCAN_REPORT_DIR` | `src/backend/reports` | Directory for normalized JSON reports |
| `SCAN_PROJECT_ROOT` | repository root | Root used by direct local repository-scanner modules |
| `GITLEAKS_COMMAND` | `gitleaks dir` | Gitleaks executable and command |
| `TRIVY_COMMAND` | `trivy` | Trivy executable |
| `NMAP_COMMAND` | `nmap` | Nmap executable |
| `ZAP_API_URL` | `http://127.0.0.1:8080` | Local ZAP API endpoint |
| `ZAP_API_KEY` | empty | ZAP API key when the ZAP API requires one |
| `CODE_SCAN_TIMEOUT_SECONDS` | `180` | Per-tool Gitleaks and Trivy timeout |
| `NMAP_TIMEOUT_SECONDS` | `90` | Maximum Nmap process duration |
| `ZAP_TIMEOUT_SECONDS` | `120` | Maximum ZAP process duration |

Network scan targets must match an entry in `SCAN_ALLOWED_TARGETS`; wildcards are not supported.
Only scan systems you own or have explicit permission to assess. The `/api/pipeline` request runs
only Nmap and ZAP; those stages return `blocked` unless the target is on the backend allowlist. The
backend's `SCAN_ENVIRONMENT=managed` setting cannot be overridden by a frontend selection.
Nmap is off by default in the dashboard and may be enabled for an individual scan when the target is
a self-hosted machine you own or are explicitly authorized to assess. Managed deployments always
skip Nmap. Nmap identifies reachable ports and services on dedicated infrastructure; it is usually
not useful for Vercel/Heroku apps because probes may see shared hosting infrastructure or filtered
ports rather than the application server. Use ZAP for live HTTP application checks. Source stages
are marked not requested in live-site results because GitHub Actions scans the repository separately.

The standalone local Gitleaks module scans `./src` without Git history and redacts secret values
from its API result; the standalone Trivy module scans `./src` for dependencies. The Nmap engine uses a bounded
top-100 TCP port profile; version detection adds service fingerprinting. ZAP uses the local ZAP
REST API to run a bounded spider and passive checks only; it does not run an active attack scan.
The ZAP daemon must be running and reachable at `ZAP_API_URL`. A missing or failing scanner marks
only that stage failed, then the orchestrator proceeds to the next stage.

Version detection uses external vulnerability catalog APIs only to look up product/CVE
information; those results are marked as possible matches unless affected-version applicability
is confirmed.

### Backend tests

With the backend requirements installed, run the mocked backend tests from the backend folder:

```bash
cd src/backend
python -m unittest discover -s tests -v
```

These tests do not invoke Nmap, ZAP, or external vulnerability services.

From the repository root, run the frontend tests and production build with:

```powershell
npm test -- --watchAll=false
npm run build
```

## Database Schema

The application uses SQLite with the following tables:

- **ports**: Port numbers, services, and descriptions
- **vulnerabilities**: CVE data, severity, affected versions
- **recommendations**: Security recommendations and alternatives
- **service_versions**: Version-specific vulnerability patterns

## Security Features

### Vulnerability Detection

- CVE database integration
- CVSS scoring
- Version-specific vulnerability matching
- Severity classification

### Recommendations

- Actionable security improvements
- Alternative service suggestions
- Priority-based recommendations
- Detailed implementation guidance

### Risk Assessment

- Real-time risk calculation
- Visual risk indicators
- Comprehensive risk summary

## Example Scans

### Basic Scan

Scans common ports and identifies open services.

### Version Detection Scan

Performs detailed service fingerprinting and version detection, then cross-references with vulnerability database.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Notice

This tool is designed for authorized security testing only. Use this application only for authorized testing.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Nmap not found**: Ensure Nmap is installed and in your PATH
2. **Permission denied**: Some scans may require elevated privileges
3. **Backend connection failed**: Ensure the backend server is running on port 8000
4. **Database errors**: The SQLite database will be created automatically on first run

### Getting Help

- Check the console for error messages
- Ensure all dependencies are installed
- Verify Nmap is working: `nmap --version`
- Check firewall settings if scans fail
