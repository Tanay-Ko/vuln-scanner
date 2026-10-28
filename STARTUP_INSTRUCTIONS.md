# VulnScan Startup Instructions

## Start the application

Run `python start.py` from the repository root. This starts the FastAPI backend and React
development server; it does not start ZAP or run scans automatically. Live-site scans run OWASP
ZAP Baseline and optionally Nmap when you submit a pipeline run. Start ZAP separately and make its
API reachable at `ZAP_API_URL` before requesting web scans. Source scans (Gitleaks and Trivy) run
in GitHub Actions against the checked-out repository, not against the website URL. Missing or
failing scanners are reported on their individual stages and do not prevent the application from
starting. The startup script verifies that the backend exposes `/api/pipeline`; an older backend
already bound to port 8000 is not mistaken for the current service.

## Install Gitleaks and Trivy on Windows

These are standalone command-line programs, not Python packages. From the repository root, run
the included PowerShell installer:

```powershell
.\scripts\install-scanners.ps1
```

The script downloads the latest Windows x64 archives from the official Gitleaks and Trivy GitHub
releases, checks each archive against that release's published SHA-256 checksum, and installs the
verified executables under the ignored project-local `bin\` folder. No global installation or
PATH change is required. The backend automatically prefers `bin\gitleaks.exe` and `bin\trivy.exe`;
explicit `GITLEAKS_COMMAND` or `TRIVY_COMMAND` environment settings take precedence. Restart the
backend after installing.

These local executables are used by standalone repository-scan modules; the live-site pipeline does
not run them. The GitHub Actions workflow installs its own pinned, checksum-verified scanner
versions and scans source files and Git history in the repository checkout. Trivy may need internet
access on its first run to download its vulnerability database. Reports from local modules are
written under `src/backend/reports/<run-id>/`. The official release pages are
[Gitleaks](https://github.com/gitleaks/gitleaks/releases) and
[Trivy](https://github.com/aquasecurity/trivy/releases).

## Access Points

Once everything is running:

- **Main application**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API documentation**: http://localhost:8000/docs

## Troubleshooting

- Ensure Python, Node.js, and npm are installed.
- Install Nmap only if you intend to run optional network scans. Install local Gitleaks and Trivy
  binaries only if you use the standalone local repository-scanner modules.
- Start OWASP ZAP with its API available at `http://127.0.0.1:8080` before running the pipeline.
  Configure `ZAP_API_URL` and `ZAP_API_KEY` if your ZAP instance uses a different address or API key.
- Install backend dependencies with `pip install -r src/backend/requirements.txt`.
- Install frontend dependencies with `npm install`.
- Configure `SCAN_ENVIRONMENT`, scanner toggles, and the exact `SCAN_ALLOWED_TARGETS` list before
  running scans. Network stages are blocked for targets outside this list; local repository
  scans can still run. Managed deployments skip Nmap.
- `python stop.py` stops processes listening on the application's default ports 3000 and 8000 only;
  it does not terminate unrelated Node.js or Python processes.
