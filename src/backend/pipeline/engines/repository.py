"""Local repository scanners for leaked secrets and vulnerable dependencies."""

import json
import logging
import subprocess
import time

from .common import failed_result


logger = logging.getLogger(__name__)


def _read_report(report_path, scanner):
    try:
        with report_path.open(encoding="utf-8") as report_file:
            return json.load(report_file)
    except (OSError, json.JSONDecodeError):
        logger.exception("%s did not produce a readable JSON report.", scanner)
        return None


def _finish_result(scanner, target, report_path, raw_report, started, finding_count=None):
    if raw_report is None:
        return failed_result(
            scanner, target, f"{scanner} did not produce a valid JSON report."
        )
    if isinstance(raw_report, list):
        findings = raw_report
    elif isinstance(raw_report, dict):
        findings = raw_report.get("Results", [])
    else:
        return failed_result(scanner, target, f"{scanner} report has an invalid format.")
    if not isinstance(findings, list):
        return failed_result(scanner, target, f"{scanner} report has an invalid format.")
    count = len(findings) if finding_count is None else finding_count
    return {
        "scanner": scanner,
        "status": "vulnerabilities_found" if count else "passed",
        "target": target,
        "report_path": str(report_path.resolve()),
        "duration_seconds": round(time.monotonic() - started, 3),
        "finding_count": count,
        "findings": raw_report,
    }


def run_gitleaks_scan(config):
    scanner = "gitleaks"
    report_path = config.report_dir / "gitleaks_report.json"
    command = [
        *config.gitleaks_command,
        "./src",
        f"--report-path={report_path}",
    ]
    started = time.monotonic()
    try:
        config.report_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            command,
            cwd=config.project_root,
            capture_output=True,
            text=True,
            timeout=config.code_scan_timeout_seconds,
            check=False,
            shell=False,
        )
        if completed.returncode not in {0, 1}:
            logger.error(
                "Gitleaks failed with exit code %s: %s",
                completed.returncode,
                completed.stderr.strip(),
            )
            return failed_result(scanner, str(config.project_root / "src"), "Gitleaks exited with an error.")
        raw_report = _read_report(report_path, scanner)
        result = _finish_result(
            scanner, str(config.project_root / "src"), report_path, raw_report, started
        )
        if result["status"] != "failed" and isinstance(result["findings"], list):
            sensitive_keys = {"secret", "match", "raw"}
            result["findings"] = [
                {
                    key: value
                    for key, value in finding.items()
                    if key.lower() not in sensitive_keys
                }
                if isinstance(finding, dict)
                else finding
                for finding in result["findings"]
            ]
        return result
    except FileNotFoundError:
        logger.exception("Gitleaks CLI is missing.")
        return failed_result(scanner, str(config.project_root / "src"), "Gitleaks CLI was not found.")
    except subprocess.TimeoutExpired:
        logger.exception("Gitleaks timed out.")
        return failed_result(scanner, str(config.project_root / "src"), "Gitleaks scan exceeded its time limit.")
    except OSError:
        logger.exception("Gitleaks could not be started or save its report.")
        return failed_result(scanner, str(config.project_root / "src"), "Gitleaks could not complete its scan.")


def run_trivy_scan(config):
    scanner = "trivy"
    report_path = config.report_dir / "trivy_report.json"
    command = [
        *config.trivy_command,
        "fs",
        "./src",
        "--format", "json",
        "--output", str(report_path),
    ]
    started = time.monotonic()
    try:
        config.report_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            command,
            cwd=config.project_root,
            capture_output=True,
            text=True,
            timeout=config.code_scan_timeout_seconds,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            logger.error(
                "Trivy failed with exit code %s: %s",
                completed.returncode,
                completed.stderr.strip(),
            )
            return failed_result(scanner, str(config.project_root / "src"), "Trivy exited with an error.")
        raw_report = _read_report(report_path, scanner)
        if isinstance(raw_report, dict):
            results = raw_report.get("Results", [])
            if results is not None and not isinstance(results, list):
                return failed_result(
                    scanner,
                    str(config.project_root / "src"),
                    "Trivy report has an invalid results list.",
                )
            vulnerability_count = sum(
                len(result.get("Vulnerabilities") or [])
                for result in results
                if isinstance(result, dict)
            ) if isinstance(results, list) else 0
        else:
            return failed_result(
                scanner,
                str(config.project_root / "src"),
                "Trivy report has an invalid format.",
            )
        return _finish_result(
            scanner,
            str(config.project_root / "src"),
            report_path,
            raw_report,
            started,
            finding_count=vulnerability_count,
        )
    except FileNotFoundError:
        logger.exception("Trivy CLI is missing.")
        return failed_result(scanner, str(config.project_root / "src"), "Trivy CLI was not found.")
    except subprocess.TimeoutExpired:
        logger.exception("Trivy timed out.")
        return failed_result(scanner, str(config.project_root / "src"), "Trivy scan exceeded its time limit.")
    except (OSError, TypeError):
        logger.exception("Trivy could not be started or save its report.")
        return failed_result(scanner, str(config.project_root / "src"), "Trivy could not complete its scan.")
