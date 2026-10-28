"""Sequential orchestration and legacy scan-response adapter."""

import logging
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from .config import PipelineConfig, target_host
from .engines.nmap import run_nmap_scan
from .engines.repository import run_gitleaks_scan, run_trivy_scan
from .engines.zap import run_zap_baseline


logger = logging.getLogger(__name__)
STAGE_ORDER = ("gitleaks", "trivy", "nmap", "zap")


def _web_target(target):
    return target if "://" in target else f"http://{target}"


def run_pipeline(
    target,
    config=None,
    environment_type=None,
    scan_type="version detection",
    time_limit=None,
    requested_stages=None,
):
    config = config or PipelineConfig.from_env()
    if environment_type not in {None, "managed", "self_hosted"}:
        raise ValueError("environment_type must be 'managed' or 'self_hosted'.")

    effective_environment = (
        "managed"
        if config.environment_type == "managed" or environment_type == "managed"
        else "self_hosted"
    )
    run_id = uuid4().hex
    run_config = replace(
        config,
        environment_type=effective_environment,
        report_dir=Path(config.report_dir) / run_id,
    )
    requested = set(STAGE_ORDER if requested_stages is None else requested_stages)
    if requested.difference(STAGE_ORDER):
        raise ValueError("requested_stages contains an unknown scanner.")
    stages = {}

    # Add a new scanner by registering its toggle, managed-mode behavior, and executor here.
    engines = {
        "gitleaks": {
            "enabled": run_config.gitleaks_enabled,
            "managed_idle": False,
            "executor": lambda: run_gitleaks_scan(run_config),
        },
        "trivy": {
            "enabled": run_config.trivy_enabled,
            "managed_idle": False,
            "executor": lambda: run_trivy_scan(run_config),
        },
        "nmap": {
            "enabled": run_config.nmap_enabled,
            "managed_idle": True,
            "executor": lambda: run_nmap_scan(
                target_host(target),
                scan_type,
                run_config,
                timeout_seconds=time_limit,
            ),
        },
        "zap": {
            "enabled": run_config.zap_enabled,
            "managed_idle": False,
            "executor": lambda: run_zap_baseline(
                _web_target(target),
                run_config,
                timeout_seconds=time_limit,
            ),
        },
    }

    started = time.monotonic()
    for name in STAGE_ORDER:
        engine = engines[name]
        if name not in requested:
            result = {
                "scanner": name,
                "status": "skipped" if name == "nmap" else "not_requested",
                "reason": (
                    "Source checks run in GitHub Actions and are not part of a live-site scan."
                    if name in {"gitleaks", "trivy"}
                    else "Bypassed / Idle (Managed Platform). Network port scanning is not run for managed deployments."
                    if name == "nmap" and effective_environment == "managed"
                    else "Nmap was disabled for this run."
                    if name == "nmap"
                    else f"{name} was not requested for this scan."
                ),
                "report_path": None,
                "findings": [],
                "finding_count": 0,
            }
        elif engine["managed_idle"] and effective_environment == "managed":
            result = {
                "scanner": name,
                "status": "skipped",
                "reason": "Bypassed / Idle (Managed Platform). Network port scanning is not run for managed deployments.",
                "report_path": None,
                "findings": [],
                "finding_count": 0,
            }
        elif name in {"nmap", "zap"} and not run_config.allows_target(target):
            result = {
                "scanner": name,
                "status": "blocked",
                "error": "Target is not permitted by SCAN_ALLOWED_TARGETS.",
                "report_path": None,
                "findings": [],
                "finding_count": 0,
            }
        elif not engine["enabled"]:
            result = {
                "scanner": name,
                "status": "skipped",
                "reason": f"{name} is disabled by configuration.",
                "report_path": None,
                "findings": [],
                "finding_count": 0,
            }
        else:
            try:
                result = engine["executor"]()
            except Exception:
                logger.exception("Pipeline stage %s failed unexpectedly.", name)
                result = {
                    "scanner": name,
                    "status": "failed",
                    "error": f"{name} failed unexpectedly.",
                    "report_path": None,
                    "findings": [],
                    "finding_count": 0,
                }

        result.setdefault("scanner", name)
        result.setdefault("finding_count", len(result.get("findings") or []))
        stages[name] = result

    statuses = [stages[name]["status"] for name in STAGE_ORDER]
    enabled_statuses = [
        stages[name]["status"]
        for name in STAGE_ORDER
        if stages[name]["status"] != "skipped"
    ]
    if all(status in {"skipped", "not_requested"} for status in statuses):
        overall_status = "skipped"
    elif any(status in {"failed", "blocked"} for status in enabled_statuses):
        overall_status = (
            "partial"
            if any(status in {"passed", "vulnerabilities_found", "completed"} for status in enabled_statuses)
            else "failed"
        )
    elif any(status == "vulnerabilities_found" for status in statuses):
        overall_status = "vulnerabilities_found"
    else:
        overall_status = "passed"

    return {
        "run_id": run_id,
        "target": target,
        "environment_type": effective_environment,
        "status": overall_status,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stages": stages,
        "report_paths": {
            name: stages[name].get("report_path") for name in STAGE_ORDER
        },
    }


def run_scan(target, scan_type="basic", time_limit=None, config=None):
    config = config or PipelineConfig.from_env()
    scanner_selection = {
        "basic": ("nmap",),
        "version detection": ("nmap",),
        "web scan": ("zap",),
        "pipeline": ("nmap", "zap"),
    }
    if scan_type not in scanner_selection:
        return {"error": "Unsupported scan type."}

    if scan_type == "pipeline":
        result = run_pipeline(
            target,
            config=config,
            scan_type="version detection",
            time_limit=time_limit,
            requested_stages=("nmap", "zap"),
        )
        return {
            "target": target,
            "scan_time": str(result["duration_seconds"]),
            "pipeline": result,
            "open_ports": (
                result["stages"]["nmap"].get("findings", {}).get("open_ports", [])
                if isinstance(result["stages"]["nmap"].get("findings"), dict)
                else []
            ),
            "web_scan": {
                "target_url": _web_target(target),
                "findings": result["stages"]["zap"].get("findings", []),
            },
        }

    result = run_pipeline(
        target,
        config=config,
        scan_type=scan_type if scan_type in {"basic", "version detection"} else "basic",
        time_limit=time_limit,
        requested_stages=scanner_selection[scan_type],
    )
    stage_name = scanner_selection[scan_type][0]
    stage = result["stages"][stage_name]
    response = {
        "target": target,
        "scan_time": str(result["duration_seconds"]),
        "pipeline": result,
    }
    if stage_name == "nmap":
        findings = stage.get("findings")
        response["open_ports"] = (
            findings.get("open_ports", []) if isinstance(findings, dict) else []
        )
        if stage["status"] in {"failed", "blocked"}:
            response["error"] = stage.get("error", "Nmap scan failed.")
    else:
        response["web_scan"] = {
            "target_url": _web_target(target),
            "findings": stage.get("findings", []),
        }
        if stage["status"] in {"failed", "blocked"}:
            response["web_scan"]["error"] = stage.get(
                "error", stage.get("reason", "ZAP scan failed.")
            )
    return response
