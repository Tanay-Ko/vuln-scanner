"""OWASP ZAP baseline CLI engine and JSON normalization."""

import json
import logging
import time
from urllib.parse import urlparse

import requests

from .common import failed_result, write_json_report


logger = logging.getLogger(__name__)


def _risk_level(alert):
    risk_names = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    try:
        risk_code = int(alert.get("riskcode"))
    except (TypeError, ValueError):
        risk_code = None
    if risk_code in risk_names:
        return risk_names[risk_code]
    return str(alert.get("riskdesc", "info")).split()[0].lower()


def _normalize_alerts(report):
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        return report["findings"]

    findings = []
    if not isinstance(report, dict) or "site" not in report:
        raise ValueError("ZAP report did not contain a site list.")
    sites = report["site"]
    if not isinstance(sites, list):
        raise ValueError("ZAP report did not contain a site list.")
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("ZAP report contained an invalid site entry.")
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            raise ValueError("ZAP report contained an invalid alerts list.")
        for alert in alerts:
            if not isinstance(alert, dict):
                raise ValueError("ZAP report contained an invalid alert entry.")
            instances = alert.get("instances") or [alert]
            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                findings.append({
                    "name": alert.get("name", "Unknown issue"),
                    "description": alert.get("desc", ""),
                    "severity": _risk_level(alert),
                    "confidence": alert.get("confidence", ""),
                    "url": instance.get(
                        "uri", instance.get("url", site.get("@name", ""))
                    ),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "cweid": alert.get("cweid", ""),
                    "param": instance.get("param", ""),
                    "attack": instance.get("attack", ""),
                    "evidence": instance.get("evidence", ""),
                })
    return findings


def _zap_get(config, endpoint, params=None, timeout=5):
    query = dict(params or {})
    if config.zap_api_key:
        query["apikey"] = config.zap_api_key
    response = requests.get(
        f"{config.zap_api_url}/JSON/{endpoint}/",
        params=query,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _wait_for_spider(config, scan_id, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ZAP spider scan exceeded its time limit.")
        status = _zap_get(
            config,
            "spider/view/status",
            {"scanId": scan_id},
            timeout=min(5, remaining),
        )
        if str(status.get("status")) == "100":
            return
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def _wait_for_passive_scan(config, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ZAP passive scan exceeded its time limit.")
        status = _zap_get(
            config,
            "pscan/view/recordsToScan",
            timeout=min(5, remaining),
        )
        if int(status.get("recordsToScan", 0)) == 0:
            return
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def run_zap_baseline(target, config, timeout_seconds=None):
    if not config.allows_target(target):
        return failed_result("zap", target, "Target is not in SCAN_ALLOWED_TARGETS.", "blocked")

    timeout = min(timeout_seconds or config.zap_timeout_seconds, config.zap_timeout_seconds)
    started = time.monotonic()
    try:
        config.report_dir.mkdir(parents=True, exist_ok=True)
        _zap_get(config, "core/view/version")
        spider = _zap_get(
            config,
            "spider/action/scan",
            {
                "url": target,
                "maxChildren": 2,
                "recurse": "false",
                "maxDepth": 1,
            },
        )
        scan_id = spider.get("scan")
        if scan_id is None:
            raise ValueError("ZAP did not return a spider scan ID.")

        deadline = time.monotonic() + timeout
        _wait_for_spider(config, scan_id, deadline)
        _wait_for_passive_scan(config, deadline)
        raw_alerts = _zap_get(
            config,
            "core/view/alerts",
            {"baseurl": target},
            timeout=min(5, max(0.1, deadline - time.monotonic())),
        )
        alerts = raw_alerts.get("alerts")
        if not isinstance(alerts, list):
            raise ValueError("ZAP did not return an alerts list.")
        findings = _normalize_alerts({
            "site": [{
                "@name": target,
                "alerts": alerts,
            }]
        })
        duration = round(time.monotonic() - started, 3)
        report = {
            "scanner": "zap",
            "target": target,
            "scan_mode": "passive",
            "duration_seconds": duration,
            "findings": findings,
            "status": "vulnerabilities_found" if findings else "passed",
            "finding_count": len(findings),
        }
        report_path = write_json_report(
            config.report_dir, "zap", report, filename="zap_report.json"
        )
        return {**report, "report_path": report_path}
    except requests.RequestException:
        logger.exception("ZAP API request failed.")
        return failed_result(
            "zap",
            target,
            "Could not connect to the ZAP API or complete the passive scan.",
        )
    except (OSError, TypeError, ValueError, TimeoutError, json.JSONDecodeError):
        logger.exception("ZAP passive scan failed.")
        return failed_result("zap", target, "ZAP passive scan failed.")
