"""Nmap CLI engine and XML-to-JSON normalization."""

import subprocess
import time
import logging
import xml.etree.ElementTree as ET

from .common import failed_result, write_json_report


logger = logging.getLogger(__name__)


def _parse_nmap_xml(xml_output):
    root = ET.fromstring(xml_output)
    if root.tag != "nmaprun":
        raise ValueError("Nmap output had an unexpected root element.")
    open_ports = []
    for host in root.findall("./host"):
        for port_element in host.findall("./ports/port"):
            state_element = port_element.find("./state")
            state = state_element.get("state") if state_element is not None else "unknown"
            if state != "open":
                continue
            service = port_element.find("./service")
            open_ports.append({
                "port": int(port_element.get("portid")),
                "state": state,
                "service": service.get("name") if service is not None else "",
                "product": service.get("product") if service is not None else "",
                "version": service.get("version") if service is not None else "",
            })
    return open_ports


def run_nmap_scan(target, scan_type, config, timeout_seconds=None):
    if not config.allows_target(target):
        return failed_result("nmap", target, "Target is not in SCAN_ALLOWED_TARGETS.", "blocked")

    if scan_type not in {"basic", "version detection"}:
        return failed_result("nmap", target, "Unsupported Nmap scan profile.")

    timeout = min(timeout_seconds or config.nmap_timeout_seconds, config.nmap_timeout_seconds)
    command = [
        *config.nmap_command,
        "-T3",
        "--top-ports", "100",
        "--max-retries", "1",
        "--host-timeout", f"{timeout}s",
        "-oX", "-",
    ]
    if scan_type == "version detection":
        command.append("-sV")
    command.append(target)
    started = time.monotonic()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            logger.error("Nmap exited with status %s: %s", completed.returncode, completed.stderr.strip())
            return failed_result("nmap", target, "Nmap exited with a non-zero status.")
        open_ports = _parse_nmap_xml(completed.stdout)
        duration = round(time.monotonic() - started, 3)
        report = {
            "scanner": "nmap",
            "status": "completed",
            "target": target,
            "scan_type": scan_type,
            "duration_seconds": duration,
            "findings": {"open_ports": open_ports},
        }
        report_path = write_json_report(
            config.report_dir, "nmap", report, filename="nmap_report.json"
        )
        return {**report, "report_path": report_path}
    except FileNotFoundError:
        logger.exception("Nmap CLI is missing.")
        return failed_result("nmap", target, "Nmap CLI was not found.")
    except subprocess.TimeoutExpired:
        logger.exception("Nmap scan timed out.")
        return failed_result("nmap", target, "Nmap scan exceeded its time limit.")
    except (ET.ParseError, OSError, TypeError, ValueError):
        logger.exception("Nmap output could not be parsed or saved.")
        return failed_result("nmap", target, "Nmap output could not be parsed or saved.")
