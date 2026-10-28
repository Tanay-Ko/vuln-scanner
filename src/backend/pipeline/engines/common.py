"""Shared report-writing helpers for scanner engines."""

import json
import os
from pathlib import Path
from uuid import uuid4


def write_json_report(report_dir, scanner, payload, filename=None):
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / (filename or f"{scanner}-{uuid4().hex}.json")
    temporary_path = report_path.with_suffix(".tmp")
    try:
        temporary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary_path, report_path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise
    return str(report_path.resolve())


def failed_result(scanner, target, message, status="failed"):
    return {
        "scanner": scanner,
        "status": status,
        "target": target,
        "report_path": None,
        "error": message,
        "findings": [],
    }
