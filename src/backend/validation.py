"""Syntax validation for scanner API targets and scan modes."""

import ipaddress
import re
from urllib.parse import urlsplit


SUPPORTED_SCAN_TYPES = {"basic", "version detection", "web scan", "pipeline"}
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class TargetValidationError(ValueError):
    """Raised when a target is not a valid host or HTTP(S) URL."""


def validate_scan_type(scan_type):
    if not isinstance(scan_type, str) or scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(
            "scanType must be 'basic', 'version detection', 'web scan', or 'pipeline'."
        )
    return scan_type


def _validate_hostname(hostname):
    if not hostname or len(hostname) > 253:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    # Do not let malformed dotted numeric addresses pass as DNS names.
    if re.fullmatch(r"[0-9.]+", hostname):
        return False
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError:
        return False
    labels = ascii_hostname.split(".")
    return bool(labels) and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def validate_target(target, scan_type="basic"):
    """Validate a host for Nmap or an HTTP(S) URL for ZAP without resolving DNS."""
    validate_scan_type(scan_type)
    if not isinstance(target, str):
        raise TargetValidationError("target must be a string.")

    candidate = target.strip()
    if not candidate or len(candidate) > 2048:
        raise TargetValidationError("target is required and must be at most 2048 characters.")
    if any(ord(char) < 32 for char in candidate):
        raise TargetValidationError("target contains invalid control characters.")

    if scan_type not in {"web scan", "pipeline"}:
        if "://" in candidate or any(char in candidate for char in "/@?#") or any(char.isspace() for char in candidate):
            raise TargetValidationError("Network scan target must be a valid IP address or hostname.")
        if not _validate_hostname(candidate):
            raise TargetValidationError("Network scan target must be a valid IP address or hostname.")
        return candidate

    try:
        parsed = urlsplit(candidate if "://" in candidate else "http://" + candidate)
        hostname = parsed.hostname
        if (parsed.scheme not in ("http", "https") or not hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError()
        port = parsed.port
        if port == 0:
            raise ValueError()
    except ValueError:
        raise TargetValidationError("Web scan target must be a valid HTTP(S) URL or hostname.")
    if not _validate_hostname(hostname):
        raise TargetValidationError("Web scan target must contain a valid IP address or hostname.")
    return candidate if "://" in candidate else "http://" + candidate
