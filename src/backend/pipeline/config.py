"""Environment-backed configuration for scanner execution."""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _scanner_default(project_root, executable, fallback):
    executable_name = f"{executable}.exe" if os.name == "nt" else executable
    local_executable = Path(project_root) / "bin" / executable_name
    if local_executable.is_file():
        return (str(local_executable.resolve()), *fallback[1:])
    return fallback


def _read_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def _read_command(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        command = json.loads(value)
    except json.JSONDecodeError:
        command = [value]
    if isinstance(command, str):
        command = [command]
    if not isinstance(command, list) or not command or any(
        not isinstance(part, str) or not part for part in command
    ):
        raise ValueError(f"{name} must be a command string or a JSON string array.")
    return tuple(command)


def _canonical_host(value):
    candidate = value.strip()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    elif "/" in candidate or "@" in candidate:
        candidate = urlsplit(f"//{candidate}").hostname or ""
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            hostname = candidate.encode("idna").decode("ascii").rstrip(".").lower()
        except UnicodeError:
            return ""
        if len(hostname) > 253 or not all(
            _HOST_LABEL.fullmatch(label) for label in hostname.split(".")
        ):
            return ""
        return hostname


def target_host(target):
    """Return a canonical host from either a host value or an HTTP(S) URL."""
    try:
        candidate = target.strip()
        if "://" in candidate:
            hostname = urlsplit(candidate).hostname
        else:
            hostname = urlsplit(f"//{candidate}").hostname
        return _canonical_host(hostname or "")
    except ValueError:
        return ""


@dataclass(frozen=True)
class PipelineConfig:
    environment_type: str = "self_hosted"
    gitleaks_enabled: bool = True
    trivy_enabled: bool = True
    nmap_enabled: bool = True
    zap_enabled: bool = True
    allowed_targets: tuple = (
        "localhost",
        "127.0.0.1",
        "::1",
        "pushups-omega.vercel.app",
    )
    project_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[3]
    )
    report_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[1] / "reports"
    )
    gitleaks_command: tuple = ("gitleaks", "dir")
    trivy_command: tuple = ("trivy",)
    nmap_command: tuple = ("nmap",)
    zap_api_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = ""
    code_scan_timeout_seconds: int = 180
    nmap_timeout_seconds: int = 90
    zap_timeout_seconds: int = 120

    def __post_init__(self):
        if self.environment_type not in {"managed", "self_hosted"}:
            raise ValueError("SCAN_ENVIRONMENT must be 'managed' or 'self_hosted'.")
        if min(
            self.code_scan_timeout_seconds,
            self.nmap_timeout_seconds,
            self.zap_timeout_seconds,
        ) < 1:
            raise ValueError("Scanner timeouts must be positive integers.")
        if not all((
            self.gitleaks_command,
            self.trivy_command,
            self.nmap_command,
        )):
            raise ValueError("Scanner commands must not be empty.")
        if not self.zap_api_url.startswith(("http://", "https://")):
            raise ValueError("zap_api_url must use HTTP or HTTPS.")
        canonical_targets = tuple(_canonical_host(host) for host in self.allowed_targets)
        if any(not host for host in canonical_targets):
            raise ValueError("allowed_targets must contain valid hostnames or IP addresses.")
        object.__setattr__(self, "allowed_targets", canonical_targets)
        object.__setattr__(self, "project_root", Path(self.project_root).resolve())
        object.__setattr__(self, "report_dir", Path(self.report_dir))

    @classmethod
    def from_env(cls):
        project_root = Path(
            os.getenv(
                "SCAN_PROJECT_ROOT",
                str(Path(__file__).resolve().parents[3]),
            )
        )
        allowed_targets = tuple(
            host.strip()
            for host in os.getenv(
                "SCAN_ALLOWED_TARGETS",
                "localhost,127.0.0.1,::1,pushups-omega.vercel.app",
            ).split(",")
            if host.strip()
        )
        return cls(
            environment_type=os.getenv("SCAN_ENVIRONMENT", "self_hosted").strip().lower(),
            gitleaks_enabled=_read_bool("GITLEAKS_ENABLED", True),
            trivy_enabled=_read_bool("TRIVY_ENABLED", True),
            nmap_enabled=_read_bool("NMAP_ENABLED", True),
            zap_enabled=_read_bool("ZAP_ENABLED", True),
            allowed_targets=allowed_targets,
            project_root=project_root,
            report_dir=Path(
                os.getenv(
                    "SCAN_REPORT_DIR",
                    str(Path(__file__).resolve().parents[1] / "reports"),
                )
            ),
            gitleaks_command=_read_command(
                "GITLEAKS_COMMAND",
                _scanner_default(project_root, "gitleaks", ("gitleaks", "dir")),
            ),
            trivy_command=_read_command(
                "TRIVY_COMMAND", _scanner_default(project_root, "trivy", ("trivy",))
            ),
            nmap_command=_read_command("NMAP_COMMAND", ("nmap",)),
            zap_api_url=os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/"),
            zap_api_key=os.getenv("ZAP_API_KEY", ""),
            code_scan_timeout_seconds=int(
                os.getenv("CODE_SCAN_TIMEOUT_SECONDS", "180")
            ),
            nmap_timeout_seconds=int(os.getenv("NMAP_TIMEOUT_SECONDS", "90")),
            zap_timeout_seconds=int(os.getenv("ZAP_TIMEOUT_SECONDS", "120")),
        )

    def allows_target(self, target):
        host = target_host(target)
        return bool(host) and host in self.allowed_targets
