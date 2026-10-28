from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

try:
    from ..analysis import VulnerabilityAnalyzer
    from ..pipeline import run_pipeline
    from ..validation import TargetValidationError, validate_scan_type, validate_target
except ImportError:  # Running uvicorn main:app from src/backend
    from analysis import VulnerabilityAnalyzer
    from pipeline import run_pipeline
    from validation import TargetValidationError, validate_scan_type, validate_target


router = APIRouter(prefix="/api", tags=["scans"])


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    scanType: str = "basic"
    timeLimit: Optional[int] = Field(default=None, ge=30, le=1800)


class PipelineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    environmentType: str = "self_hosted"
    nmapEnabled: bool = False


@router.post("/pipeline")
async def pipeline_endpoint(request_body: PipelineRequest, request: Request):
    try:
        if request_body.environmentType not in {"managed", "self_hosted"}:
            raise ValueError("environmentType must be 'managed' or 'self_hosted'.")
        target = validate_target(request_body.target, "web scan")
    except (TargetValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    config = request.app.state.pipeline_config
    result = await run_in_threadpool(
        run_pipeline,
        target,
        config=config,
        environment_type=request_body.environmentType,
        scan_type="version detection",
        requested_stages=("nmap", "zap") if request_body.nmapEnabled else ("zap",),
    )
    return {"pipeline": result}


@router.post("/scan")
async def scan_endpoint(request_body: ScanRequest, request: Request):
    try:
        scan_type = validate_scan_type(request_body.scanType)
        target = validate_target(request_body.target, scan_type)
    except (TargetValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    pipeline_config = getattr(request.app.state, "pipeline_config", None)
    if pipeline_config is not None and not pipeline_config.allows_target(target):
        raise HTTPException(
            status_code=403,
            detail="Target is not in SCAN_ALLOWED_TARGETS.",
        )

    result = await run_in_threadpool(
        request.app.state.scan_engine,
        target,
        scan_type,
        request_body.timeLimit,
    )
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="Scanner returned an invalid response.")
    if result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])
    if scan_type != "web scan":
        ports = result.get("open_ports")
        if not isinstance(ports, list) or any(not isinstance(port, dict) for port in ports):
            raise HTTPException(status_code=502, detail="Scanner returned invalid port results.")

    if scan_type == "version detection" and result.get("open_ports"):
        analysis = await run_in_threadpool(
            VulnerabilityAnalyzer(request.app.state.vulnerability_client).analyze_ports,
            [port for port in result["open_ports"] if port.get("state") == "open"],
        )
        result["vulnerability_analysis"] = analysis
        by_port = {entry["port"]: entry for entry in analysis["vulnerable_ports"]}
        for port in result["open_ports"]:
            match = by_port.get(port.get("port"))
            if match:
                port["cves"] = match["vulnerabilities"]
                port["recommendations"] = match["recommendations"]

    if scan_type != "web scan":
        try:
            request.app.state.database.save_scan_snapshot(
                target, scan_type, result.get("scan_time"), result.get("open_ports", [])
            )
        except Exception:
            raise HTTPException(
                status_code=500, detail="The scan completed, but results could not be saved."
            )
    return result
