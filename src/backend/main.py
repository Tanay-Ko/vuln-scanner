"""FastAPI application factory and route registration."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from functools import partial

try:
    from .database import VulnerabilityDB
    from .pipeline import PipelineConfig, run_scan
    from .routes.scans import router as scans_router
    from .routes.vulnerabilities import router as vulnerabilities_router
    from .vulnerability_api import OnlineVulnerabilityService
except ImportError:  # Existing startup workflow runs from src/backend as main:app
    from database import VulnerabilityDB
    from pipeline import PipelineConfig, run_scan
    from routes.scans import router as scans_router
    from routes.vulnerabilities import router as vulnerabilities_router
    from vulnerability_api import OnlineVulnerabilityService


def create_app(
    database=None,
    scan_engine=None,
    vulnerability_client=None,
    pipeline_config=None,
):
    app = FastAPI(title="Vulnerability Scanner API")
    app.state.database = database or VulnerabilityDB()
    app.state.pipeline_config = pipeline_config or PipelineConfig.from_env()
    app.state.scan_engine = scan_engine or partial(
        run_scan, config=app.state.pipeline_config
    )
    app.state.vulnerability_client = vulnerability_client or OnlineVulnerabilityService()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    app.include_router(scans_router)
    app.include_router(vulnerabilities_router)
    return app


app = create_app()
