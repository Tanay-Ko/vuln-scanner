"""Compatibility exports for callers of the former scanner module."""

try:
    from .pipeline import PipelineConfig, run_pipeline, run_scan
except ImportError:  # Existing startup workflow runs from src/backend
    from pipeline import PipelineConfig, run_pipeline, run_scan

__all__ = ["PipelineConfig", "run_pipeline", "run_scan"]
