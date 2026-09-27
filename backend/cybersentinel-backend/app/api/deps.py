from __future__ import annotations
import logging
from typing import Any

from fastapi import HTTPException, status

from app.config import settings

logger = logging.getLogger(__name__)

_alert_manager_instance: Any = None
_inference_engine_instance: Any = None
_alert_broadcaster_instance: Any = None

# Why this exists
# ---------------
# The engine used to fail to import (a missing `pandas`) and the app carried on
# serving pre-seeded rows from SQLite. Every endpoint returned 200, the UI lit
# up green, and nothing was actually being detected. There was no way to tell
# "detector says this flow is clean" apart from "no detector ran at all".
#
# So engine state is now explicit and recorded. A failure is remembered here
# with its cause, /health reports degraded, and any endpoint whose answer
# depends on inference returns 503 with that cause instead of a plausible lie.
_engine_error: str | None = None


def set_alert_manager(am: Any):
    global _alert_manager_instance
    _alert_manager_instance = am


def set_inference_engine(ie: Any):
    global _inference_engine_instance, _engine_error
    _inference_engine_instance = ie
    if ie is not None:
        _engine_error = None


def set_engine_error(err: str):
    """Record why the inference engine is unavailable."""
    global _engine_error, _inference_engine_instance
    _engine_error = err
    _inference_engine_instance = None
    logger.error("Inference engine marked UNAVAILABLE: %s", err)


def get_engine_error() -> str | None:
    return _engine_error


def engine_ready() -> bool:
    return _inference_engine_instance is not None


def set_alert_broadcaster(ab: Any):
    global _alert_broadcaster_instance
    _alert_broadcaster_instance = ab


def get_settings() -> Any:
    return settings


def get_alert_manager() -> Any:
    return _alert_manager_instance


def get_inference_engine() -> Any:
    return _inference_engine_instance


def get_alert_broadcaster() -> Any:
    return _alert_broadcaster_instance


def require_inference_engine() -> Any:
    """FastAPI dependency for endpoints whose data comes from live inference.

    Raises 503 rather than returning stale or empty results, so a broken engine
    is visible to the caller instead of looking like "no threats found".
    """
    if _inference_engine_instance is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "inference_engine_unavailable",
                "message": "Detection engine is not loaded; results would be incomplete.",
                "cause": _engine_error or "unknown initialisation failure",
            },
        )
    return _inference_engine_instance


def require_alert_manager() -> Any:
    """FastAPI dependency for endpoints that read the alert store."""
    if _alert_manager_instance is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "alert_store_unavailable",
                "message": "Alert manager is not initialised.",
            },
        )
    return _alert_manager_instance
