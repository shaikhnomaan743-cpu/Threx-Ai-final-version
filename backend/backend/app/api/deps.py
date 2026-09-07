from __future__ import annotations
import logging
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

_alert_manager_instance: Any = None
_inference_engine_instance: Any = None
_alert_broadcaster_instance: Any = None


def set_alert_manager(am: Any):
    global _alert_manager_instance
    _alert_manager_instance = am

def set_inference_engine(ie: Any):
    global _inference_engine_instance
    _inference_engine_instance = ie

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
