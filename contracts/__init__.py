"""Executable agent data contracts for Multi-Agent SOC Detection System."""

from .security_event import SecurityEvent
from .feature_vector import FeatureVector
from .anomaly_result import AnomalyResult

__all__ = [
    "SecurityEvent",
    "FeatureVector",
    "AnomalyResult",
]
