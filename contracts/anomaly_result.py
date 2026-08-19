"""AnomalyResult executable data contract."""

from typing import Optional
from pydantic import BaseModel, Field


class AnomalyResult(BaseModel):
    """Anomaly detection result payload produced by Agent 4 for Agent 5 threat fusion."""

    result_id: str = Field(..., description="Unique evaluation result identifier (UUIDv4)")
    vector_id: str = Field(..., description="Unique ID of evaluated FeatureVector")
    event_id: str = Field(..., description="Unique ID of originating SecurityEvent")
    timestamp_utc: str = Field(..., description="UTC timestamp of inference completion")
    is_anomaly: bool = Field(..., description="Binary decision classification (Required)")
    anomaly_score: float = Field(
        ..., description="Raw decision score from ML model (Required, e.g. Isolation Forest decision score)"
    )
    calibrated_confidence: Optional[float] = Field(
        None, description="Empirical probability score [0.0, 1.0] (Optional until calibrated)"
    )
    calibration_method: Optional[str] = Field(
        "UNALIGNED_RAW", description="Method tag (PLATT_SCALING, ISOTONIC_REGRESSION, UNALIGNED_RAW)"
    )
    model_id: str = Field(..., description="Unique model registry identifier")
    model_version: str = Field(..., description="Model artifact version hash")
