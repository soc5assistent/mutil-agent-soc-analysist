"""FeatureVector executable data contract."""

import math
from typing import List
from pydantic import BaseModel, Field, field_validator


class FeatureVector(BaseModel):
    """Sanitized, non-NaN numerical feature vector produced by Agent 3 for Agent 4 inference."""

    vector_id: str = Field(..., description="Unique feature vector identifier (UUIDv4)")
    event_id: str = Field(..., description="Unique ID of triggering SecurityEvent")
    timestamp_utc: str = Field(..., description="UTC timestamp of feature extraction completion")
    features: List[float] = Field(..., description="Dense array of preprocessed, scaled 64-bit float values")
    feature_names: List[str] = Field(..., description="Ordered list of feature column names")
    feature_pipeline_version: str = Field(..., description="Hash/tag of feature extraction logic & ordering")
    scaling_version: str = Field(..., description="Hash/tag of fitted scaler pipeline artifacts")
    model_compatibility_tag: str = Field(..., description="Target model family identifier (e.g., IFOREST_27D_V1)")
    is_normalized: bool = Field(True, description="True if feature values are scaled/normalized")

    @field_validator("features")
    @classmethod
    def validate_finite_numerical_values(cls, v: List[float]) -> List[float]:
        """Validates that features array contains only finite float numbers (rejecting NaN, Inf, -Inf)."""
        for idx, val in enumerate(v):
            if val is None or math.isnan(val) or math.isinf(val):
                raise ValueError(
                    f"FeatureVector features contains non-finite numerical value at index {idx}: {val}"
                )
        return v

    @field_validator("feature_names")
    @classmethod
    def validate_dimension_match(cls, v: List[str], info) -> List[str]:
        """Validates that feature_names length matches features array length."""
        features = info.data.get("features")
        if features is not None and len(v) != len(features):
            raise ValueError(
                f"FeatureVector feature_names length ({len(v)}) does not match features length ({len(features)})"
            )
        return v
