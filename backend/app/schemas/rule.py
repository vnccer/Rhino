import re
from datetime import timedelta
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RuleSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORES = {
    RuleSeverity.LOW: 25,
    RuleSeverity.MEDIUM: 50,
    RuleSeverity.HIGH: 75,
    RuleSeverity.CRITICAL: 100,
}
SUPPORTED_OPERATORS = {"eq", "ne", "in", "not_in", "contains", "starts_with", "regex", "exists"}


def _validate_match_expression(match: dict[str, Any]) -> dict[str, Any]:
    for field, expression in match.items():
        if not field:
            raise ValueError("match field names cannot be empty")
        if not isinstance(expression, dict):
            continue
        unsupported = set(expression) - SUPPORTED_OPERATORS
        if unsupported:
            raise ValueError(f"unsupported match operators: {sorted(unsupported)}")
        if not expression:
            raise ValueError("operator expressions cannot be empty")
        if "exists" in expression and not isinstance(expression["exists"], bool):
            raise ValueError("the exists operator requires a boolean")
        for operator in ("in", "not_in"):
            if operator in expression and not isinstance(expression[operator], list):
                raise ValueError(f"the {operator} operator requires a list")
        if "regex" in expression:
            re.compile(str(expression["regex"]))
    return match


class CountConditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["count"]
    match: dict[str, Any] = Field(min_length=1)
    group_by: list[str] = Field(default_factory=list)
    distinct_by: str | None = None

    _validate_match = field_validator("match")(_validate_match_expression)


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    match: dict[str, Any] = Field(min_length=1)
    min_count: int = Field(default=1, ge=1)

    _validate_match = field_validator("match")(_validate_match_expression)


class SequenceConditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["sequence"]
    ordered: list[SequenceStep] = Field(min_length=2)
    group_by: list[str] = Field(default_factory=list)


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=1)
    conditions: CountConditions | SequenceConditions = Field(discriminator="type")
    window: timedelta
    threshold: int = Field(ge=1)
    severity: RuleSeverity
    mitre: list[str] = Field(min_length=1)

    @field_validator("window", mode="before")
    @classmethod
    def parse_window(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        units = {"s": 1, "m": 60, "h": 3600}
        try:
            amount = int(value[:-1])
            seconds = amount * units[value[-1].lower()]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("window must use a positive duration such as 30s, 5m, or 1h") from exc
        if seconds <= 0:
            raise ValueError("window must be positive")
        return timedelta(seconds=seconds)

    @model_validator(mode="after")
    def validate_mitre_ids(self) -> "DetectionRule":
        if any(not technique.startswith("T") for technique in self.mitre):
            raise ValueError("MITRE technique identifiers must start with T")
        if isinstance(self.conditions, SequenceConditions) and self.threshold != 1:
            raise ValueError("sequence rules currently require threshold: 1")
        return self
