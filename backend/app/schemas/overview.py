from pydantic import BaseModel, Field


class TrendPoint(BaseModel):
    bucket: str
    events: int = Field(ge=0)
    alerts: int = Field(ge=0)


class OverviewRead(BaseModel):
    event_count: int = Field(ge=0)
    alert_count: int = Field(ge=0)
    critical_alert_count: int = Field(ge=0)
    high_risk_chain_count: int = Field(ge=0)
    chain_count: int = Field(ge=0)
    source_counts: dict[str, int]
    trend: list[TrendPoint]
