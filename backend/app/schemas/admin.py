import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.enums import ReportStatus, RiskLevel


class DashboardReport(BaseModel):
    id: uuid.UUID
    phone: str
    report_type: str
    status: ReportStatus
    created_at: datetime


class AdminDashboardOut(BaseModel):
    fraud_reports: int = 0
    active_investigations: int = 0
    suspicious_signals: int = 0
    connected_partners: int = 0
    reports_today: int
    pending_review: int
    numbers_protected: int
    high_risk_blocked: int
    risk_distribution: dict[RiskLevel, int]
    recent_reports: list[DashboardReport]
    feedback_summary: dict[str, int] = Field(default_factory=dict)
    feedback_effectiveness: dict[str, float | int] = Field(default_factory=dict)


class PartnerStatusUpdate(BaseModel):
    partner_status: Literal["active", "inactive"]
