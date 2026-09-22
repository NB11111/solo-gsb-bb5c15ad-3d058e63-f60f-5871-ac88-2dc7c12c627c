"""Pydantic schemas for the audit API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .bidi import RiskLevel


class AuditRequest(BaseModel):
    text: str = Field(..., description="Text to audit. Sent verbatim; never rewritten.")
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class AuditCreated(BaseModel):
    id: int
    risk_level: RiskLevel
    stored: bool = True
    result: dict
