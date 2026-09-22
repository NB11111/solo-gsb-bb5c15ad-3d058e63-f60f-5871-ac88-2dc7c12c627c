"""Pydantic 请求/响应模型。"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

RiskLevel = Literal["none", "low", "medium", "high", "critical"]


class AuditRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        description="待审计的原始文本（原样保存，绝不改写）",
        examples=["if access_level‮ != user‮ { ... }"],
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="可选的来源文件名；纯空白字符串按未提供处理",
        examples=["login.rs"],
    )


class AuditCreated(BaseModel):
    id: int
    filename: Optional[str]
    risk_level: RiskLevel
    statistics: dict
    report: dict
    text_sha256: str
    created_at: str


class AuditSummary(BaseModel):
    id: int
    filename: Optional[str]
    text_sha256: str
    text_bytes: int
    char_count: int
    risk_level: RiskLevel
    statistics: dict
    created_at: str


class AuditList(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AuditSummary]


class AuditDetail(AuditSummary):
    report: dict


class RiskStats(BaseModel):
    total: int
    none: int
    low: int
    medium: int
    high: int
    critical: int
