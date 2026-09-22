"""FastAPI 应用入口。"""

from __future__ import annotations

import hashlib
from typing import Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse

from . import __version__
from .bidi import analyze_text
from .config import settings
from .db import VALID_RISK, get_audit, init_db, insert_audit, query_audits, risk_counts
from .models import AuditCreated, AuditDetail, AuditList, AuditRequest, RiskStats


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Unicode Bidi Safety Audit API",
    description=(
        "审计 Unicode 双向控制字符（RLO/LRO/RLE/LRE/RLI/LRI/FSI/PDF/PDI 及"
        " LRM/RLM/ALM 等隐式标记）的安全审计服务。解析控制符配对与嵌套，"
        "报告码点、逻辑索引、影响范围与未闭合错误，并为危险区段生成保持"
        "可读顺序的转义预览。输入文本原样存储，不会被改写。"
    ),
    version=__version__,
    lifespan=lifespan,
)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/api/v1/audits", response_model=AuditCreated, status_code=201, tags=["audits"])
def create_audit(payload: AuditRequest) -> AuditCreated:
    filename = payload.filename.strip() if payload.filename and payload.filename.strip() else None
    raw_bytes = payload.text.encode("utf-8")

    result = analyze_text(payload.text, max_depth=settings.max_depth)
    statistics = result["statistics"]
    # 报告中附上原始文本与来源信息，详情查询时可完整复核
    report = {
        "filename": filename,
        "text": payload.text,
        "risk_level": result["risk_level"],
        "findings": result["findings"],
        "dangerous_spans": result["dangerous_spans"],
        "statistics": statistics,
        "max_depth": result["max_depth"],
        "note": (
            "all previews are read-only views in logical order; "
            "the submitted text is stored and returned verbatim"
        ),
    }

    audit_id = insert_audit(
        filename=filename,
        text_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        text_bytes=len(raw_bytes),
        char_count=len(payload.text),
        risk_level=result["risk_level"],
        statistics=statistics,
        report=report,
    )
    stored = get_audit(audit_id)
    assert stored is not None
    return AuditCreated(
        id=audit_id,
        filename=filename,
        risk_level=stored["risk_level"],
        statistics=stored["statistics"],
        report=report,
        text_sha256=stored["text_sha256"],
        created_at=stored["created_at"],
    )


@app.get("/api/v1/audits", response_model=AuditList, tags=["audits"])
def list_audits(
    risk_level: Optional[str] = Query(default=None, description="按风险级别精确过滤"),
    filename: Optional[str] = Query(default=None, description="按文件名过滤"),
    fuzzy_filename: bool = Query(default=False, description="文件名使用子串匹配而非精确匹配"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditList:
    if risk_level is not None and risk_level not in VALID_RISK:
        raise HTTPException(
            status_code=422,
            detail=f"invalid risk_level; expected one of {', '.join(VALID_RISK)}",
        )
    items, total = query_audits(
        risk_level=risk_level,
        filename=filename,
        fuzzy_filename=fuzzy_filename,
        limit=limit,
        offset=offset,
    )
    return AuditList(total=total, limit=limit, offset=offset, items=items)


@app.get("/api/v1/audits/{audit_id}", response_model=AuditDetail, tags=["audits"])
def get_audit_detail(audit_id: int) -> AuditDetail:
    row = get_audit(audit_id)
    if row is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return AuditDetail(**row)


@app.get("/api/v1/stats/risk", response_model=RiskStats, tags=["stats"])
def get_risk_stats() -> RiskStats:
    return RiskStats(**risk_counts())
