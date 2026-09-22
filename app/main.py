"""FastAPI application: Unicode bidirectional text security audit API."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from .bidi import RiskLevel, parse_bidi
from .database import count_audits, get_audit, init_db, insert_audit, query_audits
from .schemas import AuditRequest

app = FastAPI(
    title="Unicode Bidi Text Security Audit API",
    description=(
        "Audits text for Unicode bidirectional control characters "
        "(U+202A..U+2069, marks, invisible operators). Reports codepoints, "
        "logical indices, pairing/nesting scope, unclosed-character errors "
        "and produces escaped previews of dangerous spans without modifying "
        "the original text."
    ),
    version="1.0.0",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "bidi-audit"}


@app.post("/api/v1/audits", status_code=201)
def create_audit(payload: AuditRequest) -> dict:
    """Parse and audit one text payload, persist the record."""
    result = parse_bidi(payload.text).to_dict()
    audit_id = insert_audit(
        filename=payload.filename, text=payload.text, result=result
    )
    return {"id": audit_id, "risk_level": result["risk_level"],
            "stored": True, "result": result}


@app.get("/api/v1/audits")
def list_audits(
    risk_level: Optional[RiskLevel] = Query(
        default=None, description="Filter by risk level "
        "(info|low|medium|high|critical)"
    ),
    filename: Optional[str] = Query(
        default=None, description="Case-insensitive substring match on filename"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rl = risk_level.value if risk_level is not None else None
    items = query_audits(risk_level=rl, filename=filename,
                         limit=limit, offset=offset)
    total = count_audits(risk_level=rl, filename=filename)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/audits/{audit_id}")
def read_audit(audit_id: int) -> dict:
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return record


@app.get("/")
def root() -> dict:
    return {
        "service": "bidi-audit",
        "docs": "/docs",
        "endpoints": [
            "POST /api/v1/audits",
            "GET  /api/v1/audits",
            "GET  /api/v1/audits/{id}",
            "GET  /health",
        ],
    }
