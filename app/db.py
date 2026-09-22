"""SQLite 访问层（同步驱动，每个请求独立连接）。"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional

from .config import settings

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def _connect(db_path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """创建数据目录与表结构；容器启动和 init_db.py 都会调用。"""
    path = db_path or settings.db_path
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()
    conn = _connect(path)
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = _connect(settings.db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_audit(*, filename: Optional[str], text_sha256: str, text_bytes: int,
                 char_count: int, risk_level: str, statistics: dict,
                 report: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO audits
                (filename, text_sha256, text_bytes, char_count,
                 risk_level, statistics, report)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                text_sha256,
                text_bytes,
                char_count,
                risk_level,
                json.dumps(statistics, ensure_ascii=False),
                json.dumps(report, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)


def _row_to_summary(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "filename": row["filename"],
        "text_sha256": row["text_sha256"],
        "text_bytes": row["text_bytes"],
        "char_count": row["char_count"],
        "risk_level": row["risk_level"],
        "statistics": json.loads(row["statistics"]),
        "created_at": row["created_at"],
    }


def _row_to_detail(row: sqlite3.Row) -> dict:
    summary = _row_to_summary(row)
    report = json.loads(row["report"])
    return {**summary, "report": report}


VALID_RISK = ("none", "low", "medium", "high", "critical")


def query_audits(
    *,
    risk_level: Optional[str] = None,
    filename: Optional[str] = None,
    fuzzy_filename: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    clauses: list[str] = []
    params: list[object] = []
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level)
    if filename:
        if fuzzy_filename:
            clauses.append("filename LIKE ?")
            params.append(f"%{filename}%")
        else:
            clauses.append("filename = ?")
            params.append(filename)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    with get_conn() as conn:
        total = int(
            conn.execute(f"SELECT COUNT(*) AS c FROM audits {where}", params).fetchone()["c"]
        )
        rows = conn.execute(
            f"""
            SELECT * FROM audits {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
    return [_row_to_summary(r) for r in rows], total


def get_audit(audit_id: int) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    return _row_to_detail(row) if row else None


def risk_counts() -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT risk_level, COUNT(*) AS c FROM audits GROUP BY risk_level"
        ).fetchall()
    counts = {level: 0 for level in VALID_RISK}
    for row in rows:
        counts[row["risk_level"]] = row["c"]
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts
