"""FastAPI 端到端测试（临时 SQLite 文件，互不影响真实数据）。"""

from __future__ import annotations

import importlib
import os
import tempfile

import pytest

# 在导入 app 之前指定临时数据库
_TMPDIR = tempfile.mkdtemp(prefix="bidi-test-")
os.environ["BIDI_DB_PATH"] = os.path.join(_TMPDIR, "test.db")
os.environ["BIDI_MAX_DEPTH"] = "60"

from fastapi.testclient import TestClient  # noqa: E402

import app.config as config_module  # noqa: E402

importlib.reload(config_module)
import app.db as db_module  # noqa: E402

importlib.reload(db_module)
import app.main as main_module  # noqa: E402

importlib.reload(main_module)


@pytest.fixture(scope="module")
def client():
    main_module.init_db()
    with TestClient(main_module.app) as c:
        yield c


RLO = "‮"
PDF = "‬"


def test_health_and_docs(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/").status_code in (200, 307)


def test_create_audit_stores_verbatim_and_reports(client):
    payload_text = f"admin{ RLO }@user{ PDF }"
    resp = client.post("/api/v1/audits", json={"text": payload_text, "filename": "login.rs"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["risk_level"] == "high"
    assert body["filename"] == "login.rs"
    # 原文原样保存，未被改写
    assert body["report"]["text"] == payload_text
    findings = body["report"]["findings"]
    opener = next(f for f in findings if f["abbreviation"] == "RLO")
    assert opener["code_point"] == "U+202E"
    assert opener["logical_index"] == 5
    assert opener["paragraph"] == 0
    assert opener["closer"]["abbreviation"] == "PDF"
    assert "\\u202e" in opener["influence_span"]["escaped_preview"]


def test_blank_filename_becomes_none(client):
    resp = client.post("/api/v1/audits", json={"text": "  "})
    # 空白文本本身允许（min_length=1），但没有控制符
    assert resp.status_code == 201
    assert resp.json()["risk_level"] == "none"

    resp = client.post("/api/v1/audits", json={"text": "x", "filename": "   "})
    assert resp.json()["filename"] is None


def test_list_filter_by_risk_and_filename(client):
    client.post("/api/v1/audits", json={"text": f"{RLO}x{PDF}", "filename": "evil.rs"})
    client.post("/api/v1/audits", json={"text": "clean", "filename": "clean.rs"})

    high = client.get("/api/v1/audits", params={"risk_level": "high"}).json()
    assert high["total"] >= 1
    assert all(i["risk_level"] == "high" for i in high["items"])

    exact = client.get(
        "/api/v1/audits", params={"filename": "evil.rs"}
    ).json()
    assert all(i["filename"] == "evil.rs" for i in exact["items"])

    fuzzy = client.get(
        "/api/v1/audits", params={"filename": "evil", "fuzzy_filename": "true"}
    ).json()
    assert fuzzy["total"] >= 1 and all("evil" in (i["filename"] or "") for i in fuzzy["items"])

    bad = client.get("/api/v1/audits", params={"risk_level": "bogus"})
    assert bad.status_code == 422


def test_detail_and_404(client):
    created = client.post(
        "/api/v1/audits", json={"text": f"a{RLO}b{PDF}", "filename": "d.txt"}
    ).json()
    detail = client.get(f"/api/v1/audits/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["report"]["findings"]
    assert client.get("/api/v1/audits/99999999").status_code == 404


def test_risk_stats(client):
    stats = client.get("/api/v1/stats/risk").json()
    assert stats["total"] == sum(
        stats[k] for k in ("none", "low", "medium", "high", "critical")
    )
    assert stats["high"] >= 1


def test_empty_text_rejected(client):
    resp = client.post("/api/v1/audits", json={"text": ""})
    assert resp.status_code == 422
