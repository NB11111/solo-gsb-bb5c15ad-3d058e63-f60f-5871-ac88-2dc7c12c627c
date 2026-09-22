"""双向解析器单元测试，覆盖 UAX #9 显式格式/隔离配对规则。"""

from __future__ import annotations

from app.bidi import analyze_text


def _cp(code: int) -> str:
    return chr(code)


def _findings(result):
    return result["findings"]


def _openers(result):
    return [f for f in _findings(result) if f["type"] == "opener"]


def _closers(result):
    return [f for f in _findings(result) if f["type"] == "closer"]


def test_clean_text_is_none_risk():
    r = analyze_text("plain ascii text")
    assert r["risk_level"] == "none"
    assert r["findings"] == []
    assert r["dangerous_spans"] == []
    assert r["statistics"]["total_control_chars"] == 0


def test_matched_embedding_and_pdf():
    text = f"a{_cp(0x202A)}xy{_cp(0x202C)}b"
    r = analyze_text(text)
    op, cl = _openers(r)[0], _closers(r)[0]
    assert op["abbreviation"] == "LRE"
    assert op["matched"] is True and op["unclosed"] is False
    assert op["kind"] == "embedding"
    assert op["closer"]["abbreviation"] == "PDF"
    assert op["closer"]["logical_index"] == 4
    assert cl["matched"] is True
    assert cl["matches"]["abbreviation"] == "LRE"
    # 影响范围含控制符 [1, 5)，内部范围 [2, 4)
    assert op["influence_span"]["start"] == 1
    assert op["influence_span"]["end"] == 5
    assert op["inner_span"]["raw_preview"] == "xy"
    # 转义预览保持逻辑顺序
    assert op["influence_span"]["escaped_preview"] == "\\u202axy\\u202c"
    assert op["influence_span"]["named_preview"] == "<LRE>xy<PDF>"
    # 配对成功的嵌入为 medium
    assert op["severity"] == "medium"
    assert r["risk_level"] == "medium"


def test_rlo_override_is_high_and_has_visual_preview():
    text = f"filename_{_cp(0x202E)}txt.exe{_cp(0x202C)}.js"
    r = analyze_text(text)
    op = _openers(r)[0]
    assert op["abbreviation"] == "RLO"
    assert op["kind"] == "override"
    assert op["severity"] == "high"
    assert r["risk_level"] == "high"
    span = r["dangerous_spans"][0]
    # RLO 把内部 "txt.exe" 近似反转为 "exe.txt"
    assert span["approx_visual_preview"] == "txt.exe"[::-1] == "exe.txt"
    assert "\\u202e" in span["escaped_preview"]
    # 原文没有被改写
    assert text.startswith("filename_")


def test_unclosed_embedding_runs_to_paragraph_end():
    text = f"x{_cp(0x202B)}abc"
    r = analyze_text(text)
    op = _openers(r)[0]
    assert op["matched"] is False
    assert op["unclosed"] is True
    assert op["severity"] == "high"
    assert op["influence_span"]["end"] == len(text)
    assert op["closer"] is None
    assert r["statistics"]["unclosed"] == 1


def test_unclosed_resets_at_paragraph_boundary():
    # RLE 在第一段未闭合；换行后新段落不应继承
    text = f"{_cp(0x202B)}abc\nxy"
    r = analyze_text(text)
    op = _openers(r)[0]
    assert op["unclosed"] is True
    assert op["paragraph"] == 0
    assert op["influence_span"]["end"] == 4  # 不含换行符
    assert _cp(0x202B) not in text[5:]
    assert r["statistics"]["paragraph_count"] == 2


def test_stray_pdf_and_stray_pdi():
    text = f"a{_cp(0x202C)}b{_cp(0x2069)}"
    r = analyze_text(text)
    pdf_f, pdi_f = _closers(r)
    assert pdf_f["abbreviation"] == "PDF" and pdf_f["matched"] is False
    assert pdf_f["severity"] == "high"
    assert pdi_f["abbreviation"] == "PDI" and pdi_f["matched"] is False
    assert r["statistics"]["stray_closers"] == 2


def test_pdf_does_not_cross_isolate_boundary():
    # RLI [ RLE ... PDF ] —— PDF 关闭 RLE；再来一个 PDF 无嵌入可关 -> stray；
    # 最后 PDI 关闭 RLI
    text = (
        f"{_cp(0x2067)}{_cp(0x202A)}z{_cp(0x202C)}"
        f"{_cp(0x202C)}{_cp(0x2069)}"
    )
    r = analyze_text(text)
    pdfs = [f for f in _closers(r) if f["abbreviation"] == "PDF"]
    assert pdfs[0]["matched"] is True
    assert pdfs[0]["matches"]["abbreviation"] == "LRE"
    assert pdfs[1]["matched"] is False  # 栈顶是 RLI，PDF 不能跨隔离
    pdi = next(f for f in _closers(r) if f["abbreviation"] == "PDI")
    assert pdi["matched"] is True
    assert pdi["matches"]["abbreviation"] == "RLI"


def test_pdi_auto_closes_open_embeddings():
    # LRI [ RLE abc ] PDI：RLE 没有 PDF，由 PDI 自动闭合
    text = f"{_cp(0x2066)}{_cp(0x202B)}abc{_cp(0x2069)}"
    r = analyze_text(text)
    by_abbr = {f["abbreviation"]: f for f in _openers(r)}
    rle, lri = by_abbr["RLE"], by_abbr["LRI"]
    assert rle["unclosed"] is False
    assert rle["closer"]["abbreviation"] == "PDI"
    assert rle["closer"]["auto_closed"] is True
    assert lri["closer"]["abbreviation"] == "PDI"
    assert lri["closer"]["auto_closed"] is False
    assert r["statistics"]["auto_closed"] == 1


def test_fsi_resolves_direction_by_first_strong_char():
    # FSI + 希伯来字母（强 RTL）… PDI => 解析为 RLI
    text = f"{_cp(0x2068)}אבג{_cp(0x2069)}"
    r = analyze_text(text)
    op = _openers(r)[0]
    assert op["abbreviation"] == "FSI"
    span = r["dangerous_spans"][0]
    assert span["resolved_abbreviation"] == "RLI"
    assert span["resolved_base_direction"] == "rtl"

    text2 = f"{_cp(0x2068)}abc{_cp(0x2069)}"
    r2 = analyze_text(text2)
    assert r2["dangerous_spans"][0]["resolved_abbreviation"] == "LRI"


def test_depth_overflow_opener_is_ignored():
    text = _cp(0x202A) * 5 + "x"
    r = analyze_text(text, max_depth=3)
    openers = _openers(r)
    assert [f["overflow"] for f in openers] == [False, False, False, True, True]
    # 溢出开启符不影响范围，且前三个在段末未闭合
    assert openers[0]["unclosed"] is True
    assert openers[3]["influence_span"] is None
    assert r["statistics"]["depth_overflows"] == 2
    assert r["statistics"]["unclosed"] == 3


def test_implicit_marks_are_low_severity_without_span():
    text = f"a{_cp(0x200F)}b{_cp(0x200E)}"
    r = analyze_text(text)
    assert r["risk_level"] == "low"
    marks = [f for f in _findings(result=r) if f["type"] == "implicit_mark"]
    assert [m["abbreviation"] for m in marks] == ["RLM", "LRM"]
    assert all(m["influence_span"] is None for m in marks)
    assert r["dangerous_spans"] == []


def test_nested_overrides_span_ranges():
    # 索引: 0 RLO,1 a,2 LRO,3 b,4 PDF,5 c,6 PDF —— 总长 7
    text = f"{_cp(0x202E)}a{_cp(0x202D)}b{_cp(0x202C)}c{_cp(0x202C)}"
    r = analyze_text(text)
    spans = sorted(r["dangerous_spans"], key=lambda s: s["start"])
    # 外层 RLO 区 [0,7)，内层 LRO 区 [2,5)
    assert (spans[0]["start"], spans[0]["end"]) == (0, 7)
    assert (spans[1]["start"], spans[1]["end"]) == (2, 5)
    assert all(s["severity"] == "high" for s in spans)
