"""Unicode 双向控制字符解析与审计核心。

解析规则参考 Unicode Standard Annex #9 (Unicode Bidirectional Algorithm)
的显式嵌入/覆盖 (X2-X8) 与显式隔离 (X5a-X6c) 规则，只做控制符层面的
结构分析，不做完整的 UBA 重排序，因此结果对任何渲染器都是确定的：

* RLE/LRE/RLO/LRO + PDF 为一组“嵌入/覆盖”，嵌套在栈中；
* RLI/LRI/FSI + PDI 为一组“隔离”，嵌套在栈中；
* PDF 只终结当前隔离层内最顶层的嵌入/覆盖，不能跨隔离匹配；
* PDI 终结最顶层的隔离，隔离内尚未闭合的嵌入/覆盖会被自动闭合；
* 隔离层遇到段落分隔符会被强制终止；
* 超过深度上限 (UBA 为 63) 的开启符属于溢出，UBA 会忽略它；
* FSI 的方向按“首个强类型字符”近似解析，解析不到强类型时视为 RLI。

解析器只报告事实（码点、索引、影响范围、配对情况），危险区段的转义
预览是基于逻辑顺序额外生成的视图，输入文本本身在任何环节都不会被改写。
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Optional

# --- 显式双向格式字符 -------------------------------------------------------

EXPLICIT_OPENERS = {
    0x202A: ("LRE", "left-to-right embedding", "embedding"),
    0x202B: ("RLE", "right-to-left embedding", "embedding"),
    0x202D: ("LRO", "left-to-right override", "override"),
    0x202E: ("RLO", "right-to-left override", "override"),
}
ISOLATE_OPENERS = {
    0x2066: ("LRI", "left-to-right isolate", "isolate"),
    0x2067: ("RLI", "right-to-left isolate", "isolate"),
    0x2068: ("FSI", "first strong isolate", "isolate"),
}
ALL_OPENERS = {**EXPLICIT_OPENERS, **ISOLATE_OPENERS}

PDF = 0x202C  # POP DIRECTIONAL FORMATTING
PDI = 0x2069  # POP DIRECTIONAL ISOLATE

# 隐式方向标记（零宽，无配对）：LRM / RLM / ALM
IMPLICIT_MARKS = {
    0x200E: ("LRM", "left-to-right mark"),
    0x200F: ("RLM", "right-to-left mark"),
    0x061C: ("ALM", "arabic letter mark"),
}

# 其他影响逻辑顺序可读性的不可见格式字符（提示性质，low）
OTHER_INVISIBLES = {
    0x200D: "ZERO WIDTH JOINER",
    0x200C: "ZERO WIDTH NON-JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x2060: "WORD JOINER",
    0x00AD: "SOFT HYPHEN",
}

# UBA 段落分隔符：B 类
PARAGRAPH_SEPARATORS = frozenset("\n\v\f\r  ")

# 风险级别
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"
RISK_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

_EFFECT = {
    "LRE": "forces nested run to left-to-right embedding",
    "RLE": "forces nested run to right-to-left embedding",
    "LRO": "FORCES every nested character to left-to-right (visual override)",
    "RLO": "FORCES every nested character to right-to-left (visual override)",
    "LRI": "isolates nested run, base direction left-to-right",
    "RLI": "isolates nested run, base direction right-to-left",
    "FSI": "isolates nested run, base direction from first strong character",
    "PDF": "closes nearest embedding/override in current isolate level",
    "PDI": "closes nearest isolate (and any open embedding/override inside it)",
    "LRM": "zero-width mark forcing left-to-right direction",
    "RLM": "zero-width mark forcing right-to-left direction",
    "ALM": "zero-width mark forcing arabic (right-to-left) direction",
}


@dataclass
class _StackEntry:
    kind: str                 # embedding | override | isolate
    abbr: str                 # LRE/RLO/LRI...
    index: int                # 全局逻辑索引（码点序号）
    para: int                 # 所在段落号（0 起）
    para_offset: int          # 段内逻辑索引
    closer_index: Optional[int] = None
    closer_abbr: Optional[str] = None
    closer_para: Optional[int] = None
    auto_closed: bool = False  # 被 PDI 跨层自动闭合


@dataclass
class _Scan:
    max_depth: int
    text: str
    para: int = 0
    para_start: int = 0
    stack: list[_StackEntry] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    open_entries: list[_StackEntry] = field(default_factory=list)


def _cp(index: int, ch: str) -> dict:
    return {
        "code_point": f"U+{ord(ch):04X}",
        "char_name": unicodedata.name(ch, "<unnamed>"),
        "logical_index": index,
    }


def _location(entry: _StackEntry) -> dict:
    return {
        "paragraph": entry.para,
        "paragraph_offset": entry.para_offset,
    }


def _span(start: int, end: int, text: str) -> dict:
    """生成保持逻辑顺序的转义视图。

    escaped_preview: 所有控制符/零宽字符替换成 \\uXXXX，普通字符保留；
    named_preview:   控制符替换成 <ABBR> 形式，便于人工阅读；
    raw_preview:     原始逻辑文本（可能在等宽字体中被重排，仅作对照）。
    """
    raw = text[start:end]
    escaped_parts: list[str] = []
    named_parts: list[str] = []
    for c in raw:
        o = ord(c)
        if o in ALL_OPENERS or o in (PDF, PDI) or o in IMPLICIT_MARKS or o in OTHER_INVISIBLES:
            escaped_parts.append(f"\\u{o:04x}")
            if o in ALL_OPENERS:
                abbr = ALL_OPENERS[o][0]
            elif o == PDF:
                abbr = "PDF"
            elif o == PDI:
                abbr = "PDI"
            else:
                abbr = IMPLICIT_MARKS.get(o, ("U%04X" % o, ""))[0]
            named_parts.append(f"<{abbr}>")
        elif c in PARAGRAPH_SEPARATORS:
            escaped_parts.append(f"\\u{o:04x}")
            named_parts.append("\\n" if c == "\n" else f"\\u{o:04x}")
        else:
            escaped_parts.append(c)
            named_parts.append(c)
    return {
        "start": start,
        "end": end,
        "length": end - start,
        "raw_preview": raw,
        "escaped_preview": "".join(escaped_parts),
        "named_preview": "".join(named_parts),
    }


def _fsi_resolves_rtl(text: str, start: int) -> bool:
    """FSI 方向近似解析（X5b：首个强类型字符）。

    简化的强类型判定：R / AL 视为 RTL，L 视为 LTR；忽略 NSM、数字、
    其它中性符以及嵌套的隔离内容。找不到强类型时按 RLI 处理（UBA
    规定 PDI 前的默认段落方向为 RTL）。
    """
    depth = 0
    for i in range(start + 1, len(text)):
        ch = text[i]
        o = ord(ch)
        if o in ISOLATE_OPENERS:
            depth += 1
            continue
        if o == PDI:
            if depth == 0:
                return True  # 默认 RTL
            depth -= 1
            continue
        if depth:
            continue
        bidi_type = unicodedata.bidirectional(ch)
        if bidi_type in ("R", "AL"):
            return True
        if bidi_type == "L":
            return False
    return True


def _resolve_fsi(entry: _StackEntry, text: str, resolved_rtl: bool) -> str:
    if entry.abbr != "FSI":
        return entry.abbr
    return "RLI" if resolved_rtl else "LRI"


def _record_opener(s: _Scan, idx: int, ch: str) -> None:
    abbr, full_name, kind = ALL_OPENERS[ord(ch)]
    entry = _StackEntry(
        kind=kind, abbr=abbr, index=idx, para=s.para, para_offset=idx - s.para_start
    )
    overflow = len(s.stack) >= s.max_depth
    severity = HIGH if overflow else (HIGH if kind == "override" else MEDIUM)
    reasons = []
    if kind == "override":
        reasons.append("explicit directional override — nested characters render in forced order")
    elif kind == "isolate":
        reasons.append("directional isolate hides nested content from surrounding ordering")
    else:
        reasons.append("explicit directional embedding")
    if overflow:
        reasons.append(
            f"explicit nesting depth exceeds limit ({s.max_depth}); UBA ignores this opener"
        )

    finding = {
        **_cp(idx, ch),
        **_location(entry),
        "type": "opener",
        "abbreviation": abbr,
        "kind": kind,
        "full_name": full_name,
        "effect": _EFFECT[abbr],
        "severity": severity,
        "matched": not overflow,
        "overflow": overflow,
        "reasons": reasons,
        "deeper_isolate_depth": 0,
        "influence_span": None,   # 关闭时补齐
        "inner_span": None,
        "closer": None,
    }
    s.findings.append(finding)
    if not overflow:
        s.stack.append(entry)
        s.open_entries.append(entry)


def _close_embeddings_above(s: _Scan, isolate: _StackEntry, closer_idx: int,
                            closer_para: int, closer_abbr: str) -> None:
    """PDI 自动闭合隔离之上所有未配对的嵌入/覆盖 (X5c/X6b)。"""
    while s.stack and s.stack[-1] is not isolate:
        top = s.stack.pop()
        top.closer_index = closer_idx
        top.closer_abbr = closer_abbr
        top.closer_para = closer_para
        top.auto_closed = True


def _record_pdf(s: _Scan, idx: int) -> None:
    ch = s.text[idx]
    para = s.para
    # X7：栈顶必须是嵌入/覆盖；栈顶为隔离时 PDF 被忽略（不跨隔离匹配）
    if not s.stack or s.stack[-1].kind == "isolate":
        s.findings.append({
            **_cp(idx, ch),
            **{"paragraph": para, "paragraph_offset": idx - s.para_start},
            "type": "closer",
            "abbreviation": "PDF",
            "full_name": "pop directional formatting",
            "effect": _EFFECT["PDF"],
            "severity": HIGH,
            "matched": False,
            "reasons": ["stray PDF: no embedding/override on top of the current isolate level"],
            "matches": None,
        })
        return

    top = s.stack.pop()
    top.closer_index = idx
    top.closer_abbr = "PDF"
    top.closer_para = para
    s.findings.append({
        **_cp(idx, ch),
        **{"paragraph": para, "paragraph_offset": idx - s.para_start},
        "type": "closer",
        "abbreviation": "PDF",
        "full_name": "pop directional formatting",
        "effect": _EFFECT["PDF"],
        "severity": MEDIUM if top.kind != "override" else HIGH,
        "matched": True,
        "reasons": [],
        "matches": {
            "code_point": None,  # 由开启符的码点决定，填充时补齐
            "abbreviation": top.abbr,
            "logical_index": top.index,
        },
    })


def _record_pdi(s: _Scan, idx: int) -> None:
    ch = s.text[idx]
    para = s.para
    poff = idx - s.para_start
    # X6a：从栈顶向下找到最近的隔离；找不到则 PDI 被忽略（stray）。
    isolate = None
    for entry in reversed(s.stack):
        if entry.kind == "isolate":
            isolate = entry
            break
    if isolate is None:
        s.findings.append({
            **_cp(idx, ch),
            **{"paragraph": para, "paragraph_offset": poff},
            "type": "closer",
            "abbreviation": "PDI",
            "full_name": "pop directional isolate",
            "effect": _EFFECT["PDI"],
            "severity": MEDIUM,
            "matched": False,
            "reasons": ["stray PDI: no isolate on the formatting stack"],
            "matches": None,
        })
        return

    # X5c/X6b：先自动闭合隔离之上未配对的嵌入/覆盖，再弹出隔离本身
    auto_closed = [
        e for e in s.stack[s.stack.index(isolate) + 1:]
        if e.kind in ("embedding", "override")
    ]
    _close_embeddings_above(s, isolate, idx, para, "PDI")
    s.stack.remove(isolate)
    isolate.closer_index = idx
    isolate.closer_abbr = "PDI"
    isolate.closer_para = para

    resolved_abbr = isolate.abbr
    resolved_rtl = None
    if isolate.abbr == "FSI":
        resolved_rtl = _fsi_resolves_rtl(s.text, isolate.index)
        resolved_abbr = "RLI" if resolved_rtl else "LRI"

    s.findings.append({
        **_cp(idx, ch),
        **{"paragraph": para, "paragraph_offset": poff},
        "type": "closer",
        "abbreviation": "PDI",
        "full_name": "pop directional isolate",
        "effect": _EFFECT["PDI"],
        "severity": MEDIUM,
        "matched": True,
        "reasons": [
            f"automatically closed {len(auto_closed)} unclosed embedding/override run(s) inside isolate"
        ] if auto_closed else [],
        "matches": {
            "code_point": None,
            "abbreviation": isolate.abbr,
            "resolved_abbreviation": resolved_abbr,
            "resolved_base_direction": "rtl" if resolved_rtl else ("ltr" if resolved_rtl is False else None),
            "logical_index": isolate.index,
        },
    })


def _record_implicit(s: _Scan, idx: int, ch: str) -> None:
    abbr, full_name = IMPLICIT_MARKS[ord(ch)]
    s.findings.append({
        **_cp(idx, ch),
        **{"paragraph": s.para, "paragraph_offset": idx - s.para_start},
        "type": "implicit_mark",
        "abbreviation": abbr,
        "kind": "implicit_mark",
        "full_name": full_name,
        "effect": _EFFECT[abbr],
        "severity": LOW,
        "matched": None,
        "reasons": ["zero-width implicit directional mark; invisible but changes ordering context"],
        "influence_span": None,
    })


def _record_other_invisible(s: _Scan, idx: int, ch: str) -> None:
    s.findings.append({
        **_cp(idx, ch),
        **{"paragraph": s.para, "paragraph_offset": idx - s.para_start},
        "type": "invisible_format",
        "abbreviation": None,
        "kind": "invisible_format",
        "full_name": OTHER_INVISIBLES[ord(ch)],
        "effect": "zero-width or ambiguous formatting character invisible in most renderers",
        "severity": LOW,
        "matched": None,
        "reasons": ["invisible / zero-width formatting character"],
        "influence_span": None,
    })


def _end_paragraph(s: _Scan, para_end: int) -> None:
    """段落结束：栈中剩余条目全部未闭合 (X8/X6c)。"""
    for e in s.stack:
        e.closer_index = None
        e.closer_abbr = None
        e.closer_para = None
    s.stack.clear()
    s.para += 1
    s.para_start = para_end


def _finalize_findings(s: _Scan) -> None:
    """把栈条目上的配对/范围信息回填到开启符 finding，并生成危险区段。"""
    findings_by_index = {f["logical_index"]: f for f in s.findings if f["type"] == "opener"}

    # closer 记录里补开启符码点
    opener_chars = {idx: s.text[idx] for idx in findings_by_index}
    for f in s.findings:
        if f["type"] == "closer" and f.get("matches"):
            oi = f["matches"]["logical_index"]
            f["matches"]["code_point"] = f"U+{ord(opener_chars[oi]):04X}"

    dangerous_spans: list[dict] = []
    for e in s.open_entries:
        f = findings_by_index[e.index]
        ch = s.text[e.index]
        if f["overflow"]:
            # 溢出开启符没有影响范围
            f["influence_span"] = None
            f["inner_span"] = None
            f["closer"] = None
            f["unclosed"] = False
            continue

        unclosed = e.closer_index is None
        f["unclosed"] = unclosed
        if unclosed:
            f["matched"] = False
            f["severity"] = HIGH
            f["reasons"].append("unclosed at paragraph end — run extends to end of paragraph")
            f["closer"] = None
            end = _paragraph_end(s.text, e.index)
            closer_index = None
        else:
            end = e.closer_index
            closer_index = e.closer_index
            closer = s.text[e.closer_index]
            f["closer"] = {
                "code_point": f"U+{ord(closer):04X}",
                "abbreviation": e.closer_abbr,
                "logical_index": e.closer_index,
                "paragraph": e.closer_para,
                "auto_closed": e.auto_closed,
            }
            if e.auto_closed:
                f["matched"] = True
                f["reasons"].append(
                    "no matching PDF inside its isolate; auto-closed by PDI"
                    if e.kind in ("embedding", "override")
                    else "auto-closed at paragraph boundary"
                )

        # 影响范围（含控制符）与内部范围（不含控制符）
        influence = _span(e.index, end + (0 if unclosed else 1), s.text)
        inner = _span(e.index + 1, end, s.text)
        f["influence_span"] = influence
        f["inner_span"] = inner

        resolved_abbr = e.abbr
        resolved_rtl = None
        if e.abbr == "FSI":
            resolved_rtl = _fsi_resolves_rtl(s.text, e.index)
            resolved_abbr = "RLI" if resolved_rtl else "LRI"

        span_severity = f["severity"]
        span_record = {
            "start": influence["start"],
            "end": influence["end"],
            "opener": f["code_point"],
            "abbreviation": e.abbr,
            "resolved_abbreviation": resolved_abbr,
            "resolved_base_direction": (
                "rtl" if resolved_rtl else ("ltr" if resolved_rtl is False else None)
            ),
            "kind": e.kind,
            "severity": span_severity,
            "unclosed": unclosed,
            "auto_closed": e.auto_closed,
            "closer_index": closer_index,
            "escaped_preview": influence["escaped_preview"],
            "named_preview": influence["named_preview"],
            "raw_logical_preview": influence["raw_preview"],
            "inner_escaped_preview": inner["escaped_preview"],
            "visible_char_count": _visible_char_count(s.text, e.index + 1, end),
            "control_char_count": _control_char_count(s.text, e.index, influence["end"]),
        }
        if e.kind == "override":
            span_record["approx_visual_preview"] = _approx_override_visual(
                s.text, e.index + 1, end, rtl=(e.abbr == "RLO")
            )
        dangerous_spans.append(span_record)

    dangerous_spans.sort(key=lambda x: (x["start"], x["end"]))
    return dangerous_spans


def _paragraph_end(text: str, start: int) -> int:
    for i in range(start, len(text)):
        if text[i] in PARAGRAPH_SEPARATORS:
            return i
    return len(text)


def _visible_char_count(text: str, start: int, end: int) -> int:
    count = 0
    for c in text[start:end]:
        o = ord(c)
        if o in ALL_OPENERS or o in (PDF, PDI) or o in IMPLICIT_MARKS or o in OTHER_INVISIBLES:
            continue
        if unicodedata.category(c).startswith("C"):
            continue
        count += 1
    return count


def _control_char_count(text: str, start: int, end: int) -> int:
    count = 0
    for c in text[start:end]:
        o = ord(c)
        if (
            o in ALL_OPENERS
            or o in (PDF, PDI)
            or o in IMPLICIT_MARKS
            or o in OTHER_INVISIBLES
        ):
            count += 1
    return count


def _approx_override_visual(text: str, start: int, end: int, *, rtl: bool) -> str:
    """RLO/LRO 的近似视觉顺序预览（仅反转强方向可显示字符）。

    这不是完整 UBA 渲染，只把覆盖区内的可显示字符序列反转，用来直观
    展示 RLO 如何让文件名等内容在屏幕上反向显示。控制符同样转义。
    """
    tokens: list[str] = []
    for c in text[start:end]:
        o = ord(c)
        if o in ALL_OPENERS or o in (PDF, PDI) or o in IMPLICIT_MARKS or o in OTHER_INVISIBLES:
            tokens.append(f"\\u{o:04x}")
        elif c in PARAGRAPH_SEPARATORS:
            tokens.append(f"\\u{o:04x}")
        elif unicodedata.category(c).startswith("C"):
            tokens.append(f"\\u{o:04x}")
        else:
            tokens.append(c)
    if rtl:
        tokens.reverse()
    return "".join(tokens)


def analyze_text(text: str, *, max_depth: int = 60) -> dict:
    """审计文本中的 Unicode 双向控制字符。

    返回结构：
      findings         每个控制符一条记录（码点/逻辑索引/段落/影响范围/配对）
      dangerous_spans  所有显式格式区段（含转义预览），按逻辑位置排序
      statistics       按类型/风险级别的计数
      risk_level       整体风险级别（取 finding 最高级，无控制符则 none）
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")

    s = _Scan(max_depth=max_depth, text=text)

    for idx, ch in enumerate(text):
        code = ord(ch)
        if code in ALL_OPENERS:
            _record_opener(s, idx, ch)
        elif code == PDF:
            _record_pdf(s, idx)
        elif code == PDI:
            _record_pdi(s, idx)
        elif code in IMPLICIT_MARKS:
            _record_implicit(s, idx, ch)
        elif code in OTHER_INVISIBLES:
            _record_other_invisible(s, idx, ch)
        elif ch in PARAGRAPH_SEPARATORS:
            _end_paragraph(s, idx + 1)

    # 收尾：最后一个段落（无结尾换行）
    _end_paragraph(s, len(text))

    dangerous_spans = _finalize_findings(s)

    stats = {
        "total_control_chars": len(s.findings),
        "by_abbreviation": {},
        "by_severity": {LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0},
        "by_type": {"opener": 0, "closer": 0, "implicit_mark": 0, "invisible_format": 0},
        "unclosed": 0,
        "stray_closers": 0,
        "depth_overflows": 0,
        "auto_closed": 0,
        "override_spans": 0,
        "isolate_spans": 0,
        "embedding_spans": 0,
        "dangerous_span_count": len(dangerous_spans),
        "paragraph_count": s.para if text else 0,
        "char_count": len(text),
    }
    for f in s.findings:
        abbr = f.get("abbreviation") or f["code_point"]
        stats["by_abbreviation"][abbr] = stats["by_abbreviation"].get(abbr, 0) + 1
        stats["by_severity"][f["severity"]] += 1
        stats["by_type"][f["type"]] += 1
        if f["type"] == "opener":
            if f.get("unclosed"):
                stats["unclosed"] += 1
            if f.get("overflow"):
                stats["depth_overflows"] += 1
            if f["kind"] == "override":
                stats["override_spans"] += 1
            elif f["kind"] == "isolate":
                stats["isolate_spans"] += 1
            else:
                stats["embedding_spans"] += 1
            if f.get("closer", {}).get("auto_closed") if f.get("closer") else False:
                stats["auto_closed"] += 1
        if f["type"] == "closer" and not f["matched"]:
            stats["stray_closers"] += 1

    highest = -1
    risk_level = "none"
    for f in s.findings:
        rank = RISK_ORDER[f["severity"]]
        if rank > highest:
            highest = rank
            risk_level = f["severity"]
    if not s.findings:
        risk_level = "none"

    return {
        "risk_level": risk_level,
        "findings": s.findings,
        "dangerous_spans": dangerous_spans,
        "statistics": stats,
        "max_depth": max_depth,
    }
