"""Render the report document as ONE self-contained HTML file.

No external font, script, stylesheet or image is referenced; the stylesheet is inline and generated
from the same design tokens as the LaTeX palette. Long blocks are ``<details>``; a print stylesheet
opens them and avoids splitting boxes; the layout is a single column that reads at phone width.
Every string from the run is HTML-escaped; there is no raw HTML in the document model.
"""
from __future__ import annotations

import math

from .model import (
    BarChart, Block, Box, Bullets, Code, Document, Field, Fields, Heading, IdList, Item, Legend,
    Note, PageBreak, Para, RadarChart, Stats, Table, Timeline, Truncation,
)
from .text import clean, esc, esc_line, token
from .tokens import (
    BOX_STYLES, BoxKind, EXTRA_VERDICTS, NEUTRALS, STYLE_BY_KIND, UNKNOWN_VERDICT_COLOR,
    VERDICT_COLOR, VERDICTS, badge_text,
)

LONG_CODE_LINES = 14
LONG_TABLE_ROWS = 7
SVG_RADAR_SIZE = 440
SVG_RADAR_CENTER = 220.0
SVG_RADAR_RADIUS = 148.0
SVG_RADAR_LABEL_RADIUS = 178.0
SVG_RADAR_RINGS = (0.25, 0.5, 0.75, 1.0)
SVG_SERIES_DASH = ("", "6,3", "2,3", "8,3,2,3")


def css() -> str:
    neutral = dict(NEUTRALS)
    rules = [f":root{{--ink:#{neutral['ink']};--muted:#{neutral['muted']};--faint:#{neutral['faint']};--rule:#{neutral['rule']};"
             f"--panel:#{neutral['panel']};--brand:#{neutral['brand']};"
             "--sans:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;"
             "--mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace}"]
    for style in BOX_STYLES:
        dashed = ";--border-style:dashed" if style.dashed else ""
        rules.append(f".box[data-kind={style.kind.value}]{{--accent:#{style.accent};--fill:#{style.fill}{dashed}}}")
        rules.append(f".chip[data-kind={style.kind.value}]{{background:#{style.accent}}}")
    for state, color in sorted(VERDICT_COLOR.items()):
        rules.append(f".badge[data-state={state}]{{background:#{color}}}")
    rules.append(f".badge{{background:#{UNKNOWN_VERDICT_COLOR}}}")
    return "\n".join(rules) + "\n" + _STATIC_CSS


_STATIC_CSS = """
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:#fff;color:var(--ink);font:15px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
.page{max-width:60rem;margin:0 auto;padding:2.2rem 1rem 4rem}
a{color:inherit}
code,.mono{font-family:var(--mono);font-size:.82em;overflow-wrap:anywhere;word-break:break-word}
.muted{color:var(--muted)}
h1,h2,h3,h4{color:var(--brand);line-height:1.25;margin:0}
.cover{padding:2.5rem 0 1.5rem;border-bottom:1px solid var(--rule)}
.eyebrow{font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;font-weight:600;color:var(--muted)}
.cover h1{font-size:2.3rem;font-weight:700;margin:.5rem 0 .3rem;letter-spacing:-.02em}
.cover .sub{font-size:1.1rem;color:var(--muted)}
.meta-grid{display:grid;grid-template-columns:7rem 1fr;gap:.35rem .8rem;margin-top:1.1rem;font-size:.86rem}
.meta-grid dt{font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding-top:.15rem}
.meta-grid dd{margin:0;overflow-wrap:anywhere}
.toc{margin:1.6rem 0 0;font-size:.9rem}
.toc ol{list-style:none;margin:.4rem 0 0;padding:0}
.toc li{margin:.18rem 0}
.toc li.l2{padding-left:1.1rem}
.toc a{text-decoration:none;color:var(--muted)}
.toc a:hover{color:var(--brand);text-decoration:underline}
h2.l1{font-size:1.5rem;margin:3rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--rule)}
h3.l2{font-size:1.15rem;margin:2.2rem 0 .3rem}
h4.l3{font-size:1rem;margin:1.6rem 0 .2rem}
h5.l4{font-size:.95rem;margin:1.4rem 0 .15rem;color:var(--brand)}
.hsub{color:var(--muted);font-size:.85rem;margin:0 0 .6rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(8rem,1fr));gap:.7rem;margin:1rem 0}
.stat{min-width:0;background:var(--panel);border:1px solid var(--rule);border-left:3px solid var(--brand);border-radius:6px;padding:.55rem .75rem}
.stat .k{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600}
.stat .v{font-size:1.15rem;font-weight:700;overflow-wrap:anywhere}
.note{color:var(--muted);font-size:.88rem;margin:.6rem 0}
.box{background:var(--fill);border-left:4px solid var(--accent);border-radius:6px;padding:.7rem .95rem .75rem;margin:.8rem 0;
  border-top:0 var(--border-style,solid) var(--accent)}
.box[data-kind=gap]{border:1.5px dashed var(--accent);border-left:1.5px dashed var(--accent)}
.box>summary{cursor:pointer;list-style:none}
.box>summary::-webkit-details-marker{display:none}
.box>summary::after{content:"show";float:right;font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.box[open]>summary::after{content:"hide"}
.bh{display:flex;flex-wrap:wrap;align-items:center;gap:.35rem .6rem}
.bh h4{font-size:.95rem;margin:0;color:var(--ink)}
.bm{width:100%;font-size:.76rem;color:var(--muted)}
.chip{display:inline-block;color:#fff;font-size:.62rem;font-weight:700;letter-spacing:.1em;padding:.14rem .45rem;border-radius:3px;line-height:1.3}
.badge{display:inline-block;color:#fff;font-size:.64rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:.14rem .5rem;border-radius:3px;line-height:1.3}
.bb{margin-top:.5rem}
.bb>*:first-child{margin-top:0}
.kv{display:grid;grid-template-columns:9rem 1fr;gap:.12rem .8rem;font-size:.88rem;margin:.2rem 0}
.kv dt{color:var(--muted);font-size:.78rem;padding-top:.08rem}
.kv dd{margin:0;overflow-wrap:anywhere}
.cut{color:var(--muted);font-size:.74rem;font-style:italic}
.cut code{font-style:normal;font-size:.7rem}
.sub-label{font-size:.72rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin:.7rem 0 .2rem}
p.para{margin:.35rem 0;font-size:.9rem;overflow-wrap:anywhere}
ul.bl{margin:.2rem 0;padding-left:1.1rem;font-size:.88rem}
ul.bl li{margin:.12rem 0;overflow-wrap:anywhere}
ul.ids{list-style:none;margin:.1rem 0;padding:0;font-size:.82rem}
ul.ids li{margin:.08rem 0}
.tw{overflow-x:auto;margin:.35rem 0}
table{border-collapse:collapse;width:100%;font-size:.82rem}
th{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);text-align:left;padding:.25rem .5rem .25rem 0;border-bottom:1px solid var(--rule)}
td{padding:.28rem .5rem .28rem 0;vertical-align:top;border-bottom:1px solid rgba(0,0,0,.05);overflow-wrap:anywhere}
pre.code{background:#fff;border:1px solid var(--rule);border-radius:4px;margin:.4rem 0;padding:.55rem .7rem;overflow-x:auto;
  font:.76rem/1.5 var(--mono);white-space:pre;max-width:100%}
.code-cap{font-size:.72rem;color:var(--muted);margin-top:.4rem}
details.inner{margin:.4rem 0}
details.inner>summary{cursor:pointer;font-size:.78rem;color:var(--muted)}
.legend-row{display:grid;grid-template-columns:7.5rem 1fr;gap:.2rem .9rem;align-items:start;margin:.45rem 0;font-size:.88rem}
.legend-row .hexv{font:.72rem var(--mono);color:var(--muted);display:block;margin-top:.2rem}
.chart-card{background:var(--panel);border:1px solid var(--rule);border-radius:6px;padding:.9rem 1rem;margin:1rem 0}
.chart-head{display:flex;justify-content:space-between;align-items:baseline;gap:.6rem;margin-bottom:.6rem}
.chart-head h4{font-size:.96rem;margin:0;color:var(--brand)}
.chart-unit{font-size:.75rem;color:var(--muted)}
.radar-wrap{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-start}
.radar-svg-box{flex:0 0 auto;max-width:100%;margin:0 auto}
.radar-svg{display:block;max-width:100%;height:auto}
.radar-series-key{display:flex;flex-wrap:wrap;gap:.45rem .9rem;margin:.5rem 0;font-size:.8rem}
.radar-series-item{display:inline-flex;align-items:center;gap:.35rem}
.radar-swatch{display:inline-block;width:1.1rem;height:.22rem;border-radius:1px}
.radar-empty{padding:.8rem;border:1px dashed var(--rule);border-radius:4px;color:var(--muted);font-size:.86rem;text-align:center}
.bar-row{display:grid;grid-template-columns:10rem 1fr 6rem;gap:.5rem;align-items:center;margin:.28rem 0;font-size:.82rem}
.bar-track{background:#fff;border:1px solid var(--rule);border-radius:3px;height:.7rem;overflow:hidden}
.bar-fill{height:100%;border-radius:2px}
@media (max-width:34rem){
  body{font-size:14px}.page{padding:1rem .75rem 3rem}.cover h1{font-size:1.7rem}
  .kv{grid-template-columns:1fr;gap:0}.kv dt{padding-top:.3rem}
  .meta-grid{grid-template-columns:1fr}.legend-row{grid-template-columns:1fr}.bar-row{grid-template-columns:1fr}
}
@media print{
  body{font-size:10.5pt}.page{max-width:none;padding:0}
  .toc a{color:inherit}
  .box,.stat,.chart-card{break-inside:avoid}
  h2.l1,h3.l2,h4.l3,h5.l4{break-after:avoid}
  h2.l1.np{break-before:page}
  .box>summary::after{display:none}
  details>*{display:block}
  details::details-content{content-visibility:visible;display:block}
  pre.code{white-space:pre-wrap;overflow:visible}
  .tw{overflow:visible}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""

_OPEN_ON_PRINT = ("window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach("
                  "function(d){d.setAttribute('open','')})});")


def _cut(cut: Truncation | None) -> str:
    if cut is None:
        return ""
    return f'<p class="cut">{cut.omitted} more {esc_line(cut.unit)}, sha256 <code>{esc_line(cut.sha256)}</code></p>'


def _inline_cut(cut: Truncation | None) -> str:
    if cut is None:
        return ""
    return f' <span class="cut">(+{cut.omitted} {esc_line(cut.unit)}, sha256 <code>{esc_line(cut.sha256[:16])}...</code>)</span>'


def _tone_hex(tone: str) -> str:
    neutral = dict(NEUTRALS)
    safe = token(tone)
    return neutral["brand"] if safe == "neutral" else VERDICT_COLOR.get(safe, UNKNOWN_VERDICT_COLOR)


def _badge(state: str, label: str | None = None) -> str:
    safe = token(state)
    state_attr = safe if safe in VERDICT_COLOR else "unknown"
    return f'<span class="badge" data-state="{state_attr}">{esc_line(label if label is not None else badge_text(safe))}</span>'


def _field(row: Field) -> str:
    if row.badge:
        value = _badge(row.badge, row.badge_label)
    elif row.mono:
        value = f"<code>{esc_line(row.value)}</code>"
    else:
        value = esc_line(row.value)
    return f"<dt>{esc_line(row.label)}</dt><dd>{value}{_inline_cut(row.truncation)}</dd>"


def _table(item: Table) -> str:
    head = "".join(f"<th>{esc_line(header)}</th>" for header in item.headers)
    rows = []
    for row in item.rows:
        cells = []
        for cell in row:
            if cell.badge:
                cells.append(f"<td>{_badge(cell.badge, cell.badge_label)}</td>")
            elif cell.mono:
                cells.append(f"<td><code>{esc_line(cell.text)}</code></td>")
            else:
                cells.append(f"<td>{esc_line(cell.text)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    html = f'<div class="tw"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>{_cut(item.omitted)}'
    if len(item.rows) >= LONG_TABLE_ROWS:
        return f'<details class="inner"><summary>Show {len(item.rows)} rows</summary>{html}</details>'
    return html


def _item(item: Item) -> str:
    if isinstance(item, Para):
        cls = "para muted" if item.muted else "para"
        return f'<p class="{cls}">{esc(item.text)}</p>{_cut(item.truncation)}'
    if isinstance(item, Fields):
        return '<dl class="kv">' + "".join(_field(row) for row in item.rows) + "</dl>"
    if isinstance(item, Code):
        caption = f'<div class="code-cap">{esc_line(item.caption)}</div>' if item.caption else ""
        body = f'{caption}<pre class="code">{esc(item.text)}</pre>{_cut(item.truncation)}'
        if item.text.count("\n") + 1 > LONG_CODE_LINES:
            return f'<details class="inner"><summary>Show {item.text.count(chr(10)) + 1} lines</summary>{body}</details>'
        return body
    if isinstance(item, Table):
        return _table(item)
    if isinstance(item, IdList):
        ids = "".join(f"<li><code>{esc_line(identity)}</code></li>" for identity in item.ids)
        return f'<div class="sub-label">{esc_line(item.label)}</div><ul class="ids">{ids}</ul>{_cut(item.omitted)}'
    if isinstance(item, Bullets):
        entries = "".join(f"<li>{esc_line(text)}</li>" for text in item.items)
        return f'<ul class="bl">{entries}</ul>{_cut(item.omitted)}'
    raise TypeError(f"unknown item {type(item).__name__}")


def _box(box: Box) -> str:
    style = STYLE_BY_KIND[box.kind]
    chip = f'<span class="chip" data-kind="{box.kind.value}">{esc_line(box.chip or style.chip)}</span>'
    badges = " ".join(_badge(state) for state in box.badges)
    meta = f'<div class="bm">{esc_line(box.meta)}</div>' if box.meta else ""
    head = f'<div class="bh">{chip}<h4>{esc_line(box.title)}</h4>{badges}{meta}</div>'
    body = "".join(_item(item) for item in box.items)
    if box.collapsed:
        return f'<details class="box" data-kind="{box.kind.value}"><summary>{head}</summary><div class="bb">{body}</div></details>'
    return f'<section class="box" data-kind="{box.kind.value}">{head}<div class="bb">{body}</div></section>'


def _svg_point(index: int, count: int, radius: float) -> tuple[float, float]:
    angle = -math.pi / 2.0 + 2.0 * math.pi * index / count
    return SVG_RADAR_CENTER + radius * math.cos(angle), SVG_RADAR_CENTER + radius * math.sin(angle)


def _fmt_pts(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.2f},{y:.2f}" for x, y in points)


def _radar_chart(block: RadarChart) -> str:
    neutral = dict(NEUTRALS)
    gap_accent = STYLE_BY_KIND[BoxKind.GAP].accent
    count = len(block.axes)
    has_positive = any(val is not None and val > 0.0 for series in block.series for val in series.values)
    parts = [f'<section class="chart-card"><div class="chart-head"><h4>{esc_line(block.title)}</h4>'
             f'<span class="chart-unit">{count}-axis radar</span></div>']
    if not has_positive:
        parts.append('<div class="radar-empty">No bound radar series values &gt; 0 (Unverified Coverage Gap &mdash; never evidence of clean domains).</div>')
    if True:
        svg = [
            f'<svg class="radar-svg" width="{SVG_RADAR_SIZE}" height="{SVG_RADAR_SIZE}" '
            f'viewBox="0 0 {SVG_RADAR_SIZE} {SVG_RADAR_SIZE}" role="img" aria-label="{esc_line(block.title)}">',
            f"<title>{esc_line(block.title)}</title>",
            f"<desc>{esc_line(block.scale_note or block.caption or block.title)}</desc>",
        ]
        for ring in SVG_RADAR_RINGS:
            pts = [_svg_point(i, count, SVG_RADAR_RADIUS * ring) for i in range(count)]
            svg.append(f'<polygon points="{_fmt_pts(pts)}" fill="none" stroke="#{neutral["rule"]}" stroke-width="1"/>')
        for idx in range(count):
            sx, sy = _svg_point(idx, count, SVG_RADAR_RADIUS)
            svg.append(f'<line x1="{SVG_RADAR_CENTER:.2f}" y1="{SVG_RADAR_CENTER:.2f}" x2="{sx:.2f}" y2="{sy:.2f}" stroke="#{neutral["rule"]}" stroke-width="1"/>')
        for ring_val, ring_text in ((0.5, "0.5"), (1.0, "1.0")):
            ry = SVG_RADAR_CENTER - SVG_RADAR_RADIUS * ring_val - 3.0
            svg.append(f'<text x="{SVG_RADAR_CENTER + 4.0:.2f}" y="{ry:.2f}" fill="#{neutral["muted"]}" font-size="9" font-family="sans-serif">{ring_text}</text>')
        for s_idx, series in enumerate(block.series):
            color = _tone_hex(series.tone)
            dash = SVG_SERIES_DASH[s_idx % len(SVG_SERIES_DASH)]
            dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
            pts = [None if val is None else _svg_point(a_idx, count, SVG_RADAR_RADIUS * val)
                   for a_idx, val in enumerate(series.values)]
            if all(point is not None for point in pts):
                svg.append(f'<polygon data-series="{esc_line(series.label)}" points="{_fmt_pts(pts)}" fill="#{color}" fill-opacity="0.12" stroke="#{color}" stroke-width="2"{dash_attr}/>')
            else:
                for idx, point in enumerate(pts):
                    following = pts[(idx + 1) % count]
                    if point is not None and following is not None:
                        svg.append(f'<polyline data-series="{esc_line(series.label)}" points="{_fmt_pts([point, following])}" fill="none" stroke="#{color}" stroke-width="2"{dash_attr}/>')
            for point, val in zip(pts, series.values):
                if point is not None and val > 0.0:
                    px, py = point
                    svg.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="3" fill="#{color}"/>')
        for a_idx, axis in enumerate(block.axes):
            is_gap_axis = any(
                ("coverage" in series.label.lower() and
                 (series.values[a_idx] is None or series.values[a_idx] < 1.0))
                or (series.displays and "gap" in series.displays[a_idx].lower())
                for series in block.series
            )
            lx, ly = _svg_point(a_idx, count, SVG_RADAR_LABEL_RADIUS)
            anchor = "end" if lx < SVG_RADAR_CENTER - 20.0 else ("start" if lx > SVG_RADAR_CENTER + 20.0 else "middle")
            label_color = gap_accent if is_gap_axis else neutral["brand"]
            suffix = " !" if is_gap_axis else ""
            svg.append(f'<text x="{lx:.2f}" y="{ly + 4.0:.2f}" text-anchor="{anchor}" fill="#{label_color}" font-size="11" font-weight="700" font-family="monospace">{esc_line(axis.key + suffix)}</text>')
        svg.append("</svg>")
        parts.append(f'<div class="radar-wrap"><div class="radar-svg-box">{"".join(svg)}</div></div>')
    swatches = [
        f'<span class="radar-series-item"><span class="radar-swatch" style="background:#{_tone_hex(s.tone)}"></span><strong>{esc_line(s.label)}</strong></span>'
        for s in block.series
    ]
    parts.append(f'<div class="radar-series-key">{"".join(swatches)}</div>')
    axis_meaning = {row.key: row.meaning for row in block.legend if row.kind == "axis"}
    headers = ["Key", "Domain"] + [series.label for series in block.series] + ["Notes"]
    head_html = "".join(f"<th>{esc_line(h)}</th>" for h in headers)
    body_rows = []
    for a_idx, axis in enumerate(block.axes):
        cells = [f"<td><code>{esc_line(axis.key)}</code></td>", f"<td>{esc_line(axis.label)}</td>"]
        for series in block.series:
            disp = ("N/A" if series.values[a_idx] is None else
                    series.displays[a_idx] if series.displays else f"{series.values[a_idx]:.2f}")
            cells.append(f"<td><code>{esc_line(disp)}</code></td>")
        note_txt = axis_meaning.get(axis.key, "")
        has_gap = "gap" in note_txt.lower() or any(series.displays and "gap" in series.displays[a_idx].lower() for series in block.series)
        cells.append(f"<td>{_badge('coverage_gap', 'Unverified Coverage Gap')} {esc_line(note_txt)}</td>" if has_gap else f"<td>{esc_line(note_txt)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    parts.append(f'<div class="tw"><table><thead><tr>{head_html}</tr></thead><tbody>{"".join(body_rows)}</tbody></table></div>')
    if clean(block.scale_note):
        parts.append(f'<p class="note">{esc_line(block.scale_note)}</p>')
    if block.clamped:
        parts.append(f'<p class="note">{block.clamped} value(s) fell outside 0 to 1 and were clamped.</p>')
    if clean(block.caption):
        parts.append(f'<p class="note">{esc_line(block.caption)}</p>')
    parts.append("</section>")
    return "".join(parts)


def _bar_chart(block: BarChart) -> str:
    largest = max((bar.value for bar in block.bars), default=0.0)
    parts = [f'<section class="chart-card"><div class="chart-head"><h4>{esc_line(block.title)}</h4><span class="chart-unit">{esc_line(block.unit)}</span></div>']
    if largest <= 0.0 or not block.bars:
        parts.append('<div class="radar-empty">No data</div>')
    else:
        for bar in block.bars:
            pct = min(100.0, max(0.0, 100.0 * bar.value / largest))
            parts.append(f'<div class="bar-row"><div>{esc_line(bar.label)}</div><div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;background:#{_tone_hex(bar.tone)}"></div></div><div><code>{esc_line(bar.display)}</code></div></div>')
    if clean(block.caption):
        parts.append(f'<p class="note">{esc_line(block.caption)}</p>')
    parts.append(_cut(block.omitted))
    parts.append("</section>")
    return "".join(parts)


def _timeline(block: Timeline) -> str:
    parts = [f'<section class="chart-card"><div class="chart-head"><h4>{esc_line(block.title)}</h4><span class="chart-unit">{block.total_ms} ms</span></div>']
    if block.total_ms <= 0 or not block.lanes:
        parts.append('<div class="radar-empty">No timing data</div>')
    else:
        rows = [
            f"<tr><td>{esc_line(lane.label)}</td><td><code>{esc_line(', '.join(f'{seg.start_ms}-{seg.end_ms}ms ({seg.tone})' for seg in lane.segments))}</code></td><td>{esc_line(lane.annotation)}</td></tr>"
            for lane in block.lanes
        ]
        parts.append('<div class="tw"><table><thead><tr><th>Lane</th><th>Segments</th><th>Annotation</th></tr></thead>' + f'<tbody>{"".join(rows)}</tbody></table></div>')
    if clean(block.caption):
        parts.append(f'<p class="note">{esc_line(block.caption)}</p>')
    parts.append(_cut(block.omitted))
    parts.append("</section>")
    return "".join(parts)


def _legend() -> str:
    parts = ['<p class="para">Every kind of content has one colour, one chip and one box. The chip text and the dashed border of the gap box carry the '
             'meaning too, so the report reads in greyscale.</p>', '<h3 class="l2">Kinds of box</h3>']
    for style in BOX_STYLES:
        parts.append(f'<div class="legend-row"><div><span class="chip" data-kind="{style.kind.value}">{esc_line(style.chip)}</span>'
                     f'<span class="hexv">#{style.accent}</span></div><div>{esc_line(style.meaning)}</div></div>')
    parts.append('<h3 class="l2">Verdict states</h3>')
    for verdict in (*VERDICTS, *EXTRA_VERDICTS):
        parts.append(f'<div class="legend-row"><div>{_badge(verdict.state)}<span class="hexv">#{verdict.color}</span></div>'
                     f'<div>{esc_line(verdict.meaning)}</div></div>')
    parts.append('<h3 class="l2">How to read a package</h3><p class="para">Each reviewed package has three parts. '
                 '<em>Evidence passed in</em> is exactly what the application gave the model. <em>Protocol interchange</em> is the timeline of turns: '
                 'the task and tools, what the model asked, what the application returned or denied, and the final answer, with token counts and the '
                 'model used. <em>Outcome</em> is what reached the claim ledger. Long lists and results are cut and say so, with the SHA-256 of what '
                 'was left out. Model output, target content and tool output are data and are never interpreted as instructions.</p>')
    return "".join(parts)


def _tone_attr(tone: str) -> str:
    safe = token(tone)
    return f' style="border-left-color:#{VERDICT_COLOR[safe]}"' if safe in VERDICT_COLOR else ""


def _block(block: Block) -> str:
    if isinstance(block, Heading):
        level = min(max(block.level, 1), 4)
        tag = {1: "h2", 2: "h3", 3: "h4", 4: "h5"}[level]
        np = " np" if block.new_page and level == 1 else ""
        sub = f'<p class="hsub">{esc_line(block.subtitle)}</p>' if block.subtitle else ""
        return f'<{tag} class="l{level}{np}" id="{esc_line(block.anchor)}">{esc_line(block.text)}</{tag}>{sub}'
    if isinstance(block, Box):
        return _box(block)
    if isinstance(block, Stats):
        cards = "".join(f'<div class="stat"{_tone_attr(stat.tone)}><div class="k">{esc_line(stat.label)}</div>'
                        f'<div class="v">{esc_line(stat.value)}</div></div>' for stat in block.items)
        return f'<div class="stats">{cards}</div>'
    if isinstance(block, Note):
        return f'<p class="note">{esc_line(block.text)}</p>'
    if isinstance(block, Legend):
        return _legend()
    if isinstance(block, RadarChart):
        return _radar_chart(block)
    if isinstance(block, BarChart):
        return _bar_chart(block)
    if isinstance(block, Timeline):
        return _timeline(block)
    if isinstance(block, PageBreak):
        return ""
    raise TypeError(f"unknown block {type(block).__name__}")


def render_html(document: Document) -> str:
    toc = []
    for block in document.blocks:
        if isinstance(block, Heading) and block.level <= 2:
            toc.append(f'<li class="l{block.level}"><a href="#{esc_line(block.anchor)}">{esc_line(block.text)}</a></li>')
    body = "\n".join(filter(None, (_block(block) for block in document.blocks)))
    title = f"{document.title} {document.run_id}"
    return "\n".join([
        "<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="generator" content="' + esc_line(document.renderer) + '">',
        f"<title>{esc_line(title)}</title>", f"<style>{css()}</style>", "</head>",
        '<body><div class="page">', '<header class="cover">', '<div class="eyebrow">appsec-review</div>',
        f"<h1>{esc_line(document.title)}</h1>", f'<div class="sub">{esc_line(document.subtitle)}</div>',
        '<dl class="meta-grid">', f"<dt>Run</dt><dd><code>{esc_line(document.run_id)}</code></dd>",
        f"<dt>Status</dt><dd>{_badge(document.status_tone, document.status_badge.replace('_', ' '))}</dd>",
        f"<dt>Ledger head</dt><dd><code>{esc_line(document.ledger_head)}</code></dd>",
        f"<dt>Renderer</dt><dd><code>{esc_line(document.renderer)}</code></dd>", "</dl>",
        '<nav class="toc" aria-label="Contents"><div class="eyebrow">Contents</div><ol>' + "".join(toc) + "</ol></nav>",
        "</header>", "<main>", body, "</main>", "</div>", f"<script>{_OPEN_ON_PRINT}</script>", "</body>", "</html>", "",
    ])
