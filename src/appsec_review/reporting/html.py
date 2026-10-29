"""Render the report document as ONE self-contained HTML file.

No external font, script, stylesheet or image is referenced; the stylesheet is inline and generated
from the same design tokens as the LaTeX palette. Long blocks are ``<details>``; a print stylesheet
opens them and avoids splitting boxes; the layout is a single column that reads at phone width.
Every string from the run is HTML-escaped; there is no raw HTML in the document model.
"""
from __future__ import annotations

from .model import (Block, Box, Bullets, Code, Document, Field, Fields, Heading, IdList, Item, Legend, Note, PageBreak,
                    Para, Stats, Table, Truncation)
from .text import esc, esc_line, token
from .tokens import (BOX_STYLES, badge_text, EXTRA_VERDICTS, NEUTRALS, STYLE_BY_KIND, UNKNOWN_VERDICT_COLOR, VERDICT_COLOR,
                     VERDICTS)

LONG_CODE_LINES = 14
LONG_TABLE_ROWS = 7


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
@media (max-width:34rem){
  body{font-size:14px}.page{padding:1rem .75rem 3rem}.cover h1{font-size:1.7rem}
  .kv{grid-template-columns:1fr;gap:0}.kv dt{padding-top:.3rem}
  .meta-grid{grid-template-columns:1fr}.legend-row{grid-template-columns:1fr}
}
@media print{
  body{font-size:10.5pt}.page{max-width:none;padding:0}
  .toc a{color:inherit}
  .box,.stat{break-inside:avoid}
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
    return (f'<p class="cut">{cut.omitted} more {esc_line(cut.unit)}, sha256 <code>{esc_line(cut.sha256)}</code></p>')


def _inline_cut(cut: Truncation | None) -> str:
    if cut is None:
        return ""
    return f' <span class="cut">(+{cut.omitted} {esc_line(cut.unit)}, sha256 <code>{esc_line(cut.sha256[:16])}...</code>)</span>'


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
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="generator" content="' + esc_line(document.renderer) + '">',
        f"<title>{esc_line(title)}</title>",
        f"<style>{css()}</style>",
        "</head>",
        '<body><div class="page">',
        '<header class="cover">',
        '<div class="eyebrow">appsec-review</div>',
        f"<h1>{esc_line(document.title)}</h1>",
        f'<div class="sub">{esc_line(document.subtitle)}</div>',
        '<dl class="meta-grid">',
        f"<dt>Run</dt><dd><code>{esc_line(document.run_id)}</code></dd>",
        f"<dt>Status</dt><dd>{_badge(document.status_tone, document.status_badge.replace("_", " "))}</dd>",
        f"<dt>Ledger head</dt><dd><code>{esc_line(document.ledger_head)}</code></dd>",
        f"<dt>Renderer</dt><dd><code>{esc_line(document.renderer)}</code></dd>",
        "</dl>",
        '<nav class="toc" aria-label="Contents"><div class="eyebrow">Contents</div><ol>' + "".join(toc) + "</ol></nav>",
        "</header>",
        "<main>",
        body,
        "</main>",
        "</div>",
        f"<script>{_OPEN_ON_PRINT}</script>",
        "</body>",
        "</html>",
        ""])
