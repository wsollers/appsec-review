#!/usr/bin/env python3
"""Render the AppSec review from one data file into LaTeX and an HTML/KaTeX preview.

    python3 render.py [data.json] [--out build/] [--pdf] [--watch] [--source-root CHECKOUT]

Both outputs are rendered from the same computed model, so every number in the
preview matches the PDF. Math strings are LaTeX and go verbatim to both.
"""
import argparse, json, math, pathlib, re, subprocess, sys, time

import jinja2

HERE = pathlib.Path(__file__).resolve().parent
BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None")]
SEV_ORDER = ["Critical", "High", "Medium", "Low", "None", "Refuted"]


def band(x):
    if x is None:
        return None
    for lo, name in BANDS:
        if x >= lo:
            return name
    return "None"


def score(data):
    data.setdefault("finding_scoring", "proposed_presentation")
    data.setdefault("process_assurance", "proposed_presentation")
    s = data["scoring"]
    tier = data["report"]["native_tier"]
    authoritative = data.get("finding_scoring") == "authoritative_retained_publication"

    # ---- process assurance ----
    fams = {f["id"]: dict(f, procs=[], credit=0.0, applicable=0) for f in data["families"]}
    for p in data["processes"]:
        st = p["status"]
        if st == "SKIPPED_NA":
            c = None
        elif st == "OK_WITH_GAPS":
            c = float(p.get("coverage", 0.5))
        else:
            c = s["status_credit"][st]
        if c is not None and p["family"] == "native":
            c = c * s["tier_cap"][tier]
        p["credit"] = c
        p["detail"] = [(k, p[k] if k != "evidence" else ", ".join(p[k]))
                       for k in ("tools", "gap", "receipt", "evidence") if p.get(k)]
        f = fams[p["family"]]
        f["procs"].append(p)
        if c is not None:
            f["credit"] += c
            f["applicable"] += 1
    wsum = asum = 0.0
    for f in fams.values():
        f["weight"] = s["family_weight"][f["id"]]
        f["assurance"] = f["credit"] / f["applicable"] if f["applicable"] else None
        f["counts"] = {k: sum(1 for p in f["procs"] if p["status"] == k)
                       for k in ["OK", "OK_WITH_GAPS", "BLOCKED", "FAILED", "NOT_BUILT", "SKIPPED_NA"]}
        if f["assurance"] is not None:
            wsum += f["weight"]
            asum += f["weight"] * f["assurance"]
    assurance = asum / wsum if wsum else 0.0

    # ---- findings ----
    ev = s["evidence_weight"]; vw = s["verification_weight"]; rw = s["reachability_weight"]
    for fd in data["findings"]:
        if authoritative:
            # A retained publication may carry a CVSS v4.0 vector only with the score the pipeline's
            # pinned calculator (appsec-review-process/cvss4.py) computed; the renderer never scores.
            if fd.get("cvss") is not None and (isinstance(fd.get("cvss_score"), bool) or
                                               not isinstance(fd.get("cvss_score"), (int, float))):
                raise ValueError("authoritative retained finding must not synthesize a CVSS score")
            declared = fd.get("severity_override")
            value = fd.get("authoritative_score")
            label = fd.get("priority_label")
            if declared not in SEV_ORDER or declared == "Refuted" or isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ValueError("authoritative retained finding score is invalid")
            if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9:-]+", label):
                raise ValueError("authoritative retained finding priority is invalid")
            cvss_score = float(fd["cvss_score"]) if fd.get("cvss") is not None else None
            fd.update(cvss_score=cvss_score, cvss_band=band(cvss_score), factors=None, priority=float(value),
                      severity=declared, priority_tex=(r"S_{lifecycle} = %.1f,\quad priority = \text{%s}"
                                                       % (value, label)))
            continue
        from cvss import CVSS4
        fd["cvss_score"] = float(CVSS4(fd["cvss"]).base_score) if fd.get("cvss") else None
        fd["cvss_band"] = band(fd["cvss_score"])
        e, v, r = ev[fd["evidence_strength"]], vw[fd["verification"]], rw[fd["reachability"]]
        t = 1 + s["kev_bonus"] * (1 if fd.get("kev") else 0) + s["epss_bonus"] * (fd.get("epss") or 0)
        fd["factors"] = {"e": e, "v": v, "r": r, "t": t}
        if fd["cvss_score"] is None:
            fd["priority"] = None
            fd["severity"] = fd.get("severity_override", "None")
            fd["priority_tex"] = r"P = \text{unscored (coverage finding; reviewer severity: %s)}" % fd["severity"]
        else:
            P = min(10.0, fd["cvss_score"] * e * v * r * t)
            fd["priority"] = round(P, 1)
            fd["severity"] = "Refuted" if fd["verification"] == "REFUTED" else band(fd["priority"])
            fd["priority_tex"] = (r"P = \min\!\big(10,\; %.1f \times %.2f \times %.2f \times %.2f \times %.2f\big) = \mathbf{%.1f}"
                                  % (fd["cvss_score"], e, v, r, t, fd["priority"]))
    data["findings"].sort(key=lambda f: (SEV_ORDER.index(f["severity"]), -(f["priority"] or 0)))

    live = [f for f in data["findings"] if f["verification"] != "REFUTED"]
    top = max((f["priority"] or 0) for f in live) if live else 0.0
    # A retained publication can carry an independently verified severity without a CVSS vector.
    # Preserve that declared severity instead of manufacturing a vector merely to drive the cover.
    declared = [f["severity"] for f in live if f["severity"] != "Refuted"]
    rating = min(declared, key=SEV_ORDER.index) if declared else (band(top) if top else "None")
    if not authoritative and rating in ("None", "Low") and assurance < s["assurance_floor_for_clean"]:
        rating = "Indeterminate"
    counts = {k: sum(1 for f in data["findings"] if f["severity"] == k) for k in SEV_ORDER}

    gaps = [p for p in data["processes"] if p["status"] in ("OK_WITH_GAPS", "BLOCKED", "FAILED", "NOT_BUILT")]
    assurance_not_asserted = data.get("process_assurance") == "not_asserted"
    if assurance_not_asserted:
        for process in data["processes"]:
            process["credit"] = None
        for family in fams.values():
            family["assurance"] = None
        assurance_tex = r"A = \text{not asserted by retained publication}"
    else:
        assurance_tex = (r"A = \frac{\sum_k w_k A_k}{\sum_k w_k} = "
                         + r"\frac{" + " + ".join(r"%d \cdot %.2f" % (f["weight"], f["assurance"])
                                                   for f in fams.values() if f["assurance"] is not None)
                         + r"}{%d} = \mathbf{%.2f}" % (wsum, assurance))
    data["model"] = {
        "assurance": (None if assurance_not_asserted else assurance),
        "assurance_pct": (None if assurance_not_asserted else round(assurance * 100)),
        "rating": rating, "top_priority": top, "counts": counts,
        "families": list(fams.values()), "gaps": gaps,
        "n_processes": len(data["processes"]),
        "n_ok": sum(1 for p in data["processes"] if p["status"] == "OK"),
        "n_na": sum(1 for p in data["processes"] if p["status"] == "SKIPPED_NA"),
        "assurance_tex": assurance_tex,
    }
    data["evidence_by_id"] = {e["id"]: e for e in data["evidence"]}
    return data


# ---------- LaTeX escaping ----------
_TEX = {"&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
        "~": r"\textasciitilde{}", "^": r"\textasciicircum{}", "\\": r"\textbackslash{}",
        "…": r"\ldots{}", "<": r"\textless{}", ">": r"\textgreater{}", "‑": "-"}
_TEX_RE = re.compile("|".join(re.escape(k) for k in _TEX))


def tex(s):
    out = _TEX_RE.sub(lambda m: _TEX[m.group()], "" if s is None else str(s))
    # keep "--flag" and "``" literal instead of TeX ligatures (en dash, curly quotes)
    return out.replace("--", "-{}-").replace("--", "-{}-").replace("``", "`{}`").replace("''", "'{}'")


def texpath(s):
    """Escape and allow line breaks after / . # in long paths."""
    return re.sub(r"([/.#-])", r"\1\\allowbreak{}", tex(s)).replace(r"\\allowbreak{}_", "_")


CONTEXT = 5  # lines of context shown around a flaw


def resolve_snippets(data, source_root=None, embed=False):
    """Attach +-CONTEXT lines around each snippet's flaw lines.

    Source comes from the checkout (source_root / report.source_root) when present; otherwise from
    the lines already embedded in the data file, so the kit renders without the target checkout.
    """
    root = source_root or data["report"].get("source_root")
    root = pathlib.Path(root) if root else None
    for f in data["findings"]:
        for sn in f.get("snippets", []):
            flaw = sorted(sn["flaw"])
            src = (root / sn["path"]) if root else None
            if src and src.is_file():
                text = src.read_text(errors="replace").expandtabs(4).splitlines()
                a = max(1, flaw[0] - CONTEXT)
                b = min(len(text), flaw[-1] + CONTEXT)
                sn["start"] = a
                sn["source"] = text[a - 1:b]
            elif "source" not in sn:
                raise SystemExit(f"{f['id']}: {sn['path']} not found under {root} and no embedded source")
            sn["lines"] = [{"n": sn["start"] + i, "text": t, "flaw": (sn["start"] + i) in flaw}
                           for i, t in enumerate(sn["source"])]
            sn["end"] = sn["start"] + len(sn["source"]) - 1
    if embed:
        return {f["id"]: [{k: v for k, v in sn.items() if k in ("path", "flaw", "note", "start", "source")}
                          for sn in f.get("snippets", [])] for f in data["findings"]}
    return None


def texcode(s):
    """Escape one source line for the code environment; keep every space visible and breakable."""
    return tex(s).replace(" ", "\\ ")


def render(data_path, out, source_root=None, embed=False):
    raw = json.loads(pathlib.Path(data_path).read_text())
    embedded = resolve_snippets(raw, source_root, embed)
    if embedded is not None:
        # write the extracted lines back so the data file renders without the checkout
        disk = json.loads(pathlib.Path(data_path).read_text())
        for f in disk["findings"]:
            f["snippets"] = embedded[f["id"]]
        pathlib.Path(data_path).write_text(json.dumps(disk, indent=2, ensure_ascii=False) + "\n")
    data = score(raw)
    out.mkdir(parents=True, exist_ok=True)
    tdir = HERE / "templates"

    tex_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(tdir),
        block_start_string=r"\BLOCK{", block_end_string="}",
        variable_start_string=r"\VAR{", variable_end_string="}",
        comment_start_string=r"\#{", comment_end_string="}",
        line_statement_prefix="%%", line_comment_prefix="%#",
        trim_blocks=True, lstrip_blocks=True, autoescape=False, undefined=jinja2.StrictUndefined)
    tex_env.filters.update(tex=tex, texpath=texpath, texcode=texcode,
                           dictsort_insertion=lambda d: list(d.items()))
    tex_source = tex_env.get_template("report.tex.j2").render(**data)
    (out / "report.tex").write_text(tex_source)

    html_env = jinja2.Environment(loader=jinja2.FileSystemLoader(tdir), autoescape=True,
                                  undefined=jinja2.StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    html_env.filters["jsonscript"] = lambda v: jinja2.utils.markupsafe.Markup(
        json.dumps(v).replace("</", "<\\/"))
    katex_css = (tdir / "vendor" / "katex-0.16.11.css").read_text()
    head = '<!doctype html>\n<html lang="en"><meta charset="utf-8">\n'
    docs = {"report.tex": tex_source}
    for p in sorted((HERE / "latex").glob("*.tex")):
        docs[p.name] = p.read_text()
    for name in ("report", "workbench"):
        body = html_env.get_template(f"{name}.html.j2").render(
            katex_css=katex_css, tex_source=tex_source, docs=docs,
            viewer=False, page_title="AppSec Review LaTeX Workbench", **data)
        # <name>.html: standalone, open locally. <name>.fragment.html: for the Artifact publisher,
        # which supplies its own doctype/head/body skeleton.
        (out / f"{name}.html").write_text(head + body)
        (out / f"{name}.fragment.html").write_text(body)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", nargs="?", default=str(HERE / "examples" / "hello-autotools.review.json"))
    ap.add_argument("--out", default=str(HERE / "build"))
    ap.add_argument("--pdf", action="store_true", help="also run latexmk")
    ap.add_argument("--watch", action="store_true", help="re-render when data or templates change")
    ap.add_argument("--source-root", help="target checkout for code snippets (default: report.source_root)")
    ap.add_argument("--embed-snippets", action="store_true",
                    help="write extracted snippet lines back into the data file")
    ap.add_argument("--engine", default="pdf", choices=["pdf", "lualatex", "xelatex"],
                    help="latexmk engine flag (pdf = pdflatex)")
    a = ap.parse_args()
    out = pathlib.Path(a.out)

    def once():
        d = render(a.data, out, a.source_root, a.embed_snippets)
        m = d["model"]
        assurance = "not asserted" if m["assurance"] is None else f"{m['assurance']:.2f}"
        print(f"rendered: rating={m['rating']} assurance={assurance} "
              f"findings={len(d['findings'])} gaps={len(m['gaps'])}")
        if a.pdf:
            subprocess.run(["latexmk", f"-{a.engine}", "-interaction=nonstopmode", "-halt-on-error", "-quiet",
                            "report.tex"], cwd=out, check=True)
            print(f"pdf: {out / 'report.pdf'}")

    once()
    if a.watch:
        watched = [pathlib.Path(a.data), *(HERE / "templates").glob("*")]
        stamp = lambda: [p.stat().st_mtime for p in watched]
        last = stamp()
        while True:
            time.sleep(0.5)
            if stamp() != last:
                last = stamp()
                try:
                    once()
                except Exception as e:  # keep watching through template errors
                    print("error:", e, file=sys.stderr)


if __name__ == "__main__":
    main()
