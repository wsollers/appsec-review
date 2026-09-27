#!/usr/bin/env python3
"""Publish house-style LaTeX documents as retained TeX and KaTeX HTML.

PDF compilation remains a separate, pinned-container step in
``latex/build-in-docker.sh``.  This renderer deliberately consumes LaTeX as
the canonical document source; it does not convert Markdown into a second,
potentially divergent document.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

import jinja2


HERE = Path(__file__).resolve().parent


def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(HERE / "templates"),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["jsonscript"] = lambda value: jinja2.utils.markupsafe.Markup(
        json.dumps(value).replace("</", "<\\/")
    )
    return env


def render_document(source: Path, output_dir: Path) -> tuple[Path, Path]:
    if source.suffix.lower() not in {".tex", ".ltx"} or not source.is_file():
        raise ValueError(f"LaTeX source not found: {source}")
    text = source.read_text(encoding="utf-8")
    if "\\begin{document}" not in text or "\\end{document}" not in text:
        raise ValueError(f"not a complete LaTeX document: {source}")

    output_dir.mkdir(parents=True, exist_ok=True)
    tex_output = output_dir / f"{source.stem}.tex"
    html_output = output_dir / f"{source.stem}.html"
    if source.resolve() != tex_output.resolve():
        shutil.copyfile(source, tex_output)

    css = (HERE / "templates" / "vendor" / "katex-0.16.11.css").read_text(encoding="utf-8")
    body = _environment().get_template("workbench.html.j2").render(
        katex_css=css,
        docs={tex_output.name: text},
        viewer=True,
        page_title=source.stem.replace("-", " ").title(),
    )
    html_output.write_text(
        '<!doctype html>\n<html lang="en"><meta charset="utf-8">\n' + body,
        encoding="utf-8",
    )
    return tex_output, html_output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render canonical LaTeX documents to retained TeX and standalone KaTeX HTML"
    )
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    for source in args.sources:
        tex_output, html_output = render_document(source, args.out)
        print(f"TeX: {tex_output}")
        print(f"HTML: {html_output}")


if __name__ == "__main__":
    main()
