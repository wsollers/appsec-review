"""Command line: ``python -m appsec_review.reporting render|telemetry|palette``.

``render`` writes ``report.html`` (format ``html``) or ``report.tex`` plus ``source-date-epoch``
(format ``tex``, the input of the ``tool-report-latex`` image) into ``--out``. It never writes into
the run directory. Exit status: 0 on success, 2 on a usage or input error.

``telemetry`` renders the end-of-review telemetry report: ``--format tex`` writes
``telemetry-report.tex`` into ``--out`` without Docker; ``--format pdf`` writes the receipted report
into ``<run>/data/telemetry/report/``. Exit status: 0 when a report was produced, 1 when it was not,
2 on a usage or input error.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import shutil
import sys
from typing import Sequence

from appsec_review.config.telemetry_report import TelemetryReportSettings, parse_telemetry_report
from .html import render_html
from .latex import PALETTE, default_template_dir, render_latex
from .loader import Selection, load_document
from .telemetry import build_document, load_inputs
from .telemetry_render import TEX_NAME, render_telemetry_report
from .tokens import Limits, palette_tex


def _parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python -m appsec_review.reporting", description=__doc__.splitlines()[0])
    commands = root.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render", help="render a run's report")
    render.add_argument("--run", required=True, help="run id (under --runs-dir) or a run directory")
    render.add_argument("--runs-dir", default="runs", help="directory holding run directories (default: runs)")
    render.add_argument("--format", required=True, choices=("html", "tex"))
    render.add_argument("--out", required=True, help="output directory (created)")
    render.add_argument("--limit", type=int, default=None, help="render only the first N packages")
    render.add_argument("--package", action="append", default=[], help="render only packages whose id starts with or contains this (repeatable)")
    render.add_argument("--max-cells", type=int, default=None, help="interchanges shown per package (default %d)" % Limits().cells_per_package)
    render.add_argument("--template-dir", default=None, help="LaTeX template directory (default: the repository's)")
    telemetry = commands.add_parser(
        "telemetry", help="render a run's end-of-review telemetry report",
        description="tex writes telemetry-report.tex into --out without Docker. pdf renders the report "
                    "with the pinned tool-report-latex image into <run>/data/telemetry/report/ (with "
                    "receipt.json) and, with --out, also copies the produced files there. --format "
                    "defaults to tex when --out is given, otherwise pdf. Settings come from --config, "
                    "else from the run's data/configuration/resolved.json, else the defaults. Exit "
                    "status: 0 when a report was produced (rendered or tex_only), 1 when it was not "
                    "(failed or disabled), 2 on a usage or input error.")
    telemetry.add_argument("--run", required=True, help="run id (under --runs-dir) or a run directory")
    telemetry.add_argument("--runs-dir", default="runs", help="directory holding run directories (default: runs)")
    telemetry.add_argument("--format", choices=("tex", "pdf"), default=None,
                           help="tex or pdf (default: tex with --out, otherwise pdf)")
    telemetry.add_argument("--out", default=None, help="output directory (created); required for tex")
    telemetry.add_argument("--config", default=None, help="appsec-review.toml to take settings from")
    palette = commands.add_parser("palette", help="print or write the generated LaTeX palette")
    palette.add_argument("--write", action="store_true", help="write it into the template directory")
    palette.add_argument("--template-dir", default=None)
    return root


def _resolve_run(run: str, runs_dir: str) -> Path:
    candidate = Path(run)
    if candidate.is_dir() and ("/" in run or "\\" in run or candidate.joinpath("data").is_dir()):
        return candidate
    return Path(runs_dir) / run


def _write(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def _telemetry_settings(run_dir: Path, config: str | None) -> tuple[TelemetryReportSettings, Path | None]:
    if config is not None:
        from appsec_review.config import load_config
        loaded = load_config(config)
        return loaded.telemetry_report, loaded.runtime.repository_root
    resolved = run_dir / "data" / "configuration" / "resolved.json"
    if resolved.is_file():
        document = json.loads(resolved.read_bytes())
        reporting = document.get("reporting") if isinstance(document, dict) else None
        return parse_telemetry_report((reporting or {}).get("telemetry_report")), None
    return TelemetryReportSettings(), None


def _telemetry(args: argparse.Namespace, renderer=None) -> int:
    run_dir = _resolve_run(args.run, args.runs_dir)
    if not (run_dir / "data").is_dir():
        print(f"error: {run_dir} is not a run directory (no data/ subdirectory)", file=sys.stderr)
        return 2
    output_format = args.format or ("tex" if args.out else "pdf")
    if output_format == "tex" and not args.out:
        print("error: --format tex needs --out", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else None
    if output_format == "tex":
        try:
            document = build_document(load_inputs(run_dir))
            tex = render_latex(document, None)
        except (OSError, ValueError) as exc:
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        out.mkdir(parents=True, exist_ok=True)
        _write(out / TEX_NAME, tex)
        print(json.dumps({"format": "tex", "run_id": document.run_id, "files": [str(out / TEX_NAME)],
                          "named_gaps": len(document.named_gaps)}, sort_keys=True))
        return 0
    try:
        settings, repository_root = _telemetry_settings(run_dir, args.config)
        receipt = (renderer or render_telemetry_report)(run_dir, settings, repository_root=repository_root)
    except (OSError, ValueError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    files: list[str] = []
    if receipt.report_dir is not None:
        files = [str(receipt.report_dir / name) for name in receipt.record.get("files", ())]
        if out is not None:
            out.mkdir(parents=True, exist_ok=True)
            for name in receipt.record.get("files", ()):
                if (receipt.report_dir / name).is_file():
                    shutil.copyfile(receipt.report_dir / name, out / name)
                    files.append(str(out / name))
    print(json.dumps({"format": "pdf", "run_id": receipt.record.get("run_id", run_dir.name),
                      "status": receipt.status, "report_dir": str(receipt.report_dir) if receipt.report_dir else None,
                      "files": files, "named_gaps": list(receipt.named_gaps)}, sort_keys=True))
    return 0 if receipt.status in {"rendered", "tex_only"} else 1


def main(argv: Sequence[str] | None = None, *, telemetry_renderer=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "telemetry":
        return _telemetry(args, telemetry_renderer)
    if args.command == "palette":
        directory = Path(args.template_dir) if args.template_dir else default_template_dir()
        if args.write:
            _write(directory / PALETTE, palette_tex())
            print(f"wrote {directory / PALETTE}")
        else:
            sys.stdout.write(palette_tex())
        return 0
    run_dir = _resolve_run(args.run, args.runs_dir)
    if not (run_dir / "data").is_dir():
        print(f"error: {run_dir} is not a run directory (no data/ subdirectory)", file=sys.stderr)
        return 2
    limits = Limits()
    if args.max_cells is not None:
        if args.max_cells < 1:
            print("error: --max-cells must be positive", file=sys.stderr)
            return 2
        limits = replace(limits, cells_per_package=args.max_cells)
    try:
        selection = Selection(limit=args.limit, packages=tuple(args.package))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    document = load_document(run_dir, limits=limits, selection=selection)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files: list[str] = []
    if args.format == "html":
        _write(out / "report.html", render_html(document))
        files.append("report.html")
    else:
        template = Path(args.template_dir) if args.template_dir else None
        try:
            tex = render_latex(document, template)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _write(out / "report.tex", tex)
        _write(out / "source-date-epoch", f"{document.source_date_epoch}\n")
        files += ["report.tex", "source-date-epoch"]
    print(json.dumps({"format": args.format, "run_id": document.run_id, "files": files,
                      "source_date_epoch": document.source_date_epoch, "named_gaps": len(document.named_gaps)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
