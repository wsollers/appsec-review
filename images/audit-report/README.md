# audit-report

Final engagement report build: LaTeX source -> PDF. Consumes lane `10-synthesis-report`'s
report draft and findings.

Adapted from the LRA governance project's standalone LaTeX build image
(`lra-governance/docker/lra-exercises-latex/Dockerfile`) — same pinned TeX Live base image digest,
plus `pandoc` for converting lane 10's markdown output into LaTeX section source.

## Build

```bash
docker build -t audit-report:local images/audit-report
```

## Report renderer

`pipeline/report/` renders the report from one data file: `report.tex` (this image compiles it),
an HTML/KaTeX preview, and a LaTeX workbench page. The image adds `python3-jinja2` and a
hash-pinned `cvss` (`requirements.lock`) for it. The renderer is mounted read-only at run time:

```bash
bash pipeline/report/render-in-docker.sh       # builds audit-report:local, writes pipeline/report/build/report.pdf
```

The container runs with `--network none`, a read-only root, `--cap-drop ALL` and a non-root user.

## Open decision

The document class, style, and required section structure for the LaTeX report are not yet
decided — tracked in the project TODO ("Decide on format and styleguide for LaTeX reporting of
results and sections needed"). Until that's settled, treat this image as build tooling only: it
can compile a `.tex` tree into a PDF, but lane 10 does not yet emit one. `pipeline/report/` is a
proposed template for that decision, rendered from sample data; it is not wired into the flow.
