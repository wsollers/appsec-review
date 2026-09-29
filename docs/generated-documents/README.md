# Generated operator and design documents

These retained artifacts demonstrate the canonical LaTeX document path using the operator and
executive-design templates. They are draft documentation outputs, not review evidence.

| Document | Canonical source | PDF | KaTeX HTML |
|---|---|---|---|
| Operator user guide | [`user-guide.tex`](user-guide.tex) | [`user-guide.pdf`](user-guide.pdf) | [`user-guide.html`](user-guide.html) |
| Executive design document | [`design-doc.tex`](design-doc.tex) | [`design-doc.pdf`](design-doc.pdf) **(stale: v0.5; rebuild for v0.6)** | [`design-doc.html`](design-doc.html) |

**Stale PDF.** `design-doc.pdf` is still the v0.5 build. The `.tex` and `.html` are v0.6
(2026-09-29), which was regenerated in a session without Docker. Rebuild it in WSL with
`SKIP_BUILD=1 bash pipeline/report/latex/build-in-docker.sh design-doc.tex`, then copy
`pipeline/report/build/latex/design-doc.pdf` here and remove this note.

The `.tex` file is authoritative. The PDF is compiled from that exact source by the pinned
`audit-report:local` container with networking disabled. The HTML is produced from the same source
by `pipeline/report/render_documents.py` and uses the report workbench's browser-side KaTeX
renderer. TikZ diagrams render in PDF and appear as explicit diagram placeholders in HTML.

Regenerate from the repository root:

```bash
python3 pipeline/report/render_documents.py --out docs/generated-documents \
  pipeline/report/latex/user-guide.tex pipeline/report/latex/design-doc.tex
SKIP_BUILD=1 bash pipeline/report/latex/build-in-docker.sh user-guide.tex design-doc.tex
cp pipeline/report/build/latex/user-guide.pdf docs/generated-documents/user-guide.pdf
cp pipeline/report/build/latex/design-doc.pdf docs/generated-documents/design-doc.pdf
```

Do not treat template metrics or fill-ins as measured project results. Replace `\tbd{...}` fields
and qualify factual claims before changing a document's status from Draft.
