# Generated operator and design documents

These retained artifacts demonstrate the canonical LaTeX document path using the operator and
executive-design templates. They are draft documentation outputs, not review evidence.

| Document | Canonical source | PDF | KaTeX HTML |
|---|---|---|---|
| Operator user guide | [`user-guide.tex`](user-guide.tex) | [`user-guide.pdf`](user-guide.pdf) | [`user-guide.html`](user-guide.html) |
| Executive design document | [`design-doc.tex`](design-doc.tex) | [`design-doc.pdf`](design-doc.pdf) | [`design-doc.html`](design-doc.html) |

The `.tex` file is authoritative. The PDF is compiled from that exact source by the pinned
`audit-report:local` container with networking disabled. The HTML is produced from the same source
by `pipeline/report/render_documents.py` and uses the report workbench's browser-side KaTeX
renderer. TikZ diagrams render in PDF and appear as explicit diagram placeholders in HTML.

> **PDFs lag the sources (2026-10-03).** `user-guide.tex` and `design-doc.tex` gained the gap
> punch-list notes (base-image packages, OSV Debian/Alpine) and the HTML was regenerated; the PDFs
> were not, because no Docker daemon or `audit-report:local` was available. Recompile them with the
> commands below and remove this note.

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
