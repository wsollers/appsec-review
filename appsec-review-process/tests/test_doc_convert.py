"""Gap 7: document intake for 02-doc-intelligence-ingest. Fixture documents are generated here; the
PDF/DOCX converters are faked (no Docker). One test per real tool runs only when it is installed."""
import io, json, re, shutil, subprocess, sys, tempfile, unittest, zipfile
from pathlib import Path
from unittest import mock
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
import container_execution as ce
import doc_convert as dc
import static_intelligence_core as core
from execution_state import file_hash
from schema_validate import validate_document

JOB = core.DOC
BINDING = {"job_id": "00-intake", "attempt_id": "i", "fingerprint": "f", "source_fingerprint": "a" * 64,
           "source_revision": "r", "pointer_sha256": "sha256:" + "b" * 64}
IMAGE = {"image_id": "audit-doc-convert", "digest": "sha256:" + "c" * 64}


def make_pdf(pages, encrypt=False):
    """A small valid PDF, one Helvetica text line per string; an empty page has no text at all."""
    n, objs = len(pages), [b"<< /Type /Catalog /Pages 2 0 R >>"]
    font = 3 + 2 * n
    objs.append(f"<< /Type /Pages /Kids [{' '.join(f'{3 + 2 * i} 0 R' for i in range(n))}] /Count {n} >>".encode())
    for i, lines in enumerate(pages):
        body = ("BT /F1 12 Tf 72 720 Td 14 TL " + " ".join(f"({line}) Tj T*" for line in lines) + " ET") if lines else ""
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font} 0 R >> >> "
                    f"/Contents {4 + 2 * i} 0 R >>".encode())
        objs.append(f"<< /Length {len(body)} >>\nstream\n{body}\nendstream".encode())
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out, offsets = b"%PDF-1.4\n", []
    for number, obj in enumerate(objs, 1):
        offsets.append(len(out)); out += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    extra = " /Encrypt 99 0 R" if encrypt else ""
    return out + f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R{extra} >>\nstartxref\n{xref}\n%%EOF\n".encode()


def make_docx(paragraphs):
    """(style or None, text) paragraphs in a minimal WordprocessingML package."""
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    body = "".join((f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else "<w:p>") + f"<w:r><w:t>{text}</w:t></w:r></w:p>"
                   for style, text in paragraphs)
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                         '<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" '
                         'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        archive.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                         'Target="word/document.xml"/></Relationships>')
        archive.writestr("word/document.xml", f'<?xml version="1.0"?><w:document {ns}><w:body>{body}</w:body></w:document>')
    return data.getvalue()


class FakeConverter:
    """Stands in for the B13 container: emulates pdftotext -layout and pandoc -t gfm on the fixtures."""
    image = IMAGE

    def __init__(self, target, fail=None):
        self.target, self.calls, self.fail = Path(target), [], fail

    def run(self, step, argv, output):
        self.calls.append((step, list(argv), output))
        ok = {"status": "OK", "cause": None, "exit_code": 0, "stdout": b"", "stderr": b"", "output": None}
        if argv[1:] == ["-v"]:
            return {**ok, "stderr": b"pdftotext version 24.02.0\nCopyright 2005-2024 The Poppler Developers\n"}
        if argv[1:] == ["--version"]:
            return {**ok, "stdout": b"pandoc 3.1.3\nFeatures: +server +lua\n"}
        if self.fail:
            return {**ok, "status": "FAILED", "cause": "CONTAINER_EXIT_NONZERO", "exit_code": 1, "stderr": self.fail}
        source = next(item for item in argv if item.startswith(dc.WORKSPACE + "/"))
        data = (self.target / source[len(dc.WORKSPACE) + 1:]).read_bytes()
        if argv[0] == dc.PDFTOTEXT:
            pages = re.findall(rb"stream\n(.*?)\nendstream", data, re.S)
            text = "".join("".join(line + "\n" for line in re.findall(r"\((.*?)\) Tj", page.decode())) + "\f" for page in pages)
        else:
            xml = zipfile.ZipFile(io.BytesIO(data)).read("word/document.xml").decode()
            parts = []
            for style, words in re.findall(r'<w:p>(?:<w:pPr><w:pStyle w:val="Heading(\d)"/></w:pPr>)?<w:r><w:t>(.*?)</w:t>', xml):
                parts.append(("#" * int(style) + " " if style else "") + words)
            text = "\n\n".join(parts) + "\n"
        return {**ok, "output": text.encode()}


def source_files(target):
    return {p.relative_to(target).as_posix(): {"kind": "file", "sha256": file_hash(p), "bytes": p.stat().st_size}
            for p in sorted(target.rglob("*")) if p.is_file()}


def run(target, converter=None, files=None):
    artifacts = {}
    out = core.extract(JOB, run_id="r", attempt_id="a", target=target, source=BINDING,
                       source_files=files or source_files(target), converter=converter, artifacts=artifacts)
    return out, artifacts


def manifest(artifacts):
    return json.loads(artifacts[dc.MANIFEST])


def write(target, relative, content):
    path = target / relative; path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(content, bytes) else path.write_text)(content)


class Universe(unittest.TestCase):
    def test_readmes_policy_changelog_and_doc_paths_are_included_and_classified(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            for relative in ("README.md", "src/lib/readme.txt", "tools/README", "SECURITY.md", ".github/SECURITY.md",
                             "ChangeLog", "NEWS", "HISTORY.rst", "CONTRIBUTING.md", "docs/api/endpoints.md",
                             "docs/design/overview.md", "docs/guide.adoc", "man/hello.1", "doc/hello.8"):
                write(t, relative, "# Title\nThe service must check auth.\n")
            for relative in ("vendor/lib/README.md", "node_modules/x/README.md", "build-aux/README", "src/notes.txt",
                             "CMakeLists.txt", "docs/spec.odt", "security.c", "src/readme.py", "lib/libfoo.so.1"):
                write(t, relative, "x\n")
            out, _ = run(t)
            got = {item["path"]: (item["doc_class"], item["format"]) for item in out["documents"]}
            self.assertEqual(got, {
                ".github/SECURITY.md": ("security_policy", "markdown"), "CONTRIBUTING.md": ("other", "markdown"),
                "ChangeLog": ("changelog", "text"), "HISTORY.rst": ("changelog", "rst"), "NEWS": ("changelog", "text"),
                "README.md": ("readme", "markdown"), "SECURITY.md": ("security_policy", "markdown"),
                "doc/hello.8": ("manual", "roff"), "docs/api/endpoints.md": ("api", "markdown"),
                "docs/design/overview.md": ("design", "markdown"), "docs/guide.adoc": ("other", "adoc"),
                "man/hello.1": ("manual", "roff"), "src/lib/readme.txt": ("readme", "text"),
                "tools/README": ("readme", "text")})
            self.assertEqual(out["skipped"], [
                {"path": "CMakeLists.txt", "reason": "outside-document-scope"},
                {"path": "build-aux/README", "reason": "excluded-path:build-system"},
                {"path": "docs/spec.odt", "reason": "unsupported-format:.odt"},
                {"path": "node_modules/x/README.md", "reason": "excluded-path:vendored"},
                {"path": "src/notes.txt", "reason": "outside-document-scope"},
                {"path": "vendor/lib/README.md", "reason": "excluded-path:vendored"}])
            self.assertIn("unsupported-document-format:docs/spec.odt", out["coverage_gaps"])
            self.assertEqual(validate_document(out, "doc-intelligence.schema.json"), [])
            policy = [r for r in out["records"] if r["path"] == "SECURITY.md" and r["kind"] == "document"][0]
            self.assertEqual((policy["doc_class"], policy["topics"], policy["citation"]),
                             ("security_policy", ["reporting_policy"], "SECURITY.md:1"))

    def test_readme_only_checkout_is_applicable(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d); write(t, "README.md", "# hello\n")
            out, _ = run(t)
            self.assertEqual((out["status"], out["applicability"], out["inventory"]["candidates"]), ("OK", core.APPLICABLE, 1))

    def test_no_documents_is_not_applicable_with_skips_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d); write(t, "src/main.c", "int main(void){return 0;}\n"); write(t, "src/notes.txt", "x\n")
            out, artifacts = run(t)
            self.assertEqual((out["status"], out["records"], out["coverage_gaps"]), ("SKIPPED", [], []))
            self.assertEqual(out["skipped"], [{"path": "src/notes.txt", "reason": "outside-document-scope"}])
            self.assertEqual(manifest(artifacts)["documents"], [])
            self.assertEqual(validate_document(out, "doc-intelligence.schema.json"), [])


class Conversion(unittest.TestCase):
    def test_html_drops_script_style_and_comments_and_keeps_links_tables_and_lines(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "docs/index.html", '<html><head><title>Guide</title>\n<script>var leak = "SCRIPT-SECRET";\n'
                  'document.write("<p>injected</p>")</script>\n<style>p { color: red }</style></head>\n<body>\n'
                  '<!-- COMMENT-TEXT -->\n<h2>Authentication</h2>\n<p>Sessions expire; see <a href="https://x.test/a">the policy</a>'
                  ' and <a href="javascript:alert(1)">this</a>.</p>\n<table><tr><th>Cipher</th><td>AES-GCM</td></tr></table>\n'
                  '<script src="x.js"></script></body></html>\n')
            out, artifacts = run(t)
            [entry] = manifest(artifacts)["documents"]
            text = artifacts[entry["text_path"]].decode()
            for absent in ("SCRIPT-SECRET", "injected", "color", "COMMENT-TEXT", "javascript"):
                self.assertNotIn(absent, text)
            self.assertEqual(text, "Guide\n## Authentication\nSessions expire; see the policy (https://x.test/a) and this.\n"
                                   "Cipher | AES-GCM\n")
            self.assertEqual(entry["provenance"], {"kind": "source-line", "lines": [1, 7, 8, 9]})
            self.assertEqual((entry["converter"]["name"], entry["converter"]["image_id"]), ("html.parser", None))
            section = [r for r in out["records"] if r["kind"] == "security-section"][0]
            self.assertEqual((section["summary"], section["topics"], section["citation"], section["locator"]),
                             ("Authentication", ["auth"], "docs/index.html:7", "line:7:text-line:2"))
            self.assertEqual(validate_document(manifest(artifacts), "doc-text-manifest.schema.json"), [])

    def test_man_page_macros_are_stripped_with_line_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "man/hello.1", '.\\" Copyright notice\n.TH HELLO 1 "2024" "GNU"\n.SH NAME\nhello \\- friendly greeting\n'
                  '.de XX\nmacro body\n..\n.SH SECURITY\n.B hello\nreads \\fI~/.hellorc\\fR and never stores \\fBpasswords\\fP.\n'
                  '.TP\n.BR \\-t ", " \\-\\-traditional\nuse the traditional greeting\n')
            out, artifacts = run(t)
            [entry] = manifest(artifacts)["documents"]
            self.assertEqual(artifacts[entry["text_path"]].decode(),
                             "# HELLO(1)\n## NAME\nhello - friendly greeting\n## SECURITY\nhello\n"
                             "reads ~/.hellorc and never stores passwords.\n-t, --traditional\nuse the traditional greeting\n")
            self.assertEqual(entry["provenance"]["lines"], [2, 3, 4, 8, 9, 10, 12, 13])
            kinds = {(r["kind"], r["locator"]) for r in out["records"]}
            self.assertIn(("security-section", "line:8:text-line:4"), kinds)
            self.assertIn(("document-statement", "line:10:text-line:6"), kinds)
            self.assertEqual(out["documents"][0]["doc_class"], "manual")

    def test_pdf_through_faked_pdftotext_keeps_page_provenance_and_records_versions(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "docs/design.pdf", make_pdf([["System Design overview for the reporting service"],
                                                  ["All clients must use TLS 1.3", "Tokens are stored in the vault"]]))
            fake = FakeConverter(t)
            out, artifacts = run(t, fake)
            self.assertEqual(out["status"], "OK")
            [entry] = manifest(artifacts)["documents"]
            self.assertEqual(entry["provenance"], {"kind": "page", "pages": [[1, 1], [2, 3]]})
            self.assertEqual(entry["converter"]["name"], "pdftotext")
            self.assertEqual(entry["converter"]["version"], "pdftotext version 24.02.0")
            self.assertEqual(entry["converter"]["image_digest"], IMAGE["digest"])
            self.assertEqual(entry["converter"]["argv"][:2], [dc.PDFTOTEXT, "-layout"])
            self.assertEqual(entry["text_sha256"], core._sha_bytes(artifacts[entry["text_path"]]))
            self.assertEqual(entry["source_sha256"], "sha256:" + file_hash(t / "docs/design.pdf"))
            tls = [r for r in out["records"] if "tls" in r.get("topics", [])][0]
            self.assertEqual((tls["locator"], tls["citation"]), ("page:2:line:1", "docs/design.pdf#page=2"))
            self.assertEqual([call[0].split("-")[1] for call in fake.calls], ["pdftotext", "version"])
            self.assertEqual(validate_document(out, "doc-intelligence.schema.json"), [])
            self.assertEqual(validate_document(manifest(artifacts), "doc-text-manifest.schema.json"), [])

    def test_image_only_encrypted_corrupt_and_oversized_pdfs_are_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "docs/scan.pdf", make_pdf([[], []]))
            write(t, "docs/locked.pdf", make_pdf([["secret plan"]], encrypt=True))
            write(t, "docs/broken.pdf", b"not a pdf at all")
            write(t, "docs/huge.pdf", make_pdf([["x" * 4000]]))
            fake = FakeConverter(t)
            limits = {**core._doc_limits(), "binary_document_max_bytes": 2000}
            with mock.patch.object(core, "_doc_limits", return_value=limits):
                out, artifacts = run(t, fake)
            self.assertEqual(out["status"], "OK_WITH_GAPS")
            self.assertEqual(sorted(out["coverage_gaps"]), [
                "corrupt-document:docs/broken.pdf", "encrypted-document:docs/locked.pdf",
                "image-only-or-scanned-pdf:docs/scan.pdf:0-chars-2-pages", "oversized-input:docs/huge.pdf",
                "zero-indexable-records"])
            self.assertEqual({item["path"]: item["reason"] for item in out["documents"]}, {
                "docs/broken.pdf": "corrupt-document", "docs/locked.pdf": "encrypted-document",
                "docs/scan.pdf": "image-only-or-scanned-pdf", "docs/huge.pdf": "oversized-input"})
            self.assertEqual([call[1][-2] for call in fake.calls], ["/workspace/docs/scan.pdf"])   # only scan.pdf ran
            self.assertEqual(manifest(artifacts)["documents"], [])
            self.assertEqual(validate_document(out, "doc-intelligence.schema.json"), [])

    def test_failed_conversion_and_missing_converter_are_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d); write(t, "docs/a.pdf", make_pdf([["Design text that is long enough to count"]]))
            out, _ = run(t, None)
            self.assertEqual(out["coverage_gaps"], ["converter-unavailable:docs/a.pdf", "zero-indexable-records"])
            out, _ = run(t, FakeConverter(t, fail=b"Command Line Error: Incorrect password\n"))
            self.assertIn("encrypted-document:docs/a.pdf", out["coverage_gaps"])
            out, _ = run(t, FakeConverter(t, fail=b"Syntax Error: Couldn't find trailer dictionary\n"))
            self.assertIn("conversion-failed:container_exit_nonzero-exit-1:docs/a.pdf", out["coverage_gaps"])

    def test_docx_through_faked_pandoc(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "docs/threat-model.docx", make_docx([("Heading1", "Security Model"), (None, "Tokens are signed with HMAC."),
                                                          ("Heading2", "Deployment"), (None, "Operators must rotate keys.")]))
            fake = FakeConverter(t)
            out, artifacts = run(t, fake)
            [entry] = manifest(artifacts)["documents"]
            self.assertEqual((entry["doc_class"], entry["format"], entry["provenance"]), ("design", "docx", {"kind": "converted-line"}))
            self.assertEqual(entry["converter"]["version"], "pandoc 3.1.3")
            self.assertEqual(fake.calls[0][1][:3], [dc.PANDOC, "--sandbox", "-f"])
            got = {(r["kind"], r["locator"], r["summary"]) for r in out["records"] if r["kind"] != "document"}
            self.assertEqual(got, {("security-section", "text-line:1", "Security Model"),
                                   ("document-statement", "text-line:3", "Tokens are signed with HMAC."),
                                   ("document-heading", "text-line:5", "Deployment"),
                                   ("document-statement", "text-line:7", "Operators must rotate keys.")})
            self.assertEqual(validate_document(out, "doc-intelligence.schema.json"), [])

    def test_encrypted_and_corrupt_docx_never_reach_pandoc(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "docs/locked.docx", b"\xd0\xcf\x11\xe0" + "EncryptedPackage".encode("utf-16-le"))
            write(t, "docs/bad.docx", b"PK\x03\x04garbage")
            fake = FakeConverter(t)
            out, _ = run(t, fake)
            self.assertEqual(fake.calls, [])
            self.assertEqual(out["coverage_gaps"], ["corrupt-document:docs/bad.docx", "encrypted-document:docs/locked.docx",
                                                    "zero-indexable-records"])

    def test_output_is_deterministic_and_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            write(t, "README.md", "# Demo\nThe service must authenticate.\n")
            write(t, "docs/index.html", '<h1>Keys</h1><p>api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"</p>\n')
            write(t, "docs/design.pdf", make_pdf([["Design: data must be encrypted at rest"]]))
            write(t, "man/x.1", ".TH X 1\n.SH DESCRIPTION\nx must authenticate\n")
            one, first = run(t, FakeConverter(t))
            two, second = run(t, FakeConverter(t))
            self.assertEqual((one, first), (two, second))
            self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", json.dumps(one) + "".join(v.decode() for v in first.values()))
            self.assertEqual(one["converted_text"], {"manifest": dc.MANIFEST, "sha256": core._sha_bytes(first[dc.MANIFEST]),
                                                     "documents": 3})
            self.assertEqual([e["redaction"] for e in manifest(first)["documents"]], ["unchanged", "redacted", "unchanged"])


class Boundary(unittest.TestCase):
    def test_container_request_is_network_none_read_only_target_and_no_shell(self):
        converter = dc.ContainerConverter(attempt=Path("/tmp/attempt"), run_id="run1", job=JOB, target="/srv/target",
            converter={"image": IMAGE, "container_limits": core.tunables.container_limits(JOB)},
            source_snapshot_sha256="sha256:" + "a" * 64)
        command = dc.argv("pdf", "docs/a b.pdf", "out.txt")
        request = converter.request("dc-pdftotext-0123", command)
        self.assertEqual(ce.request_errors(request, run_id="run1", job_id=JOB, attempt_id="dc-pdftotext-0123"), [])
        self.assertEqual(request["network"], {"mode": "none", "destinations": []})
        self.assertEqual(request["target_mounts"], [{"host_path": "/srv/target", "container_path": "/workspace"}])
        self.assertEqual(request["argv"], [dc.PDFTOTEXT, "-layout", "-enc", "UTF-8", "-eol", "unix",
                                           "/workspace/docs/a b.pdf", "/scratch/out.txt"])
        self.assertIn("--read-only", ce.BOUNDARY_FLAGS)

    def test_template_contract_and_graph_agree(self):
        template = json.loads((ROOT / "pipeline/job-templates/02-doc-intelligence-ingest.json").read_text())
        contract = json.loads((ROOT / "pipeline/output-contracts/doc-intelligence.json").read_text())
        graph = json.loads((ROOT / "pipeline/job-graph.json").read_text())
        self.assertTrue(template["implemented"] and graph["jobs"][JOB]["implemented"])
        self.assertTrue(set(contract["required_files"]) <= set(template["outputs"]["files"]))
        self.assertTrue({dc.MANIFEST, dc.RECEIPT} <= set(template["outputs"]["files"]))
        image = json.loads((ROOT.parent / "images/audit-doc-convert/image.json").read_text())
        self.assertEqual(image["builds"][0]["image_id"], template["tunables"]["image_id"]["value"])
        dockerfile = (ROOT.parent / "images/audit-doc-convert/Dockerfile").read_text()
        self.assertRegex(dockerfile, r"poppler-utils=\S+"); self.assertRegex(dockerfile, r"pandoc=\S+")
        self.assertNotRegex(dockerfile, r"(?m)^\s*(COPY|ADD)\b")


class DerivedIndex(unittest.TestCase):
    """Hand-off: the published PDF text is searchable through 02-evidence-index-derived with page provenance."""

    def test_converted_pdf_is_searchable_with_page_provenance(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import evidence_index_derived as derived
        import execution_state as state
        from test_evidence_index_derived import accept, plain_envelope
        from test_evidence_index_enrichment import ATTEMPT, RUN_ID, SOURCE, ProducerFixture
        from worker_result import artifact_records, terminal_envelope
        with tempfile.TemporaryDirectory() as d:
            old, state.RUNS = state.RUNS, Path(d)
            try:
                jobs = state.RUNS / RUN_ID / "data" / "jobs"
                fixture = ProducerFixture(state.RUNS)
                index = jobs / "02-evidence-index" / "whole"; index_attempt = index / "attempts" / "index-1"
                state.atomic_json(index_attempt / "lineage.json", {"source_snapshot_sha256": "sha256:" + SOURCE})
                plain_envelope(index_attempt, ["lineage.json"]); accept(index, RUN_ID, "02-evidence-index", index_attempt)
                write(fixture.target, "docs/design.pdf", make_pdf([["Overview of the reporting service and its parts"],
                                                                   ["Operators rotate the TOKENROTATION signing key monthly"]]))
                artifacts = {}
                result = core.extract(JOB, run_id=RUN_ID, attempt_id=ATTEMPT, target=fixture.target,
                                      source={**BINDING, "source_fingerprint": SOURCE},
                                      source_files=source_files(fixture.target), converter=FakeConverter(fixture.target),
                                      artifacts=artifacts)
                attempt = fixture.attempt
                state.atomic_json(attempt / "doc-intelligence.json", result)
                for relative, body in artifacts.items():
                    (attempt / relative).parent.mkdir(parents=True, exist_ok=True); (attempt / relative).write_bytes(body)
                self.assertEqual(validate_document(json.loads(artifacts[dc.DERIVED_MANIFEST]), derived.TEXT_MANIFEST_SCHEMA), [])
                envelope = terminal_envelope(run_id=RUN_ID, job_id=JOB, attempt_id=ATTEMPT, worker_kind="deterministic_python",
                    execution_status="OK", acceptance_status="CURRENT", input_fingerprint="sha256:" + "f" * 64,
                    output_contract="doc-intelligence", started_at="2026-01-01T00:00:00+00:00",
                    finished_at="2026-01-01T00:00:01+00:00", summary="fixture", artifacts=artifact_records(attempt,
                        ["doc-intelligence.json", "status.json", "permission.json", "lineage.json", *sorted(artifacts)]))
                state.atomic_json(attempt / "result.json", envelope)
                accept(fixture.base, RUN_ID, JOB, attempt, extra={"fingerprint": "sha256:" + "f" * 64})
                derived.run(RUN_ID, "dagster-test")
                found = derived.query(RUN_ID, text="TOKENROTATION")
                hit = found["text_hits"][0]
                self.assertEqual((hit["source_path"], hit["page"], hit["start_line"], hit["end_line"]),
                                 ("docs/design.pdf", 2, 2, 2))
                self.assertEqual(hit["producer_job_id"], JOB)
                self.assertTrue(any("docs/design.pdf" in r["search_text"] for r in found["results"]))   # the locator record
            finally:
                state.RUNS = old


class LocalConverter:
    """Runs the real tool on this host with the container paths mapped; used only when it is installed."""
    image = IMAGE

    def __init__(self, target, scratch):
        self.target, self.scratch = str(target), Path(scratch)

    def run(self, step, argv, output):
        mapped = [shutil.which(Path(argv[0]).name)] + [item.replace(dc.WORKSPACE + "/", self.target + "/")
                                                       .replace("/scratch/", str(self.scratch) + "/") for item in argv[1:]]
        done = subprocess.run(mapped, capture_output=True, timeout=60)
        produced = self.scratch / output if output else None
        return {"status": "OK" if done.returncode == 0 else "FAILED", "cause": None if done.returncode == 0 else
                "CONTAINER_EXIT_NONZERO", "exit_code": done.returncode, "stdout": done.stdout, "stderr": done.stderr,
                "output": produced.read_bytes() if produced and produced.exists() else None}


class RealTools(unittest.TestCase):
    @unittest.skipUnless(shutil.which("pdftotext"), "pdftotext (poppler-utils) is not installed")
    def test_real_pdftotext_gives_page_provenance_and_scanned_gap(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as s:
            t = Path(d)
            write(t, "docs/design.pdf", make_pdf([["Overview of the reporting service design and its parts"],
                                                  ["Clients must use TLS 1.3 for every connection to the service"]]))
            write(t, "docs/scan.pdf", make_pdf([[]]))
            out, artifacts = run(t, LocalConverter(t, s))
            [entry] = manifest(artifacts)["documents"]
            self.assertEqual(entry["provenance"]["kind"], "page"); self.assertEqual(len(entry["provenance"]["pages"]), 2)
            self.assertTrue(entry["converter"]["version"].startswith("pdftotext version"))
            self.assertIn("Clients must use TLS 1.3", artifacts[entry["text_path"]].decode())
            self.assertTrue(any(r["citation"] == "docs/design.pdf#page=2" for r in out["records"]))
            self.assertIn("image-only-or-scanned-pdf:docs/scan.pdf:0-chars-1-pages", out["coverage_gaps"])

    @unittest.skipUnless(shutil.which("pandoc"), "pandoc is not installed")
    def test_real_pandoc_converts_docx(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as s:
            t = Path(d)
            write(t, "docs/design.docx", make_docx([("Heading1", "Security Model"), (None, "Tokens are signed with HMAC.")]))
            out, artifacts = run(t, LocalConverter(t, s))
            [entry] = manifest(artifacts)["documents"]
            self.assertIn("Tokens are signed with HMAC.", artifacts[entry["text_path"]].decode())
            self.assertTrue(entry["converter"]["version"].startswith("pandoc"))


if __name__ == "__main__":
    unittest.main()
