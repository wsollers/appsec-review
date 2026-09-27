import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_documents


class RenderDocumentsTest(unittest.TestCase):
    def test_renders_read_only_html_and_retains_exact_source(self):
        source = render_documents.HERE / "latex" / "user-guide.tex"
        with tempfile.TemporaryDirectory() as directory:
            tex_output, html_output = render_documents.render_document(source, Path(directory))
            self.assertEqual(source.read_bytes(), tex_output.read_bytes())
            html = html_output.read_text(encoding="utf-8")
            self.assertIn("var REPORT=DOCS[Object.keys(DOCS)[0]], VIEWER=true", html)
            self.assertIn("appsec-house.sty", html)
            self.assertIn("katex.renderToString", html)
            self.assertNotIn("{{", html)

    def test_rejects_a_fragment(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fragment.tex"
            source.write_text("\\section{Only a fragment}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a complete"):
                render_documents.render_document(source, Path(directory) / "out")


if __name__ == "__main__":
    unittest.main()
