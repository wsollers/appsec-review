"""Tests for the deterministic evidence redactor and its receipt (ADR-0010 G9-A, task V06).

Every secret here is synthetic and assembled at run time from fragments plus a fixed-seed stream,
so neither this file nor the fixture templates contain a scannable secret literal. Fixture
templates carry `@@NAME@@` placeholders; oversized, binary, link and secret-named inputs are
generated because they cannot or should not be committed.

The invariant tests run over ALL cases under BOTH policies. `assert_no_planted_values` lives here,
not in the module: the module must never need to know a planted value.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evidence_redaction as er
from schema_validate import SchemaStore, validate_document

FIXTURES = ROOT / "tests" / "fixtures" / "evidence-redaction"
SCHEMA_PATH = ROOT.parent / "schemas" / er.RECEIPT_SCHEMA
DOC_PATH = ROOT.parent / "docs" / "evidence-redaction.md"
LIMITS = er.Limits(max_file_bytes=65536, max_line_length=4096, max_files=40,
                   max_total_bytes=200000, max_json_depth=16, max_path_length=200)

UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM = "abcdefghijklmnopqrstuvwxyz" + UPPER_DIGITS
BASE64 = ALNUM + "+/"
BASE64URL = ALNUM + "-_"


def stream(label: str, alphabet: str, length: int) -> str:
    """Deterministic on every platform and Python version (sha256 counter, rejection sampled)."""
    out, counter, bound = [], 0, 256 - 256 % len(alphabet)
    while len(out) < length:
        for byte in hashlib.sha256(f"v06-synthetic:{label}:{counter}".encode()).digest():
            if byte < bound and len(out) < length:
                out.append(alphabet[byte % len(alphabet)])
        counter += 1
    return "".join(out)


def b64url(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def pem(label: str, name: str, lines: int, closed: bool = True) -> str:
    dashes = "-" * 5
    body = ["FAKE" + stream(f"{name}:{index}", BASE64, 60) for index in range(lines)]
    block = [dashes + "BEGIN " + label + dashes, *body]
    if closed:
        block.append(dashes + "END " + label + dashes)
    return "\n".join(block)


PRIVATE = "PRIVATE " + "KEY"
SECRETS = {
    "AWS_KEY": "AK" + "IA" + "FAKEEXAMPLE" + stream("aws", UPPER_DIGITS, 5),
    "GITHUB_TOKEN": "gh" + "p_" + "FAKEexample" + stream("github", ALNUM, 25),
    "SK_KEY": "sk" + "-" + "EXAMPLEfake" + stream("sk", ALNUM, 24),
    "JWT": ".".join([b64url({"alg": "none", "typ": "FAKE"}), b64url({"sub": "EXAMPLE", "aud": "synthetic"}),
                     stream("jwt", BASE64URL, 43)]),
    "BEARER": "FAKE" + stream("bearer", ALNUM, 36),
    "BLOB": "EXAMPLE" + stream("blob", ALNUM, 40) + "7",
    "AZURE_KEY": "FAKE" + stream("azure", BASE64, 82) + "==",
    "HUMAN_PASSWORD": "SuperFake-Hunter2-99!",
    "SHORT_PASSWORD": "Fake2!x",
    "SPACED_PASSWORD": "correct horse FAKE staple",
    "URL_PASSWORD": "FAKE-url-pw-9",
    "NUMERIC_PASSWORD": "90210427",
    "ARG_PASSWORD": "FAKE-argv-pw",
    "ENV_SECRET": "FAKEflavor-internal",
    "FINGERPRINT": hashlib.sha256(b"EXAMPLE synthetic fingerprint").hexdigest(),
    "PEM_RSA": pem("RSA " + PRIVATE, "rsa", 4),
    "PEM_OPENSSH": pem("OPENSSH " + PRIVATE, "openssh", 3),
    "PEM_TRUNCATED": pem("EC " + PRIVATE, "truncated", 2, closed=False),
}
SURVIVORS = {  # public material: must be published untouched
    "PUBLIC_CERT": "\n".join(["-" * 5 + "BEGIN CERTIFICATE" + "-" * 5,
                              *["MIIB" + stream(f"cert:{index}", BASE64, 60) for index in range(3)],
                              "-" * 5 + "END CERTIFICATE" + "-" * 5]),
    "SSH_PUBLIC": "AAAAC3NzaC1lZDI1NTE5AAAAI" + stream("sshpub", BASE64, 43),
}
PLANTS = {**SECRETS, **SURVIVORS}


def leak_values() -> list[str]:
    values = []
    for name, value in SECRETS.items():
        parts = [line for line in value.split("\n") if "BEGIN" not in line and "END" not in line] if name.startswith("PEM_") else [value]
        for part in parts:
            values.append(part)
            if len(part) >= 16:
                values += [part[:len(part) // 2], part[len(part) // 2:]]
    return values


LEAK_VALUES = leak_values()
_PLACEHOLDER = re.compile(r'"@@([A-Z0-9_]+):number@@"|@@([A-Z0-9_]+)(?::(json|uescape))?@@')


def materialize(template: str) -> str:
    def substitute(match: re.Match) -> str:
        if match.group(1):
            return PLANTS[match.group(1)]
        value, mode = PLANTS[match.group(2)], match.group(3)
        if mode == "json":
            return json.dumps(value)[1:-1]
        if mode == "uescape":
            return "".join(f"\\u{ord(char):04x}" for char in value[:4]) + value[4:]
        return value
    return _PLACEHOLDER.sub(substitute, template)


def load_template(data: bytes) -> str:
    """A tracked fixture is a TEMPLATE, not redactor input. Git may hand it to us with CRLF line
    endings (`core.autocrlf=true`, the common Windows setting), so the newline convention of a
    template is normalized to LF here and the redactor's input never depends on how the repository
    was checked out. Byte-for-byte preservation of CRLF, LF and a BOM is proven separately with
    inputs GENERATED at test time (see test_crlf_and_lf_are_each_preserved_byte_for_byte...)."""
    return data.decode("utf-8").replace("\r\n", "\n")


def fixture_case(name: str):
    def build(source: Path) -> None:
        for path in sorted((FIXTURES / name).rglob("*")):
            if path.is_file():
                target = source / path.relative_to(FIXTURES / name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(materialize(load_template(path.read_bytes())).encode("utf-8"))
    return build


def write(source: Path, relative: str, data: bytes | str) -> None:
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


PW = f'password = "{SECRETS["HUMAN_PASSWORD"]}"\n'


def case_oversized(source: Path) -> None:
    write(source, "big.log", PW + "x" * LIMITS.max_file_bytes)
    write(source, "ok.log", PW)


def case_long_line(source: Path) -> None:
    write(source, "long.log", "y" * LIMITS.max_line_length + " " + PW)
    write(source, "minified.json", json.dumps({"text": "z" * LIMITS.max_line_length + SECRETS["AWS_KEY"]}))
    write(source, "at-limit.log", "y" * (LIMITS.max_line_length - len(PW) - 40) + PW)


def case_deep_nesting(source: Path) -> None:
    write(source, "deep.json", "[" * 17 + json.dumps(SECRETS["AWS_KEY"]) + "]" * 17)
    write(source, "abyss.json", "[" * 30000 + json.dumps(SECRETS["BLOB"]) + "]" * 30000)
    write(source, "at-limit.json", "[" * 16 + json.dumps(SECRETS["AWS_KEY"]) + "]" * 16)


def case_binary(source: Path) -> None:
    write(source, "nul.log", PW.encode() + b"\x00tail")
    write(source, "latin1.txt", b"caf\xe9 " + PW.encode())
    write(source, "utf16.log", PW.encode("utf-16"))


def case_newlines(source: Path) -> None:
    write(source, "crlf.log", f"first\r\napi_key={SECRETS['SHORT_PASSWORD']}\r\nlast\r\n".encode())
    write(source, "lf.log", f"first\napi_key={SECRETS['SHORT_PASSWORD']}\nlast\n".encode())
    write(source, "bom.json", b"\xef\xbb\xbf" + json.dumps({"password": SECRETS["HUMAN_PASSWORD"]}).encode())


def case_secret_filename(source: Path) -> None:
    write(source, SECRETS["AWS_KEY"] + ".log", "nothing secret inside\n")
    write(source, "token=" + SECRETS["BEARER"] + "/inner.log", "nothing secret inside\n")
    write(source, "plain.log", "nothing secret inside\n")


def case_unsupported(source: Path) -> None:
    write(source, "blob.bin", PW)
    write(source, "noextension", PW)
    write(source, er.RECEIPT_FILENAME, json.dumps({"password": SECRETS["HUMAN_PASSWORD"]}))
    write(source, "empty.log", b"")


def case_links(source: Path) -> None:
    outside = source.parent / (source.name + "-outside")
    write(outside, "secret.log", PW)
    write(source, "real.log", PW)
    os.symlink(outside / "secret.log", source / "link.log")
    os.symlink(outside, source / "linkdir", target_is_directory=True)


def case_total_bytes(source: Path) -> None:
    for index in range(4):
        write(source, f"part-{index}.log", PW + ("filler line\n" * 5000))


def case_mixed(source: Path) -> None:
    write(source, "a-clean.log", "scan ok\n")
    write(source, "b-secrets.log", PW + f"id {SECRETS['AWS_KEY']} seen\n")
    write(source, "c-findings.json", json.dumps({"results": [{"lines": PW, "client_secret": SECRETS["SHORT_PASSWORD"]}]}))
    write(source, "d-blob.bin", PW)
    write(source, SECRETS["GITHUB_TOKEN"] + ".txt", "named after a token\n")


CAN_SYMLINK = hasattr(os, "symlink") and os.name != "nt"
CASES = {name: fixture_case(name) for name in sorted(path.name for path in FIXTURES.iterdir() if path.is_dir())}
CASES.update({"gen-oversized": case_oversized, "gen-long-line": case_long_line, "gen-deep-nesting": case_deep_nesting,
              "gen-binary": case_binary, "gen-newlines": case_newlines, "gen-secret-filename": case_secret_filename,
              "gen-unsupported": case_unsupported, "gen-total-bytes": case_total_bytes, "gen-mixed": case_mixed})
if CAN_SYMLINK:
    CASES["gen-links"] = case_links


@contextmanager
def captured():
    out, err, log = io.StringIO(), io.StringIO(), io.StringIO()
    handler, root = logging.StreamHandler(log), logging.getLogger()
    level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            yield lambda: out.getvalue() + err.getvalue() + log.getvalue()
    finally:
        root.removeHandler(handler)
        root.setLevel(level)


def exception_text(error: BaseException) -> str:
    extra = [str(getattr(error, "reasons", "")), str(getattr(error, "errors", ""))]
    return "".join(traceback.format_exception(error)) + repr(error) + str(error) + "".join(extra)


def views(text: str) -> list[str]:
    return [text, re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), text)]


def assert_no_planted_values(test: unittest.TestCase, label: str, text: str) -> None:
    for view in views(text):
        for value in LEAK_VALUES:
            test.assertNotIn(value, view, f"planted value leaked into {label}")


def tree(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()}


class Run:
    def __init__(self, base: Path, name: str, policy: str, tag: str = "a"):
        self.source = base / name / "source"
        if not self.source.exists():
            self.source.mkdir(parents=True)
            CASES[name](self.source)
        self.published = base / name / f"published-{policy}-{tag}"
        self.receipt, self.error = None, None
        before = tree(self.source)
        with captured() as output:
            try:
                self.receipt = er.redact_tree(self.source, self.published, on_unhandled=policy, limits=LIMITS)
            except er.RedactionError as error:
                self.error = error
        self.output = output()
        self.source_unchanged = before == tree(self.source)

    def record(self, path: str) -> dict:
        return next(record for record in self.receipt["files"] if record["path"] == path)

    def text(self, path: str) -> str:
        return (self.published / path).read_bytes().decode("utf-8")


class RedactionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._temp.name)
        cls.runs = {(name, policy): Run(cls.base, name, policy) for name in CASES for policy in er.POLICIES}

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def published_runs(self):
        for key, run in self.runs.items():
            if run.receipt is not None:
                yield key, run

    def verify(self, receipt, published, policy="withhold", limits=LIMITS):
        er.verify_receipt(receipt, published, on_unhandled=policy, limits=limits)

    def verify_errors(self, receipt, published, policy="withhold", limits=LIMITS) -> list[str]:
        with self.assertRaises(er.ReceiptVerificationError) as caught:
            self.verify(receipt, published, policy, limits)
        return caught.exception.errors


class InvariantTests(RedactionTestCase):
    """One statement each, over every case under every policy."""

    def test_every_case_ran_and_at_least_one_policy_outcome_is_a_refusal(self):
        self.assertGreaterEqual(len(CASES), 15)
        self.assertTrue(any(isinstance(run.error, er.PublicationRefused) for run in self.runs.values()))
        for key, run in self.runs.items():
            with self.subTest(case=key):
                self.assertNotEqual(run.receipt is None, run.error is None)

    def test_invariant_no_planted_value_in_published_files_receipt_logs_or_exception_text(self):
        for key, run in self.runs.items():
            with self.subTest(case=key):
                assert_no_planted_values(self, "captured stdout/stderr/logging", run.output)
                if run.error is not None:
                    assert_no_planted_values(self, "exception text", exception_text(run.error))
                    continue
                for path, data in tree(run.published).items():
                    assert_no_planted_values(self, f"published file {path}", data.decode("utf-8"))
                    assert_no_planted_values(self, "a published path", path)
                assert_no_planted_values(self, "returned receipt", json.dumps(run.receipt))

    def test_invariant_refusal_publishes_nothing(self):
        for key, run in self.runs.items():
            if run.error is not None:
                with self.subTest(case=key):
                    self.assertFalse(run.published.exists())

    def test_invariant_every_published_receipt_is_schema_valid_and_verifies(self):
        for (name, policy), run in self.published_runs():
            with self.subTest(case=(name, policy)):
                self.assertEqual(validate_document(run.receipt, er.RECEIPT_SCHEMA), [])
                with captured() as output:
                    self.verify(run.receipt, run.published, policy)
                self.assertEqual(output(), "")
                self.assertEqual(json.loads(run.text(er.RECEIPT_FILENAME)), run.receipt)

    def test_invariant_totals_equal_sum_of_per_file_counts(self):
        for key, run in self.published_runs():
            with self.subTest(case=key):
                files, totals = run.receipt["files"], run.receipt["totals"]
                for kind in er.KINDS:
                    self.assertEqual(totals["redactions"][kind], sum(record["redactions"][kind] for record in files))
                self.assertEqual(totals["redactions_total"], sum(totals["redactions"].values()))
                self.assertEqual(totals["files_total"], len(files))
                self.assertEqual(totals["files_total"], totals["files_unchanged"] + totals["files_redacted"] + totals["files_withheld"])
                self.assertEqual(totals["published_bytes"], sum(len(data) for path, data in tree(run.published).items() if path != er.RECEIPT_FILENAME))

    def test_invariant_published_set_is_exactly_the_non_withheld_records_plus_the_receipt(self):
        for key, run in self.published_runs():
            with self.subTest(case=key):
                listed = {record["path"] for record in run.receipt["files"] if record["disposition"] != "withheld"}
                self.assertEqual(set(tree(run.published)), listed | {er.RECEIPT_FILENAME})

    def test_invariant_redacting_already_redacted_output_is_a_no_op(self):
        for (name, policy), run in self.published_runs():
            with self.subTest(case=(name, policy)):
                again_source = self.base / name / f"again-source-{policy}"
                shutil.copytree(run.published, again_source)
                (again_source / er.RECEIPT_FILENAME).unlink()  # reserved name; not evidence
                again = er.redact_tree(again_source, self.base / name / f"again-published-{policy}", on_unhandled="refuse", limits=LIMITS)
                self.assertEqual(again["totals"]["redactions_total"], 0)
                self.assertEqual({record["disposition"] for record in again["files"]} - {"unchanged"}, set())
                first = {path: data for path, data in tree(run.published).items() if path != er.RECEIPT_FILENAME}
                second = {path: data for path, data in tree(self.base / name / f"again-published-{policy}").items() if path != er.RECEIPT_FILENAME}
                self.assertEqual(first, second)

    def test_invariant_same_input_gives_byte_identical_output_and_receipt(self):
        for (name, policy), run in self.published_runs():
            with self.subTest(case=(name, policy)):
                second = Run(self.base, name, policy, tag="b")
                self.assertEqual(second.receipt, run.receipt)
                self.assertEqual(tree(second.published), tree(run.published))

    def test_invariant_source_is_never_modified(self):
        for key, run in self.runs.items():
            with self.subTest(case=key):
                self.assertTrue(run.source_unchanged)

    def test_invariant_every_withheld_record_names_a_reason_and_publishes_nothing(self):
        for key, run in self.published_runs():
            for record in run.receipt["files"]:
                with self.subTest(case=key, path=record["path"]):
                    if record["disposition"] == "withheld":
                        self.assertIn(record["withheld_reason"], er.WITHHELD_REASONS)
                        self.assertIsNone(record["published_sha256"])
                    else:
                        self.assertEqual(record["published_sha256"], hashlib.sha256((run.published / record["path"]).read_bytes()).hexdigest())

    def test_invariant_no_marker_carries_anything_but_a_kind_and_a_small_ordinal(self):
        for key, run in self.published_runs():
            for path, data in tree(run.published).items():
                for match in re.finditer(r"\[REDACTED:[^\]]*\]", data.decode("utf-8")):
                    with self.subTest(case=key, path=path):
                        self.assertRegex(match.group(0), r"^\[REDACTED:(" + "|".join(er.KINDS) + r"):[1-9][0-9]{0,8}\]$")


class AcceptanceFixtureTests(RedactionTestCase):
    def run_for(self, name, policy="withhold") -> Run:
        return self.runs[(name, policy)]

    def test_machine_tokens_are_redacted_by_shape_and_entropy(self):
        run = self.run_for("machine-tokens")
        log = run.record("scanner.log")
        self.assertEqual((log["disposition"], log["parser_mode"]), ("redacted", "text"))
        for kind in ("provider-token", "jwt", "high-entropy", "named-secret"):
            self.assertGreater(run.receipt["totals"]["redactions"][kind], 0, kind)
        self.assertIn("scan done files=12 findings=3", run.text("scanner.log"))
        self.assertIn("AccountName=examplestore", run.text("scanner.log"))
        self.assertEqual(json.loads(run.text("tokens.json"))["summary"], {"files": 12, "findings": 4})
        self.assertIsNone(self.run_for("machine-tokens", "refuse").error)

    def test_low_entropy_human_passwords_are_redacted_by_name(self):
        run = self.run_for("human-passwords")
        text = run.text("app-config.txt")
        self.assertLess(er.shannon_entropy(SECRETS["HUMAN_PASSWORD"]), 4.2)
        self.assertLess(len(SECRETS["SHORT_PASSWORD"]), 20)
        self.assertEqual(run.record("app-config.txt")["redactions"]["named-secret"], 8)
        self.assertEqual(run.record("app-config.txt")["redactions"]["url-credential"], 1)
        self.assertIn('username = "alice"', text)
        self.assertIn('timeout = "30"', text)
        self.assertIn("postgres://svc-user:[REDACTED:url-credential:", text)
        document = json.loads(run.text("findings.json"))
        self.assertRegex(document["results"][1]["extra"]["password"], er.MARKER_RE)  # a NUMBER under a secret name
        self.assertEqual(document["config"]["user"], "alice")
        self.assertRegex(document["config"]["credentials"]["value"], er.MARKER_RE)
        xml = run.text("settings.xml")
        self.assertIn("<username>alice</username><password>[REDACTED:named-secret:1]</password>", xml)
        self.assertIn('<add key="Db" connectionString="[REDACTED:named-secret:2]" />', xml)  # whole connection string

    def test_private_key_blocks_are_redacted_whole_and_public_material_survives(self):
        run = self.run_for("pem-blocks")
        log = run.text("keys.log")
        self.assertEqual(run.record("keys.log")["redactions"], {**{kind: 0 for kind in er.KINDS}, "private-key-block": 2})
        self.assertIn("reading key material\n[REDACTED:private-key-block:1]\nnext key\n[REDACTED:private-key-block:2]\npublic part", log)
        self.assertIn(SURVIVORS["PUBLIC_CERT"], log)
        self.assertIn(SURVIVORS["SSH_PUBLIC"], log)
        self.assertNotIn("PRIVATE", log)
        document = json.loads(run.text("keys.json"))
        self.assertEqual(document["results"][0]["excerpt"], "[REDACTED:private-key-block:1]")
        self.assertEqual(document["results"][1]["excerpt"], "[REDACTED:private-key-block:2]")  # no END line: to end of string
        self.assertEqual(document["results"][2]["excerpt"], SURVIVORS["PUBLIC_CERT"])
        self.assertEqual(run.text("escaped.txt"), 'log line with an escaped block: "[REDACTED:private-key-block:1]" and more text\n')

    def test_sarif_fields_are_redacted_structurally_and_output_is_still_valid_sarif_json(self):
        run = self.run_for("sarif-snippets")
        record = run.record("semgrep.sarif")
        self.assertEqual((record["disposition"], record["parser_mode"]), ("redacted", "sarif"))
        sarif = json.loads(run.text("semgrep.sarif"))
        sarif_run = sarif["runs"][0]
        result, invocation = sarif_run["results"][0], sarif_run["invocations"][0]
        marker = er.MARKER_RE.pattern
        self.assertRegex(result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"],
                         r'^String password = "' + marker + r'";\nString id = "' + marker + r'";$')
        self.assertRegex(result["message"]["text"], r"^Hardcoded login: password = '" + marker + r"' reaches the connection$")
        flow = result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
        self.assertRegex(flow["message"]["text"], "^tainted value " + marker + " flows to sink$")
        self.assertRegex(flow["physicalLocation"]["region"]["snippet"]["text"], r'token="' + marker + r'"\)$')
        self.assertRegex(result["fingerprints"]["matchBasedId/v1"], r"^\[REDACTED:fingerprint:\d+\]$")
        self.assertRegex(result["partialFingerprints"]["primaryLocationLineHash"], r"^\[REDACTED:fingerprint:\d+\]$")
        self.assertRegex(invocation["commandLine"], "^example-sast --config rules --api-token " + marker + " --db-password " + marker + " src$")
        self.assertRegex(invocation["arguments"][2], "^" + marker + "$")
        self.assertEqual([invocation["arguments"][index] for index in (0, 1, 3, 4)], ["example-sast", "--db-password", "--jobs", "4"])
        for value in invocation["environmentVariables"].values():
            self.assertRegex(value, "^" + marker + "$")
        # evidence that must stay legible
        self.assertEqual(result["ruleId"], "generic.secrets.hardcoded-password")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "src/main/java/com/example/v2/controllers/UserAccountController.java")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 41)
        self.assertEqual(record["redactions"]["fingerprint"], 2)

    def test_malformed_json_falls_back_to_text_passes_is_recorded_and_is_never_repaired(self):
        run = self.run_for("malformed")
        for path in ("broken.sarif", "duplicate-keys.json", "not-a-number.json"):
            with self.subTest(path=path):
                record = run.record(path)
                self.assertEqual((record["disposition"], record["parser_mode"]), ("redacted", "fallback-text"))
        with self.assertRaises(ValueError):
            json.loads(run.text("broken.sarif"))
        self.assertTrue(run.text("broken.sarif").startswith('{"version": "2.1.0", "runs": [{"results": [{"message": {"text": "password = \\"[REDACTED:'))
        self.assertEqual(run.text("duplicate-keys.json").count('"note"'), 2)  # duplicates kept, not collapsed
        self.assertIn('"ratio": NaN', run.text("not-a-number.json"))

    def test_valid_json_that_claims_sarif_is_recorded_as_json(self):
        record = self.run_for("malformed").record("claims.sarif")
        self.assertEqual((record["disposition"], record["parser_mode"]), ("redacted", "json"))

    def test_oversized_input_is_withheld_not_passed_through(self):
        run = self.run_for("gen-oversized")
        self.assertEqual(run.record("big.log")["withheld_reason"], "file-size-limit")
        self.assertFalse((run.published / "big.log").exists())
        self.assertEqual(run.record("ok.log")["disposition"], "redacted")
        refused = self.run_for("gen-oversized", "refuse").error
        self.assertIsInstance(refused, er.PublicationRefused)
        self.assertEqual(refused.reasons, [("big.log", "file-size-limit")])
        self.assertIn("publication refused under on_unhandled='refuse': 1 file(s) could not be proven handled: big.log (file-size-limit)", str(refused))

    def test_very_long_line_is_withheld_in_text_and_in_a_json_string(self):
        run = self.run_for("gen-long-line")
        self.assertEqual(run.record("long.log")["withheld_reason"], "line-length-limit")
        self.assertEqual(run.record("minified.json")["withheld_reason"], "line-length-limit")
        self.assertEqual(run.record("at-limit.log")["disposition"], "redacted")

    def test_deeply_nested_json_is_withheld_without_recursing(self):
        run = self.run_for("gen-deep-nesting")
        self.assertEqual(run.record("deep.json")["withheld_reason"], "json-depth-limit")
        self.assertEqual(run.record("abyss.json")["withheld_reason"], "json-depth-limit")
        self.assertEqual(run.record("at-limit.json")["disposition"], "redacted")

    def test_nul_bytes_and_non_utf8_are_withheld_never_copied(self):
        run = self.run_for("gen-binary")
        self.assertEqual({record["path"]: record["withheld_reason"] for record in run.receipt["files"]},
                         {"latin1.txt": "not-utf8", "nul.log": "binary-content", "utf16.log": "binary-content"})
        self.assertEqual(set(tree(run.published)), {er.RECEIPT_FILENAME})

    def test_crlf_and_lf_are_each_preserved_byte_for_byte_and_bom_is_kept(self):
        run = self.run_for("gen-newlines")
        self.assertEqual((run.published / "crlf.log").read_bytes(), b"first\r\napi_key=[REDACTED:named-secret:1]\r\nlast\r\n")
        self.assertEqual((run.published / "lf.log").read_bytes(), b"first\napi_key=[REDACTED:named-secret:1]\nlast\n")
        bom = (run.published / "bom.json").read_bytes()
        self.assertTrue(bom.startswith(b"\xef\xbb\xbf{"))
        self.assertNotIn(b"\r", bom)
        self.assertEqual(run.record("bom.json")["parser_mode"], "json")

    def test_secret_looking_filename_is_withheld_under_an_ordinal_placeholder_path(self):
        run = self.run_for("gen-secret-filename")
        self.assertEqual([(record["path"], record["withheld_reason"]) for record in run.receipt["files"]],
                         [("[WITHHELD-PATH:1]", "unsafe-path"), ("plain.log", None), ("[WITHHELD-PATH:2]", "unsafe-path")])
        self.assertEqual(set(tree(run.published)), {"plain.log", er.RECEIPT_FILENAME})
        refused = self.run_for("gen-secret-filename", "refuse").error
        self.assertEqual(refused.reasons, [("[WITHHELD-PATH:1]", "unsafe-path"), ("[WITHHELD-PATH:2]", "unsafe-path")])

    def test_unknown_type_and_reserved_receipt_name_are_withheld_and_empty_file_is_unchanged(self):
        run = self.run_for("gen-unsupported")
        self.assertEqual({record["path"]: record["withheld_reason"] for record in run.receipt["files"]},
                         {"blob.bin": "unsupported-type", "noextension": "unsupported-type",
                          er.RECEIPT_FILENAME: "reserved-name", "empty.log": None})
        self.assertEqual(run.record("empty.log")["disposition"], "unchanged")
        self.assertEqual(json.loads(run.text(er.RECEIPT_FILENAME)), run.receipt)  # ours, not the source's

    def test_total_bytes_limit_withholds_the_files_past_the_budget(self):
        run = self.run_for("gen-total-bytes")
        self.assertEqual([record["withheld_reason"] for record in run.receipt["files"]], [None, None, None, "total-bytes-limit"])

    @unittest.skipUnless(CAN_SYMLINK, "symlinks unavailable")
    def test_symlinks_are_withheld_and_never_followed(self):
        run = self.run_for("gen-links")
        self.assertEqual({record["path"]: record["withheld_reason"] for record in run.receipt["files"]},
                         {"link.log": "symlink", "linkdir": "symlink", "real.log": None})
        self.assertEqual(set(tree(run.published)), {"real.log", er.RECEIPT_FILENAME})

    def test_adversarial_split_escapes_base64_labels_secret_keys_and_preexisting_markers(self):
        run = self.run_for("adversarial")
        document = json.loads(run.text("split-escape.json"))
        self.assertRegex(document["excerpt"], "^id " + er.MARKER_RE.pattern + " here$")
        self.assertRegex(document["password"], "^" + er.MARKER_RE.pattern + "$")
        self.assertEqual(run.record("split-escape.log")["redactions"]["provider-token"], 2)  # text mode, via the escape view
        self.assertEqual(sum(run.record("base64-label.txt")["redactions"].values()), 3)
        lookup = json.loads(run.text("secret-as-key.json"))["lookup"]
        self.assertEqual(lookup["plain"], "owner-b")
        self.assertTrue(any(er.MARKER_RE.fullmatch(key) for key in lookup))
        markers = run.record("preexisting-markers.txt")
        self.assertEqual((markers["preexisting_markers"], markers["redactions"]["named-secret"]), (2, 1))
        self.assertIn("already [REDACTED:named-secret:7] here", run.text("preexisting-markers.txt"))
        self.assertIn("secret: [REDACTED:jwt:1]\n", run.text("preexisting-markers.txt"))

    def test_clean_evidence_is_published_byte_identical_with_a_source_hash(self):
        run = self.run_for("clean", "refuse")
        for record in run.receipt["files"]:
            self.assertEqual(record["disposition"], "unchanged")
            self.assertEqual(record["source_sha256"], hashlib.sha256((run.source / record["path"]).read_bytes()).hexdigest())
            self.assertEqual((run.published / record["path"]).read_bytes(), (run.source / record["path"]).read_bytes())

    def test_redacted_and_withheld_records_never_carry_a_source_hash(self):
        for key, run in self.published_runs():
            for record in run.receipt["files"]:
                if record["disposition"] != "unchanged":
                    with self.subTest(case=key, path=record["path"]):
                        self.assertIsNone(record["source_sha256"])

    def test_benign_evidence_survives_the_text_passes(self):
        for benign in (
            'username = "alice" path = "/usr/local/lib/python3.12/site-packages/foo" timeout = "30"',
            "appsec-review-process/tests/fixtures/evidence-redaction/Case01/semgrep2.sarif",
            "python-lang-security-audit-dangerous-subprocess-use-v2",
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "commit 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "run 123e4567-e89b-12d3-a456-426614174000",
            "token=null and secret: true",
            "rule generic.secrets.security.detected-password fired",
        ):
            with self.subTest(text=benign):
                tally = er._Tally()
                self.assertEqual(er._redact_text(benign, tally), benign)
                self.assertEqual(tally.total, 0)


class PolicyAndBoundaryTests(RedactionTestCase):
    def fresh(self, name="x") -> tuple[Path, Path]:
        base = Path(tempfile.mkdtemp(dir=self.base))
        (base / "source").mkdir()
        return base / "source", base / name

    def test_policy_and_limits_are_required_arguments(self):
        source, published = self.fresh()
        with self.assertRaises(TypeError):
            er.redact_tree(source, published)
        with self.assertRaises(TypeError):
            er.redact_tree(source, published, on_unhandled="withhold")
        with self.assertRaises(TypeError):
            er.redact_tree(source, published, limits=LIMITS)
        with self.assertRaises(TypeError):
            er.redact_tree(source, published, "withhold", LIMITS)  # keyword-only: no positional slip
        with self.assertRaises(TypeError):
            er.Limits(max_file_bytes=1, max_line_length=1, max_files=1, max_total_bytes=1, max_json_depth=1)
        self.assertFalse(published.exists())

    def test_verify_requires_published_dir_policy_and_limits(self):
        run = self.runs[("clean", "refuse")]
        with self.assertRaises(TypeError):
            er.verify_receipt(run.receipt)
        with self.assertRaises(TypeError):
            er.verify_receipt(run.receipt, run.published)
        with self.assertRaises(TypeError):
            er.verify_receipt(run.receipt, run.published, on_unhandled="refuse")
        with self.assertRaises(TypeError):
            er.verify_receipt(run.receipt, run.published, limits=LIMITS)

    def test_unknown_policy_and_non_limits_are_rejected_by_name(self):
        source, published = self.fresh()
        for policy in ("allow", "", None, "WITHHOLD", True):
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(er.RedactionError, "on_unhandled must be exactly 'refuse' or 'withhold'"):
                    er.redact_tree(source, published, on_unhandled=policy, limits=LIMITS)
        with self.assertRaisesRegex(er.RedactionError, "limits must be an evidence_redaction.Limits instance"):
            er.redact_tree(source, published, on_unhandled="refuse", limits={"max_files": 1})
        for bad in (0, -1, True, 1.5, "9"):
            with self.subTest(limit=bad):
                with self.assertRaisesRegex(er.RedactionError, "limit max_files must be a positive integer"):
                    er.Limits(**{**er.asdict(LIMITS), "max_files": bad})
        with self.assertRaisesRegex(er.RedactionError, "max_json_depth must not exceed 200"):
            er.Limits(**{**er.asdict(LIMITS), "max_json_depth": 201})

    def test_too_many_files_is_refused_under_both_policies(self):
        for policy in er.POLICIES:
            with self.subTest(policy=policy):
                source, published = self.fresh()
                for index in range(LIMITS.max_files + 1):
                    write(source, f"f{index:03}.log", "ok\n")
                with self.assertRaises(er.PublicationRefused) as caught:
                    er.redact_tree(source, published, on_unhandled=policy, limits=LIMITS)
                self.assertEqual(caught.exception.reasons, [(".", "file-count-limit")])
                self.assertIn("more entries than max_files", str(caught.exception))
                self.assertFalse(published.exists())

    def test_published_directory_must_be_absent_or_empty_and_disjoint_from_source(self):
        source, published = self.fresh()
        write(source, "a.log", "ok\n")
        write(published, "stale.log", "old\n")
        with self.assertRaisesRegex(er.RedactionError, "published directory must be absent or empty"):
            er.redact_tree(source, published, on_unhandled="refuse", limits=LIMITS)
        for target in (source, source / "out", source.parent):
            with self.subTest(target=target.name):
                with self.assertRaisesRegex(er.RedactionError, "must not contain one another"):
                    er.redact_tree(source, target, on_unhandled="refuse", limits=LIMITS)
        with self.assertRaisesRegex(er.RedactionError, "source directory does not exist or is not a directory"):
            er.redact_tree(source / "missing", published.parent / "y", on_unhandled="refuse", limits=LIMITS)

    @unittest.skipUnless(CAN_SYMLINK, "symlinks unavailable")
    def test_linked_source_or_published_root_is_refused(self):
        source, published = self.fresh()
        write(source, "a.log", "ok\n")
        os.symlink(source, source.parent / "source-link", target_is_directory=True)
        with self.assertRaisesRegex(er.RedactionError, "must not be or traverse a link"):
            er.redact_tree(source.parent / "source-link", published, on_unhandled="refuse", limits=LIMITS)
        (source.parent / "real-out").mkdir()
        os.symlink(source.parent / "real-out", source.parent / "out-link", target_is_directory=True)
        with self.assertRaisesRegex(er.RedactionError, "must not be or traverse a link"):
            er.redact_tree(source, source.parent / "out-link", on_unhandled="refuse", limits=LIMITS)

    def test_internal_failure_withholds_the_file_and_never_echoes_the_cause(self):
        source, published = self.fresh()
        write(source, "a.log", PW)
        original = er._redact_text

        def explode(text, tally):
            raise RuntimeError("cause quoting content: " + text)

        er._redact_text = explode
        try:
            with captured() as output:
                receipt = er.redact_tree(source, published, on_unhandled="withhold", limits=LIMITS)
                with self.assertRaises(er.PublicationRefused) as caught:
                    er.redact_tree(source, published.parent / "second", on_unhandled="refuse", limits=LIMITS)
        finally:
            er._redact_text = original
        self.assertEqual(receipt["files"][0]["withheld_reason"], "internal-error")
        self.assertIsNone(caught.exception.__cause__)
        assert_no_planted_values(self, "exception text", exception_text(caught.exception))
        assert_no_planted_values(self, "captured output", output())
        self.assertEqual(set(tree(published)), {er.RECEIPT_FILENAME})

    def test_output_that_is_not_a_fixed_point_is_withheld_as_unstable(self):
        source, published = self.fresh()
        write(source, "a.log", "y" * (LIMITS.max_line_length - 12) + "api_key=ab\n")  # marker pushes the line over the limit
        receipt = er.redact_tree(source, published, on_unhandled="withhold", limits=LIMITS)
        self.assertEqual(receipt["files"][0]["withheld_reason"], "unstable-output")

    def test_module_has_no_logging_no_third_party_and_no_runtime_publication_imports(self):
        module = ast.parse((ROOT / "evidence_redaction.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertEqual(imported - set(sys.stdlib_module_names), {"execution_state", "schema_validate"})
        self.assertEqual(imported & {"logging", "publish_job_output", "validate_job_output", "worker_result", "worker_adapters", "subprocess"}, set())
        prints = [node for node in ast.walk(module) if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print"]
        main = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        self.assertEqual({id(node) for node in prints} - {id(node) for node in ast.walk(main)}, set())

    def test_cli_redacts_verifies_and_never_prints_a_value(self):
        run = self.runs[("gen-mixed", "withhold")]
        target = Path(tempfile.mkdtemp(dir=self.base)) / "cli-out"
        with captured() as output:
            self.assertEqual(er.main(["redact", str(run.source), str(target), "--policy", "withhold"]), 0)
            self.assertEqual(er.main(["verify", str(target / er.RECEIPT_FILENAME), str(target), "--policy", "withhold"]), 0)
            self.assertEqual(er.main(["redact", str(run.source), str(target.parent / "refused"), "--policy", "refuse"]), 2)
            (target / "b-secrets.log").write_bytes(PW.encode())
            self.assertEqual(er.main(["verify", str(target / er.RECEIPT_FILENAME), str(target), "--policy", "withhold"]), 1)
            with self.assertRaises(SystemExit):
                er.main(["redact", str(run.source), str(target.parent / "nopolicy")])
        self.assertIn('"verified": true', output())
        self.assertIn("d-blob.bin (unsupported-type)", output())
        assert_no_planted_values(self, "CLI output", output())


class ReceiptTamperTests(RedactionTestCase):
    """Every receipt field is edited alone and the receipt is RE-SEALED (receipt_sha256 recomputed,
    on-disk copy rewritten), so what fails is the named cross-check, not merely the hash."""

    def setUp(self):
        self.good = self.runs[("gen-mixed", "withhold")]
        self.work = Path(tempfile.mkdtemp(dir=self.base)) / "published"
        shutil.copytree(self.good.published, self.work)

    def index(self, path):
        return next(index for index, record in enumerate(self.good.receipt["files"]) if record["path"] == path)

    def tamper(self, mutate, reseal=True, policy="withhold", limits=LIMITS) -> list[str]:
        receipt = deepcopy(self.good.receipt)
        mutate(receipt)
        if reseal:
            receipt = er._seal(receipt)
        (self.work / er.RECEIPT_FILENAME).write_bytes(er.receipt_bytes(receipt))
        return self.verify_errors(receipt, self.work, policy, limits)

    def mutations(self):
        clean, text, doc, held, named = (self.index(path) for path in ("a-clean.log", "b-secrets.log", "c-findings.json", "d-blob.bin", "[WITHHELD-PATH:1]"))

        def put(path, value):
            def mutate(receipt):
                node = receipt
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value(node[path[-1]]) if callable(value) else value
            return mutate

        def swap_kinds(receipt):
            counts = receipt["files"][text]["redactions"]
            counts["named-secret"] -= 1
            counts["jwt"] += 1
            receipt["totals"] = er._totals(receipt["files"])

        def bump_with_totals(path):
            def mutate(receipt):
                put(path, lambda value: value + 1)(receipt)
                receipt["totals"] = er._totals(receipt["files"])
            return mutate

        def reorder(receipt):
            receipt["files"][clean], receipt["files"][text] = receipt["files"][text], receipt["files"][clean]

        def drop_published_record(receipt):
            del receipt["files"][text]
            receipt["totals"] = er._totals(receipt["files"])

        rows = [
            ("schema_version", put(["schema_version"], "2.0"), "$.schema_version: violates redaction-receipt.schema.json (expected const)"),
            ("receipt_type", put(["receipt_type"], "other"), "$.receipt_type: violates redaction-receipt.schema.json (expected const)"),
            ("redactor.name", put(["redactor", "name"], "someone-else"), "$.redactor.name: violates redaction-receipt.schema.json (expected const)"),
            ("redactor.module_version", put(["redactor", "module_version"], "9.9.9"), "redactor identity must equal this module's name, module_version and ruleset_sha256"),
            ("redactor.ruleset_sha256", put(["redactor", "ruleset_sha256"], "a" * 64), "redactor identity must equal this module's name, module_version and ruleset_sha256"),
            ("policy.on_unhandled", put(["policy", "on_unhandled"], "refuse"), "policy.on_unhandled must equal the policy the verifier requires"),
            ("unredacted_file_in_published_set", put(["unredacted_file_in_published_set"], True), "$.unredacted_file_in_published_set: violates redaction-receipt.schema.json (expected const)"),
            ("receipt_sha256", put(["receipt_sha256"], "b" * 64), "receipt_sha256 does not match the canonical digest of every other field"),
            ("files[].path", put(["files", clean, "path"], "a-renamed.log"), "published directory holds a file the receipt does not list: a-clean.log"),
            ("files[].path", put(["files", clean, "path"], "a-renamed.log"), "published directory is missing a file the receipt lists: a-renamed.log"),
            ("files[].path", put(["files", clean, "path"], "../a-clean.log"), "files[%d]: path must be a normalized relative path that itself passes the redactor" % clean),
            ("files[].path", put(["files", clean, "path"], "token=" + "Zq9" * 9 + ".log"), "files[%d]: path must be a normalized relative path that itself passes the redactor" % clean),
            ("files[].path", put(["files", clean, "path"], "[WITHHELD-PATH:9]"), "files[%d]: only a withheld file may use a placeholder path" % clean),
            ("files[].path", put(["files", named, "path"], "[WITHHELD-PATH:2]"), "placeholder paths must be numbered 1..n in order"),
            ("files[].path", put(["files", held, "path"], "[WITHHELD-PATH:2]"), "files[%d]: a placeholder path is used exactly when withheld_reason is 'unsafe-path'" % held),
            ("files[].path", reorder, "files must list each real path once, in ascending order"),
            ("files[].path", drop_published_record, "published directory holds a file the receipt does not list: b-secrets.log"),
            ("files[].disposition", put(["files", text, "disposition"], "unchanged"), "files[%d]: an unchanged file must have zero redactions" % text),
            ("files[].disposition", put(["files", clean, "disposition"], "redacted"), "files[%d]: a redacted file must have at least one redaction" % clean),
            ("files[].disposition", put(["files", clean, "disposition"], "withheld"), "files[%d]: a withheld file must name its withheld_reason" % clean),
            ("files[].disposition", put(["files", held, "disposition"], "unchanged"), "files[%d]: a published file must have parser_mode, published_sha256 and published_bytes" % held),
            ("files[].disposition", put(["files", clean, "disposition"], "copied"), "$.files[%d].disposition: violates redaction-receipt.schema.json (not in enum)" % clean),
            ("files[].withheld_reason", put(["files", held, "withheld_reason"], None), "files[%d]: a withheld file must name its withheld_reason" % held),
            ("files[].withheld_reason", put(["files", clean, "withheld_reason"], "symlink"), "files[%d]: only a withheld file may carry a withheld_reason" % clean),
            ("files[].withheld_reason", put(["files", named, "withheld_reason"], "symlink"), "files[%d]: a placeholder path is used exactly when withheld_reason is 'unsafe-path'" % named),
            ("files[].withheld_reason", put(["files", held, "withheld_reason"], "because"), "$.files[%d].withheld_reason: violates redaction-receipt.schema.json (not in enum)" % held),
            ("files[].parser_mode", put(["files", text, "parser_mode"], "json"), "files[%d] (b-secrets.log): parser_mode does not match the mode re-derived from the published bytes" % text),
            ("files[].parser_mode", put(["files", doc, "parser_mode"], "sarif"), "files[%d] (c-findings.json): parser_mode does not match the mode re-derived from the published bytes" % doc),
            ("files[].parser_mode", put(["files", held, "parser_mode"], "text"), "files[%d]: a withheld file must have null parser_mode, source_sha256, published_sha256 and published_bytes" % held),
            ("files[].source_sha256", put(["files", clean, "source_sha256"], "c" * 64), "files[%d]: an unchanged file must have source_sha256 equal to published_sha256" % clean),
            ("files[].source_sha256", put(["files", clean, "source_sha256"], None), "files[%d]: an unchanged file must have source_sha256 equal to published_sha256" % clean),
            ("files[].source_sha256", put(["files", text, "source_sha256"], "c" * 64), "files[%d]: a redacted file must have null source_sha256" % text),
            ("files[].published_sha256", put(["files", text, "published_sha256"], "d" * 64), "files[%d] (b-secrets.log): published_sha256 does not match the published bytes" % text),
            ("files[].published_sha256", put(["files", held, "published_sha256"], "d" * 64), "files[%d]: a withheld file must have null parser_mode, source_sha256, published_sha256 and published_bytes" % held),
            ("files[].published_bytes", bump_with_totals(["files", text, "published_bytes"]), "files[%d] (b-secrets.log): published_bytes does not match the published file size" % text),
            ("files[].redactions", bump_with_totals(["files", text, "redactions", "named-secret"]), "files[%d] (b-secrets.log): markers in the published bytes must equal redactions plus preexisting_markers" % text),
            ("files[].redactions", swap_kinds, "files[%d] (b-secrets.log): per-kind redaction counts and ordinals 1..n must match the markers in the published bytes" % text),
            ("files[].redactions", bump_with_totals(["files", held, "redactions", "jwt"]), "files[%d]: a withheld file must have zero redactions and zero preexisting_markers" % held),
            ("files[].redactions", put(["files", text, "redactions", "jwt"], -1), "files[%d]: redaction and marker counts must be non-negative integers" % text),
            ("files[].preexisting_markers", bump_with_totals(["files", text, "preexisting_markers"]), "files[%d] (b-secrets.log): markers in the published bytes must equal redactions plus preexisting_markers" % text),
        ]
        rows += [(f"limits.{name}", put(["limits", name], lambda value: value + 1), "limits must equal the limits the verifier requires")
                 for name in er.asdict(LIMITS)]
        rows += [(f"totals.{name}", put(["totals", name], lambda value: value + 1), "totals must equal the sums of the per-file records")
                 for name in self.good.receipt["totals"] if name != "redactions"]
        rows += [("totals.redactions", put(["totals", "redactions", kind], lambda value: value + 1), "totals must equal the sums of the per-file records")
                 for kind in er.KINDS]
        return rows

    def test_every_single_field_edit_is_caught_by_its_named_cross_check_even_when_resealed(self):
        for field, mutate, expected in self.mutations():
            with self.subTest(field=field, expected=expected):
                errors = self.tamper(mutate, reseal=field != "receipt_sha256")
                self.assertTrue(any(expected in error for error in errors), errors)
                self.assertFalse(any("receipt_sha256 does not match" in error for error in errors if field != "receipt_sha256"), errors)
                self.assertFalse(any(er.RECEIPT_FILENAME + " equal to" in error for error in errors), errors)

    def test_mutation_table_covers_every_leaf_field_of_a_real_receipt(self):
        def leaves(node, prefix=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from leaves(value, f"{prefix}.{key}" if prefix else key)
            elif isinstance(node, list):
                for item in node:
                    yield from leaves(item, prefix + "[]")
            else:
                yield prefix
        collapse = lambda path: re.sub(r"^(files\[\]\.redactions|totals\.redactions)\..*$", r"\1", path)
        self.assertEqual({collapse(path) for path in leaves(self.good.receipt)}, {field for field, _, _ in self.mutations()})

    def test_unsealed_edit_is_caught_by_receipt_sha256(self):
        errors = self.tamper(lambda receipt: receipt["totals"].__setitem__("files_total", 99), reseal=False)
        self.assertIn("receipt_sha256 does not match the canonical digest of every other field", errors)

    def test_verifier_states_its_own_policy_and_limits(self):
        errors = self.verify_errors(self.good.receipt, self.good.published, policy="refuse")
        self.assertEqual(errors, ["policy.on_unhandled must equal the policy the verifier requires"])
        errors = self.verify_errors(self.good.receipt, self.good.published, limits=er.DEFAULT_LIMITS)
        self.assertEqual(errors, ["limits must equal the limits the verifier requires"])

    def test_refuse_policy_cannot_coexist_with_a_withheld_file(self):
        errors = self.tamper(lambda receipt: receipt["policy"].__setitem__("on_unhandled", "refuse"), policy="refuse")
        self.assertEqual(errors, ["policy.on_unhandled 'refuse' cannot coexist with a withheld file"])

    def test_more_records_than_max_files_is_rejected(self):
        tight = er.Limits(**{**er.asdict(LIMITS), "max_files": 2})
        errors = self.tamper(lambda receipt: receipt["limits"].__setitem__("max_files", 2), limits=tight)
        self.assertIn("files must not exceed limits.max_files", errors)

    def test_non_object_and_open_receipts_are_rejected_without_echoing_their_content(self):
        for receipt in (None, [], "receipt", {**self.good.receipt, "note": SECRETS["HUMAN_PASSWORD"]},
                        {**self.good.receipt, SECRETS["AWS_KEY"]: 1}, {key: value for key, value in self.good.receipt.items() if key != "totals"}):
            with self.subTest(kind=type(receipt).__name__):
                with self.assertRaises(er.ReceiptVerificationError) as caught:
                    self.verify(receipt, self.work)
                self.assertTrue(all("violates redaction-receipt.schema.json" in error for error in caught.exception.errors))
                assert_no_planted_values(self, "verification error", exception_text(caught.exception))

    # --- the published bytes, not the receipt, are edited -------------------------------------

    def published_tamper(self, change) -> list[str]:
        change(self.work)
        return self.verify_errors(self.good.receipt, self.work)

    def test_changed_published_byte_is_caught(self):
        errors = self.published_tamper(lambda root: (root / "a-clean.log").write_bytes(b"scan OK\n"))
        self.assertEqual(errors, ["files[%d] (a-clean.log): published_sha256 does not match the published bytes" % self.index("a-clean.log")])

    def test_extra_published_file_is_caught_and_a_secret_looking_name_is_not_echoed(self):
        def change(root):
            write(root, "extra.log", "ok\n")
            write(root, SECRETS["AWS_KEY"] + ".log", "ok\n")
        errors = self.published_tamper(change)
        self.assertEqual(sorted(errors), ["published directory holds a file the receipt does not list: [UNSAFE-PATH]",
                                          "published directory holds a file the receipt does not list: extra.log"])

    def test_withheld_file_smuggled_into_the_published_directory_is_caught(self):
        errors = self.published_tamper(lambda root: write(root, "d-blob.bin", "harmless\n"))
        self.assertEqual(errors, ["published directory holds a file the receipt does not list: d-blob.bin"])

    def test_missing_published_file_is_caught(self):
        errors = self.published_tamper(lambda root: (root / "c-findings.json").unlink())
        self.assertEqual(errors, ["published directory is missing a file the receipt lists: c-findings.json"])

    def test_missing_or_different_on_disk_receipt_is_caught(self):
        errors = self.published_tamper(lambda root: (root / er.RECEIPT_FILENAME).unlink())
        self.assertEqual(errors, [f"published directory must contain {er.RECEIPT_FILENAME} equal to the receipt being verified"])
        write(self.work, er.RECEIPT_FILENAME, "{}")
        self.assertEqual(self.verify_errors(self.good.receipt, self.work), errors)

    @unittest.skipUnless(CAN_SYMLINK, "symlinks unavailable")
    def test_published_file_replaced_by_a_link_is_caught(self):
        def change(root):
            (root / "a-clean.log").rename(root.parent / "moved.log")
            os.symlink(root.parent / "moved.log", root / "a-clean.log")
        errors = self.published_tamper(change)
        self.assertEqual(errors, ["files[%d] (a-clean.log): published entry must be a regular file, not a link or special file" % self.index("a-clean.log")])

    def test_unredacted_content_with_a_fully_consistent_forged_receipt_is_caught_by_re_running_the_redactor(self):
        planted = ("scan ok\n" + PW).encode()
        (self.work / "a-clean.log").write_bytes(planted)
        index = self.index("a-clean.log")

        def forge(receipt):
            sha = hashlib.sha256(planted).hexdigest()
            receipt["files"][index].update(source_sha256=sha, published_sha256=sha, published_bytes=len(planted))
            receipt["totals"] = er._totals(receipt["files"])
        errors = self.tamper(forge)
        self.assertEqual(errors, ["files[%d] (a-clean.log): published bytes are not a fixed point of this redactor under the receipt's limits "
                                  "(re-running it would redact or withhold the file)" % index])
        assert_no_planted_values(self, "verification errors", json.dumps(errors))

    def test_published_file_over_the_receipts_limits_is_caught(self):
        big = b"ok\n" * (LIMITS.max_file_bytes // 3 + 1)
        (self.work / "a-clean.log").write_bytes(big)
        errors = self.verify_errors(self.good.receipt, self.work)
        self.assertEqual(errors, ["files[%d] (a-clean.log): published file is not a readable regular file within max_file_bytes" % self.index("a-clean.log")])

    def test_published_directory_must_exist(self):
        errors = self.verify_errors(self.good.receipt, self.work.parent / "absent")
        self.assertEqual(errors, ["published directory must be a real, listable directory within max_files"])

    def test_honest_limit_withheld_claims_cannot_be_rederived_because_the_source_is_not_published(self):
        """Pinned on purpose: a resealed receipt may restate WHY a file was withheld, or drop the
        withheld record, and still verify. Verification proves the published bytes; it cannot prove
        what was left behind. docs/evidence-redaction.md must say so."""
        held = self.index("d-blob.bin")

        def restate(receipt):
            receipt["files"][held]["withheld_reason"] = "symlink"

        def drop(receipt):
            del receipt["files"][held]
            receipt["totals"] = er._totals(receipt["files"])
        for mutate in (restate, drop):
            receipt = er._seal((lambda value: (mutate(value), value)[1])(deepcopy(self.good.receipt)))
            (self.work / er.RECEIPT_FILENAME).write_bytes(er.receipt_bytes(receipt))
            self.verify(receipt, self.work)
        self.assertIn("cannot be re-derived", DOC_PATH.read_text(encoding="utf-8"))


class SchemaAndGoldenTests(RedactionTestCase):
    FORBIDDEN = {"value", "values", "secret", "secrets", "match", "matched", "matches", "snippet", "line", "line_text",
                 "text", "context", "excerpt", "original", "raw", "preview", "prefix", "suffix", "fragment", "sample",
                 "length", "value_length", "hash_of_value", "value_hash", "value_sha256", "entropy", "source_bytes",
                 "timestamp", "generated_at", "created_at"}
    SUBSET = {"$schema", "$id", "title", "description", "type", "required", "properties", "additionalProperties",
              "enum", "const", "pattern", "items", "minItems", "$ref"}

    def walk(self, node, path="$"):
        yield path, node
        for key, child in node.get("properties", {}).items():
            yield from self.walk(child, f"{path}.{key}")
        if isinstance(node.get("items"), dict):
            yield from self.walk(node["items"], path + "[]")

    def test_schema_offers_no_home_for_a_value_fragment_hash_length_line_or_timestamp(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        names = {key for _, node in self.walk(schema) for key in node.get("properties", {})}
        self.assertEqual(names & self.FORBIDDEN, set())
        self.assertGreater(len(names), 30)

    def test_schema_objects_are_closed_every_property_is_required_and_only_the_supported_subset_is_used(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        for path, node in self.walk(schema):
            with self.subTest(path=path):
                self.assertEqual(set(node) - self.SUBSET, set())
                if node.get("type") == "object":
                    self.assertIs(node["additionalProperties"], False)
                    self.assertEqual(sorted(node["required"]), sorted(node["properties"]))

    def test_schema_enums_match_the_module(self):
        schema = SchemaStore().load(er.RECEIPT_SCHEMA)
        record = schema["properties"]["files"]["items"]["properties"]
        self.assertEqual(record["withheld_reason"]["enum"], [*er.WITHHELD_REASONS, None])
        self.assertEqual(record["parser_mode"]["enum"], [*er.PARSER_MODES, None])
        self.assertEqual(list(record["redactions"]["properties"]), list(er.KINDS))
        self.assertEqual(list(schema["properties"]["limits"]["properties"]), list(er.asdict(LIMITS)))
        self.assertEqual(schema["properties"]["policy"]["properties"]["on_unhandled"]["enum"], list(er.POLICIES))

    def test_golden_is_a_produced_state_and_is_pinned(self):
        """The golden is what the redactor PRODUCES for the committed SARIF template; published bytes
        hold markers only, so the pin does not depend on the synthetic values. A ruleset change must
        move RULESET_SHA256 (and therefore this pin) on purpose."""
        run = self.runs[("sarif-snippets", "refuse")]
        self.assertEqual(er.RULESET_SHA256, GOLDEN["ruleset_sha256"])
        self.assertEqual(run.record("semgrep.sarif")["published_sha256"], GOLDEN["sarif_published_sha256"])
        self.assertEqual(run.record("semgrep.sarif")["redactions"], GOLDEN["sarif_redactions"])
        self.assertEqual(run.receipt["receipt_sha256"], GOLDEN["sarif_receipt_sha256"])
        self.verify(run.receipt, run.published, "refuse")

    def test_ruleset_digest_covers_the_rules_and_the_module_version(self):
        changed = deepcopy(er.RULESET)
        changed["entropy"]["segment_min_entropy"] = 9.0
        self.assertNotEqual(er.digest({"module_version": er.MODULE_VERSION, "ruleset": changed}), er.RULESET_SHA256)
        self.assertNotEqual(er.digest({"module_version": "9.9.9", "ruleset": er.RULESET}), er.RULESET_SHA256)

    def test_this_work_contains_no_scannable_secret_literal(self):
        scanners = [re.compile("AK" + r"IA[0-9A-Z]{16}"), re.compile("gh" + r"p_[A-Za-z0-9]{36}"),
                    re.compile("-----BEGIN " + r"(RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")]
        paths = [ROOT / "evidence_redaction.py", Path(__file__), DOC_PATH, SCHEMA_PATH, *[path for path in FIXTURES.rglob("*") if path.is_file()]]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for scanner in scanners:
                with self.subTest(path=path.name, scanner=scanner.pattern[:8]):
                    self.assertIsNone(scanner.search(text))
        for name, value in SECRETS.items():  # and the synthetic values really are scanner-shaped
            if name in ("AWS_KEY", "GITHUB_TOKEN", "PEM_RSA", "JWT"):
                self.assertTrue(any(scanner.search(value) for scanner in scanners), name)



class OwnDocumentsTests(unittest.TestCase):
    """The redactor sits on the publication path of this repository's OWN evidence documents
    (tool-results, coverage, probe receipts, wave manifests, ...). It must not rewrite their
    structure. V04 and V07 each found that it did: the key `source_snapshot_sha256` was classed as
    a high-entropy token, and about a third of real run ids were too. Nothing here may loosen
    detection of an actual secret, so every relaxation is paired with a must-still-flag case."""

    REPO = ROOT.parent

    @staticmethod
    def flagged(text: str) -> bool:
        return bool(list(er._entropy_spans(text)))

    def property_names(self):
        names = set()

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("properties"), dict):
                    names.update(node["properties"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        for path in sorted((self.REPO / "schemas").glob("*.schema.json")):
            walk(json.loads(path.read_text(encoding="utf-8")))
        return names

    def test_no_schema_property_name_in_the_repository_is_an_entropy_hit(self):
        names = self.property_names()
        self.assertGreater(len(names), 300)
        self.assertEqual(sorted(name for name in names if self.flagged(name)), [])

    def test_structural_hash_keys_are_identifiers_not_secrets(self):
        for key in ("source_snapshot_sha256", "intercom_records_sha256", "previous_wave_manifest_sha256",
                    "cell_result_sha256", "definition_sha256", "requirement_sha256", "content_sha256",
                    "manifest_sha256", "receipt_sha256", "published_sha256", "ruleset_sha256"):
            with self.subTest(key=key):
                self.assertFalse(self.flagged(key))

    def test_run_ids_in_the_repository_format_are_never_flagged(self):
        import random
        generator = random.Random(20260920)
        for _ in range(2000):
            run_id = (f"2026{generator.randint(1, 12):02d}{generator.randint(1, 28):02d}T{generator.randint(0, 23):02d}"
                      f"{generator.randint(0, 59):02d}{generator.randint(0, 59):02d}Z-{generator.getrandbits(24):06x}")
            self.assertFalse(self.flagged(run_id), run_id)
        self.assertFalse(self.flagged("20260919T123919Z-0b9e70"))

    def test_every_relaxation_still_flags_a_secret_that_merely_resembles_it(self):
        secret = stream("own-docs-secret", ALNUM, 40)
        hexish = stream("own-docs-hex", "0123456789abcdef", 24)
        cases = {
            "random only": secret,
            "technical token as a prefix": "sha256_" + secret[:32],
            "random around a technical token": secret[:14] + "_sha256_" + secret[14:28],
            "two plain words then a long random piece": "alpha_bravo_" + secret[:28],
            "a run id followed by a secret": "20260919T123919Z-0b9e70" + secret[:24],
            "run-id shape with a long hex tail": "20260919T123919Z-" + hexish,
        }
        for label, value in cases.items():
            with self.subTest(case=label):
                self.assertTrue(self.flagged(value), value)
        # not identifiers: technical tokens and counters alone, or an over-long counter
        self.assertFalse(er._wordy("sha256-md5-base64-sha512-x509"))
        self.assertFalse(er._wordy("alpha_bravo_1234567890123"))
        self.assertTrue(er._wordy("source_snapshot_sha256"))
        self.assertTrue(er._wordy("semgrep-security-audit-attempt-0001"))

    def test_own_evidence_documents_pass_through_unchanged(self):
        fixtures = ROOT / "tests" / "fixtures"
        # Evidence documents a producer publishes. Permission fixtures are run INPUTS whose
        # `credential_ref` is secret-named on purpose; they never pass through the redactor.
        evidence_dirs = ("tool-instance-shapes", "threat-workbench")
        documents = [path for path in sorted(fixtures.rglob("*.json"))
                     if any(name in path.parts for name in evidence_dirs) and path.name != "declared-tools.json"]
        self.assertGreaterEqual(len(documents), 12)
        with tempfile.TemporaryDirectory() as directory:
            source, published = Path(directory) / "source", Path(directory) / "published"
            for index, path in enumerate(documents):
                target = source / f"{index:03d}" / path.name
                target.parent.mkdir(parents=True)
                target.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
            limits = er.Limits(max_file_bytes=4_000_000, max_line_length=200_000, max_files=400,
                               max_total_bytes=40_000_000, max_json_depth=64, max_path_length=400)
            receipt = er.redact_tree(source, published, on_unhandled="refuse", limits=limits)
        changed = {record["path"]: {kind: count for kind, count in record["redactions"].items() if count}
                   for record in receipt["files"] if record["disposition"] != "unchanged"}
        self.assertEqual(changed, {}, "the redactor rewrote one of this repository's own evidence documents")

    def test_the_relaxation_lives_in_the_ruleset_and_moved_the_version(self):
        for key in ("wordy_technical_pieces", "wordy_min_plain_words", "wordy_counter_max_length", "exempt_patterns"):
            changed = deepcopy(er.RULESET)
            changed["entropy"].pop(key)
            self.assertNotEqual(er.digest({"module_version": er.MODULE_VERSION, "ruleset": changed}), er.RULESET_SHA256, key)
        self.assertEqual(er.MODULE_VERSION, "1.1.0")


class CheckoutIndependenceTests(unittest.TestCase):
    """PR 10 review: the suite must pass on a standard Windows checkout, where Git converts the
    tracked templates to CRLF, without weakening the explicit byte-preservation checks."""

    def templates(self):
        return [path for path in sorted(FIXTURES.rglob("*")) if path.is_file() and path.name != "README.md"]

    def test_a_crlf_checkout_of_every_template_loads_to_the_same_input(self):
        self.assertGreaterEqual(len(self.templates()), 15)
        for path in self.templates():
            with self.subTest(template=path.relative_to(FIXTURES).as_posix()):
                as_lf = path.read_bytes().replace(b"\r\n", b"\n")
                as_crlf = as_lf.replace(b"\n", b"\r\n")
                self.assertNotIn(b"\r", as_lf, "a tracked template must not carry a bare CR of its own")
                self.assertEqual(load_template(as_crlf), load_template(as_lf))
                self.assertNotIn("\r", load_template(as_crlf))

    def test_a_crlf_checkout_produces_the_same_published_bytes_and_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            receipts = {}
            for label, convert in (("lf", lambda data: data), ("crlf", lambda data: data.replace(b"\n", b"\r\n"))):
                source, published = base / label / "source", base / label / "published"
                for path in self.templates():
                    target = source / path.relative_to(FIXTURES)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    checked_out = convert(path.read_bytes().replace(b"\r\n", b"\n"))
                    target.write_bytes(materialize(load_template(checked_out)).encode("utf-8"))
                receipts[label] = er.redact_tree(source, published, on_unhandled="withhold", limits=LIMITS)
            self.assertEqual(receipts["crlf"], receipts["lf"])
            self.assertEqual(tree(base / "crlf" / "published"), tree(base / "lf" / "published"))

    def test_byte_preservation_is_still_proven_with_generated_not_tracked_inputs(self):
        # The guarantee the reviewer asked to keep: CRLF and LF inputs are each preserved exactly.
        with tempfile.TemporaryDirectory() as directory:
            source, published = Path(directory) / "s", Path(directory) / "p"
            write(source, "crlf.log", b"first\r\napi_key=" + PLANTS["HUMAN_PASSWORD"].encode() + b"\r\nlast\r\n")
            write(source, "lf.log", b"first\napi_key=" + PLANTS["HUMAN_PASSWORD"].encode() + b"\nlast\n")
            er.redact_tree(source, published, on_unhandled="refuse", limits=LIMITS)
            self.assertEqual((published / "crlf.log").read_bytes(), b"first\r\napi_key=[REDACTED:named-secret:1]\r\nlast\r\n")
            self.assertEqual((published / "lf.log").read_bytes(), b"first\napi_key=[REDACTED:named-secret:1]\nlast\n")

    def test_templates_are_pinned_to_lf_in_gitattributes(self):
        import subprocess
        sample = self.templates()[0]
        try:
            result = subprocess.run(["git", "check-attr", "eol", "text", "--", str(sample)], cwd=str(ROOT.parent),
                                    capture_output=True, text=True, timeout=30, check=True)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git is not available or this is not a work tree")
        self.assertIn("eol: lf", result.stdout)
        self.assertIn("text: set", result.stdout)


class VerificationProbeTests(unittest.TestCase):
    """Cases added while independently verifying V06: shapes redactors commonly miss. Every planted
    value is built at run time; none is a literal in this file."""

    HUMAN = "Tr0ub4dor" + "-" + "EXAMPLE"                      # low entropy: only a name can catch it
    TOKEN = "gh" + "p_" + stream("probe-token", ALNUM, 36)
    SIGNATURE = stream("probe-sig", ALNUM, 43)
    KEY_LINES = [stream(f"probe-key-{i}", BASE64, 64) for i in range(4)]

    @classmethod
    def key_block(cls, label, newline="\n"):
        return ("-----BEGIN " + label + "-----" + newline + newline.join(cls.KEY_LINES) + newline
                + "-----END " + label + "-----" + newline)

    def cases(self):
        human, token = self.HUMAN, self.TOKEN
        basic = base64.b64encode(f"user:{human}".encode()).decode()
        return {
            "token-used-as-a-json-key.json": (json.dumps({token: True, "note": "a token as an object key"}), [token]),
            "camel-upper-and-hyphen-names.json": (json.dumps({"clientSecret": human, "DB_PASSWORD": human + "1", "Api-Key": human + "2",
                                                              "passphrase": human + "3", "pwd": human + "4"}), [human]),
            # Dockerfile legacy form: directive, secret-ish NAME, whitespace, value, no operator.
            "dockerfile-env-space-form.txt": (f"FROM scratch\nENV API_KEY {human}\nENV DB_PASSWORD={human}5\nARG NPM_TOKEN {token}\n"
                                              f"  export SIGNING_KEY {human}6\n", [human, token]),
            "dotenv.txt": (f"DB_PASS={human}\nexport SECRET_KEY='{human}7'\n", [human]),
            "connection-strings.txt": (f"postgres://app:{human}@db.internal:5432/x\nServer=db;User Id=sa;Password={human}8;\n", [human]),
            "basic-auth-header.txt": (f"Authorization: Basic {basic}\n", [basic]),
            "pgp-private-key-block.txt": (self.key_block("PGP PRIVATE KEY BLOCK"), self.KEY_LINES),
            "encrypted-private-key.txt": (self.key_block("ENCRYPTED PRIVATE KEY"), self.KEY_LINES),
            "crlf-private-key.txt": (self.key_block("RSA PRIVATE KEY", "\r\n"), self.KEY_LINES),
            "plain-yaml.yaml": (f"db:\n  user: app\n  password: {human}\n  token: \"{token}\"\n", [human, token]),
            "xml-attribute-and-element.xml": (f'<conn user="app" password="{human}" />\n<apiKey>{token}</apiKey>\n', [human, token]),
            "url-query.txt": (f"GET https://api.example.test/v1?user=a&access_token={token}&sig={self.SIGNATURE}\n", [token, self.SIGNATURE]),
            # Positional credentials: no secret-ish name exists to anchor on.
            "mysql-short-password-flag.txt": (f"mysql -u root -p{human} appdb\nmysqldump --host db -p{human}9 appdb > dump.sql\n", [human]),
            "sshpass.txt": (f"sshpass -p {human} ssh deploy@host\nsshpass -p{human}a scp f host:\n", [human]),
            "curl-user-password.txt": (f"curl -sS -u deploy:{human} https://repo.example.test/x\nwget --user=ci:{human}b https://x.example.test\n", [human]),
        }

    def redact(self, files, policy="withhold"):
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source, published = base / "src", base / "dst"
        (source / "nested").mkdir(parents=True)
        for name, text in files.items():
            (source / "nested" / name).write_bytes(text.encode("utf-8"))
        out, err, log = io.StringIO(), io.StringIO(), io.StringIO()
        handler = logging.StreamHandler(log)
        logging.getLogger().addHandler(handler)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                receipt = er.redact_tree(source, published, on_unhandled=policy, limits=LIMITS)
        finally:
            logging.getLogger().removeHandler(handler)
        return receipt, published, out.getvalue() + err.getvalue() + log.getvalue()

    def test_no_planted_value_survives_in_any_probe_case(self):
        cases = self.cases()
        receipt, published, noise = self.redact({name: text for name, (text, _) in cases.items()})
        records = {record["path"].rsplit("/", 1)[-1]: record for record in receipt["files"]}
        sealed = json.dumps(receipt)
        for name, (_, planted) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(records[name]["disposition"], "redacted")
                text = (published / "nested" / name).read_text(encoding="utf-8")
                for value in planted:
                    self.assertNotIn(value, text, "published file")
                    self.assertNotIn(value, sealed, "receipt")
                    self.assertNotIn(value, noise, "stdout, stderr or logging")
        er.verify_receipt(receipt, published, on_unhandled="withhold", limits=LIMITS)

    def test_directive_rule_does_not_fire_without_a_secretish_name_or_with_an_operator(self):
        text = "ENV APP_MODE production\nENV LOG_LEVEL debug\nARG BASE_IMAGE alpine\n"
        receipt, published, _ = self.redact({"benign.txt": text})
        self.assertEqual(receipt["files"][0]["disposition"], "unchanged")
        self.assertEqual((published / "nested" / "benign.txt").read_text(encoding="utf-8"), text)

    def test_mysql_rule_leaves_port_and_other_flags_alone(self):
        text = "mysql -u root -P 3306 --protocol tcp appdb\nmysqldump --no-data -h db appdb\n"
        receipt, _, _ = self.redact({"benign.txt": text})
        self.assertEqual(receipt["files"][0]["disposition"], "unchanged")

    def test_new_bounded_patterns_stay_linear_on_hostile_lines(self):
        import time
        width = LIMITS.max_line_length - 8
        hostile = {
            "mysql-repeated.txt": ("mysql " * (width // 6))[:width] + "\n",
            "curl-repeated.txt": ("curl -u " * (width // 8))[:width] + "\n",
            "env-repeated.txt": "\n".join(["ENV " + "A" * 60 + "_TOKEN"] * 400) + "\n",
            "sshpass-repeated.txt": ("sshpass -p " * (width // 11))[:width] + "\n",
        }
        started = time.monotonic()
        self.redact(hostile)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_new_rules_are_part_of_the_ruleset_digest(self):
        for key in ("directive_prefix", "directive_tail", "cli_credentials"):
            changed = deepcopy(er.RULESET)
            changed.pop(key)
            self.assertNotEqual(er.digest({"module_version": er.MODULE_VERSION, "ruleset": changed}), er.RULESET_SHA256, key)


# Produced by running the redactor over fixtures/evidence-redaction/sarif-snippets, then pinned.
GOLDEN = {
    "ruleset_sha256": "4f180f5abeb92829a7ff02d4d9eb560f86dc72fe5897bcc9748b5a783d4fa651",
    "sarif_published_sha256": "bbf1eac71274b50cd3e39a71ff1d0979803ab1ad4d60329a153be848a253e93b",
    "sarif_redactions": {"private-key-block": 0, "named-secret": 8, "url-credential": 0, "bearer-token": 0,
                         "provider-token": 1, "jwt": 0, "high-entropy": 1, "fingerprint": 2},
    "sarif_receipt_sha256": "9563aca5f463b7f6b83693744ca7da055838f1f1f9495c83fd5aa09282b198e1",
}


if __name__ == "__main__":
    unittest.main()
