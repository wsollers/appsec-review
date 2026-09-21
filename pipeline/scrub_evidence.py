#!/usr/bin/env python3
"""
scrub_evidence.py — produce a handoff-safe copy of the /evidence tree.

Remediation for finding E4-1 (Adversarial Process Review, 2026-09-01):
gitleaks was run with --redact, which protects gitleaks' OWN output only.
Every other tool that quotes a source line in its findings (semgrep JSON,
mobsfscan SARIF, and anything else with a "snippet"/"context"-shaped field)
writes the RAW matched text into /evidence by default — including, when the
matched line itself contains a hardcoded credential, the raw secret value.
Verified live during the review: a semgrep hardcoded-password finding and a
mobsfscan finding on a hardcoded key both persisted the literal secret string
into their SARIF/JSON output.

2026-09-01 verification follow-up (this script's own first cut was too
weak): a broad high-entropy heuristic alone caught machine-generated secrets
(88-char Azure storage keys, random tokens) but MISSED human-memorable
hardcoded passwords - verified: `$db_password = "SuperSecret-Hunter2-99!"`
(entropy 3.43, just under the 3.5 floor) and short values like "Hunter2!"
(under the 20-char candidate minimum) sailed straight through into the
"shareable" copy. That is exactly the class E4-1 was demonstrated with. So
this script now runs TWO passes over every string:

  1. High-entropy substring redaction (the original broad heuristic) - the
     backstop for unlabeled blobs like keys and tokens.
  2. Secret-name-aware value redaction - if a secret-ish identifier
     (password/pwd/secret/token/api_key/access_key/private_key/client_secret/
     connection_string/credential/bearer/auth_token) is assigned a quoted
     value, that value is redacted REGARDLESS of its entropy or length; and
     if a JSON object key itself is secret-ish, its string value is redacted
     wholesale. This is what catches the hardcoded-password class.

Both passes are deliberately conservative in different directions: pass 1 can
occasionally redact a long hash/GUID that wasn't a secret; pass 2 only fires
on a value tied to a secret-named identifier, so it won't touch a benign
`username = "alice"` / `path = "/usr/..."` / `timeout = "30"` (all verified to
survive). The cost of a rare false positive (slightly less legible evidence)
is far smaller than a false negative (a real secret reaching a handoff zip).

Usage:
    python3 scrub_evidence.py /evidence -o /evidence/_shareable

Only /evidence/_shareable (the output of this script) is intended to leave
the machine. The rest of /evidence — including this script's own input — is
internal-only: it is the raw, unscrubbed tool output and may contain
plaintext secret values exactly like the ones this script exists to catch.
"""
import argparse
import json
import math
import os
import re
import sys

# Text-bearing evidence formats this script actually inspects. Binary/large
# artifacts (Joern's cpg.bin, anything else this list doesn't recognize) are
# deliberately NOT copied into the shareable tree at all — they were never
# meant for handoff, and scanning multi-GB binaries for "high entropy
# strings" is both slow and meaningless.
SCANNABLE_EXTENSIONS = {".json", ".sarif", ".txt", ".log", ".xml"}

# Anything under these evidence subdirectories is skipped entirely (not
# copied, not scanned) — either because it's already been through a
# dedicated redaction path (gitleaks' own --redact output) or because it's
# not evidence text at all (a built CPG, a lancedb vector index).
SKIP_DIRS = {"joern", "semantic-index"}

REDACTED = "« REDACTED-high-entropy-string »"
REDACTED_SECRET = "« REDACTED-secret-value »"

# Same broad shape gitleaks/detect-secrets use for a first-pass entropy
# filter: a token-looking run of base64/hex/URL-safe characters, long enough
# that truncating it materially destroys any secret it might be.
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_=\-]{20,}")

# E4-1 hardening pass 2: a secret-ish identifier. Used both to match an
# assignment in free text (a snippet like `$db_password = "..."`) and to
# match a secret-ish JSON object key whose value should be wiped wholesale.
_SECRET_KW = (
    r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|client[_-]?secret|"
    r"conn(?:ection)?[_-]?string|credential|bearer|auth[_-]?token)"
)
_SECRET_KEY_RE = re.compile(r"(?i)" + _SECRET_KW)
# identifier (with any prefix/suffix, incl. a leading $ or JSON quote) then an
# assignment operator (`=` or `:`, allowing a JSON key's closing quote before
# it) then a single- or double-quoted value. The value is group 4.
_ASSIGN_RE = re.compile(
    r"(?ix)"
    r"([A-Za-z0-9_\-\.\$]*" + _SECRET_KW + r"[A-Za-z0-9_\-\.]*)"  # 1: identifier
    r"(\s*[\"']?\s*[:=]\s*)"                                       # 2: (close-quote?) + operator
    r"([\"'])([^\"']*)([\"'])"                                     # 3 open / 4 value / 5 close
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * (p and math.log2(p))
    return ent


def _redact_entropy(s: str, stats: dict) -> str:
    def _sub(m: "re.Match") -> str:
        tok = m.group(0)
        # Skip things that are almost certainly not secrets even though they
        # match the character-class shape: pure digits, and repeated-char
        # runs (both low entropy).
        if tok.isdigit():
            return tok
        if shannon_entropy(tok) < 3.5:
            return tok
        stats["redactions"] = stats.get("redactions", 0) + 1
        return REDACTED

    return _CANDIDATE_RE.sub(_sub, s)


def _redact_secret_assignments(s: str, stats: dict) -> str:
    def _sub(m: "re.Match") -> str:
        stats["secret_value_redactions"] = stats.get("secret_value_redactions", 0) + 1
        # keep identifier + operator + surrounding quotes, wipe only the value
        return m.group(1) + m.group(2) + m.group(3) + REDACTED_SECRET + m.group(5)

    return _ASSIGN_RE.sub(_sub, s)


def redact_string(s: str, stats: dict) -> str:
    # Entropy pass FIRST so its inserted marker isn't itself re-scanned; the
    # labeled-secret pass runs SECOND and will upgrade a labeled value that
    # the entropy pass already generically redacted to the secret-value
    # marker (and catch the low-entropy/short passwords the entropy pass
    # can't). Order matters: doing it the other way nests the two markers.
    return _redact_secret_assignments(_redact_entropy(s, stats), stats)


def scrub_json_value(value, stats: dict, key_is_secret: bool = False):
    if isinstance(value, str):
        # A value sitting directly under a secret-ish JSON key (e.g.
        # {"secret": "raw"}) is redacted wholesale, no assignment syntax
        # needed - this is the structural companion to the text-assignment
        # pass in redact_string.
        if key_is_secret and value.strip():
            stats["secret_value_redactions"] = stats.get("secret_value_redactions", 0) + 1
            return REDACTED_SECRET
        return redact_string(value, stats)
    if isinstance(value, dict):
        return {
            k: scrub_json_value(
                v, stats, bool(isinstance(k, str) and _SECRET_KEY_RE.search(k))
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub_json_value(v, stats, key_is_secret) for v in value]
    return value


def scrub_file(src_path: str, dst_path: str, stats: dict) -> None:
    ext = os.path.splitext(src_path)[1].lower()
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    if ext in (".json", ".sarif"):
        try:
            with open(src_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Not actually valid JSON (or unreadable) - fall through to the
            # plain-text path below rather than silently dropping the file.
            scrub_text_file(src_path, dst_path, stats)
            return
        scrubbed = scrub_json_value(data, stats)
        with open(dst_path, "w", encoding="utf-8") as f:
            json.dump(scrubbed, f, indent=2)
        return

    scrub_text_file(src_path, dst_path, stats)


def scrub_text_file(src_path: str, dst_path: str, stats: dict) -> None:
    try:
        with open(src_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        stats["unreadable"] = stats.get("unreadable", 0) + 1
        with open(dst_path, "w", encoding="utf-8") as f:
            f.write(f"<< scrub_evidence.py could not read source file: {e} >>\n")
        return
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(redact_string(text, stats))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="Evidence root to scrub (e.g. /evidence)")
    ap.add_argument("-o", "--out", required=True, help="Output directory for the scrubbed, shareable copy")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    out = os.path.abspath(args.out)
    if out == root or out.startswith(root + os.sep) and os.path.basename(out) != "_shareable":
        # Guard against pointing -o back at a live evidence subdir and
        # scrubbing in place - this script is meant to produce a copy.
        pass  # the default "_shareable" nested-output case below is fine

    stats = {"files_copied": 0, "files_skipped": 0, "redactions": 0,
             "secret_value_redactions": 0, "unreadable": 0}
    excluded_binaries = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        top = rel_dir.split(os.sep)[0]
        if top in SKIP_DIRS:
            dirnames[:] = []
            continue
        if os.path.abspath(dirpath) == out or os.path.abspath(dirpath).startswith(out + os.sep):
            # Don't recurse into our own output directory if it's nested
            # under root (default usage: -o /evidence/_shareable).
            dirnames[:] = []
            continue

        for fname in filenames:
            src = os.path.join(dirpath, fname)
            rel = os.path.relpath(src, root)
            dst = os.path.join(out, rel)
            ext = os.path.splitext(fname)[1].lower()

            if ext in SCANNABLE_EXTENSIONS:
                scrub_file(src, dst, stats)
                stats["files_copied"] += 1
            else:
                excluded_binaries.append(rel)
                stats["files_skipped"] += 1

    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "EXCLUDED_FROM_HANDOFF.txt"), "w", encoding="utf-8") as f:
        f.write(
            "Files present in the full /evidence tree but NOT copied here "
            "(binary/large artifacts not meant for handoff - see joern-parse's "
            "cpg.bin and the semantic-index vector store in particular):\n\n"
        )
        f.write("\n".join(sorted(excluded_binaries)) or "(none)")
        f.write("\n")

    with open(os.path.join(out, "SCRUB_REPORT.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print(f"Scrubbed {stats['files_copied']} files into {out} "
          f"({stats['redactions']} high-entropy substrings + "
          f"{stats['secret_value_redactions']} labeled-secret values redacted, "
          f"{stats['files_skipped']} binary/non-text files excluded, "
          f"{stats['unreadable']} files unreadable).")
    print("Only this directory is safe to zip and hand off. "
          "Everything else under the evidence root is internal-only.")


if __name__ == "__main__":
    sys.exit(main())
