"""Focused T-174 unit tests for 9-language in-memory patch application, balanced syntax, and guard/sink hardening."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.jobs.job_poc_generation import detect_poc_language
from appsec_review.jobs.job_remediation_validation import (
    STATIC_PATCH_VALIDATION_SCHEMA,
    SUPPORTED_REMEDIATION_LANGUAGES,
    UnifiedDiffApplyError,
    apply_unified_diff_in_memory,
    validate_file_remediation_in_memory,
    validate_remediation_patch_set,
)

ROOT = Path(__file__).resolve().parents[3]


def _validation_schema_validator() -> Draft202012Validator:
    schema_dir = ROOT / "docs" / "schemas" / "remediation-validation"
    docs = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(schema_dir.glob("*.schema.json"))}
    registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in docs.values())
    return Draft202012Validator(docs["static-patch-validation.schema.json"], registry=registry)


NINE_LANGUAGE_PATCHES: dict[str, tuple[str, str, str]] = {
    "cpp": (
        "src/frame.cpp",
        "int helper() { return 1; }\nint copy_buf(char *dst, const char *src, size_t n) {\n    strcpy(dst, src);\n    return 0;\n}\n",
        "int helper() { return 1; }\nint copy_buf(char *dst, const char *src, size_t n) {\n    if (src == nullptr || strlen(src) >= n) { return -1; }\n    snprintf(dst, n, \"%s\", src);\n    return 0;\n}\n",
    ),
    "java": (
        "src/UserDao.java",
        "class UserDao {\n    int helper() { return 1; }\n    void findUser(Connection c, String id) throws Exception {\n        c.createStatement().execute(\"SELECT * FROM u WHERE id=\" + id);\n    }\n}\n",
        "class UserDao {\n    int helper() { return 1; }\n    void findUser(Connection c, String id) throws Exception {\n        PreparedStatement ps = c.prepareStatement(\"SELECT * FROM u WHERE id = ?\");\n        ps.setString(1, id);\n        ps.executeQuery();\n    }\n}\n",
    ),
    "javascript": (
        "src/render.js",
        "function helper() { return true; }\nfunction renderBio(el, bio) {\n    el.innerHTML = bio;\n}\n",
        "function helper() { return true; }\nfunction renderBio(el, bio) {\n    if (typeof bio !== \"string\") { throw new Error(\"invalid\"); }\n    el.textContent = bio;\n}\n",
    ),
    "python": (
        "app/db.py",
        "def helper():\n    return 1\n\ndef fetch_user(cur, uid):\n    cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n    return cur.fetchone()\n",
        "def helper():\n    return 1\n\ndef fetch_user(cur, uid):\n    if not isinstance(uid, int):\n        raise ValueError(\"invalid uid\")\n    cur.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))\n    return cur.fetchone()\n",
    ),
    "ruby": (
        "app/loader.rb",
        "def helper\n  true\nend\n\ndef load_cfg(raw)\n  YAML.load(raw)\nend\n",
        "def helper\n  true\nend\n\ndef load_cfg(raw)\n  raise ArgumentError, \"empty\" if raw.nil?\n  YAML.safe_load(raw, permitted_classes: [])\nend\n",
    ),
    "go": (
        "internal/file/read.go",
        "package file\n\nfunc helper() int { return 1 }\n\nfunc ReadDoc(base string, name string) ([]byte, error) {\n    return os.ReadFile(base + \"/\" + name)\n}\n",
        "package file\n\nfunc helper() int { return 1 }\n\nfunc ReadDoc(base string, name string) ([]byte, error) {\n    clean := filepath.Clean(name)\n    if strings.Contains(clean, \"..\") {\n        return nil, fmt.Errorf(\"invalid path\")\n    }\n    return os.ReadFile(filepath.Join(base, clean))\n}\n",
    ),
    "csharp": (
        "Services/QueryService.cs",
        "public class QueryService {\n    public int Helper() { return 1; }\n    public void Run(SqlCommand cmd, string user) {\n        cmd.CommandText = \"SELECT * FROM Users WHERE Name = '\" + user + \"'\";\n    }\n}\n",
        "public class QueryService {\n    public int Helper() { return 1; }\n    public void Run(SqlCommand cmd, string user) {\n        ArgumentNullException.ThrowIfNull(user);\n        cmd.CommandText = \"SELECT * FROM Users WHERE Name = @user\";\n        cmd.Parameters.AddWithValue(\"@user\", user);\n    }\n}\n",
    ),
    "rust": (
        "src/parser.rs",
        "pub fn helper() -> usize { 1 }\npub fn read_idx(buf: &[u8], idx: usize) -> u8 {\n    unsafe { *buf.get_unchecked(idx) }\n}\n",
        "pub fn helper() -> usize { 1 }\npub fn read_idx(buf: &[u8], idx: usize) -> Result<u8, &'static str> {\n    buf.get(idx).copied().ok_or(\"out of bounds\")\n}\n",
    ),
    "php": (
        "src/AuthRepository.php",
        "<?php\nfunction helper(): int { return 1; }\nfunction findByEmail(PDO $pdo, string $email): array {\n    return $pdo->query(\"SELECT * FROM users WHERE email = '$email'\")->fetchAll();\n}\n",
        "<?php\nfunction helper(): int { return 1; }\nfunction findByEmail(PDO $pdo, string $email): array {\n    $stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = :email\");\n    $stmt->execute([\"email\" => $email]);\n    return $stmt->fetchAll();\n}\n",
    ),
}


@pytest.mark.parametrize("language", sorted(NINE_LANGUAGE_PATCHES))
def test_nine_language_in_memory_remediation_validation_passes_hardened_patches(language: str) -> None:
    assert set(SUPPORTED_REMEDIATION_LANGUAGES) == set(NINE_LANGUAGE_PATCHES)
    rel_path, before_text, after_text = NINE_LANGUAGE_PATCHES[language]
    assert detect_poc_language(rel_path) == language

    res = validate_file_remediation_in_memory(
        path=rel_path,
        before_text=before_text,
        after_text=after_text,
    )
    assert res.hunks_applied is True, (language, res.issues)
    assert res.syntax_valid is True, (language, res.issues)
    assert res.functions_preserved is True, (language, res.issues)
    assert res.guard_or_sink_hardened is True, (language, res.issues)
    assert res.issues == ()


def test_unified_diff_in_memory_application_and_batch_schema_validation() -> None:
    before = "def keep_me():\n    return 42\n\ndef run_cmd(user_arg):\n    return subprocess.run(user_arg, shell=True)\n"
    diff = (
        "--- a/app/runner.py\n"
        "+++ b/app/runner.py\n"
        "@@ -2,4 +2,6 @@\n"
        "     return 42\n"
        " \n"
        " def run_cmd(user_arg):\n"
        "-    return subprocess.run(user_arg, shell=True)\n"
        "+    if not isinstance(user_arg, str) or not user_arg.isalnum():\n"
        "+        raise ValueError(\"invalid arg\")\n"
        "+    return subprocess.run([\"/usr/bin/echo\", user_arg], shell=False, check=True)\n"
    )
    patched = apply_unified_diff_in_memory(before, diff)
    assert "shell=False" in patched

    batch = validate_remediation_patch_set(
        [
            {"path": "app/runner.py", "before_text": before, "unified_diff": diff},
            {
                "path": "src/frame.cpp",
                "before_text": NINE_LANGUAGE_PATCHES["cpp"][1],
                "after_text": NINE_LANGUAGE_PATCHES["cpp"][2],
            },
        ]
    )
    assert batch.ok is True
    assert batch.patch_applies_cleanly is True
    assert batch.ast_parse_clean is True
    assert batch.signature_preserved is True
    assert batch.dominating_guard_verified is True
    assert batch.validation_tier == "in_memory_patch_and_syntax_verified"
    record = batch.record()
    assert record["schema"] == STATIC_PATCH_VALIDATION_SCHEMA
    _validation_schema_validator().validate(record)


def test_static_remediation_validator_rejects_deleted_unrelated_function_and_bad_diff() -> None:
    before = "function keepHelper() {\n    return 1;\n}\nfunction sink(x) {\n    eval(x);\n}\n"
    deleted_unrelated = "function sink(x) {\n    if (typeof x !== 'string') throw new Error('bad');\n    return JSON.parse(x);\n}\n"
    res = validate_file_remediation_in_memory(
        path="src/sink.js",
        before_text=before,
        after_text=deleted_unrelated,
    )
    assert res.functions_preserved is False
    assert any("keepHelper" in issue or "deleted" in issue for issue in res.issues)

    with pytest.raises(UnifiedDiffApplyError):
        apply_unified_diff_in_memory(before, "@@ -1,2 +1,2 @@\n-wrong context line\n+replacement\n")
