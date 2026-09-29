"""Lane-12b denylist (brief F guardrails): every rule rejects a hostile-looking fixture, and the
benign shapes a light PoC needs (filler input, one call, a temp file) pass.

The fixtures are defanged: each only trips a rule's pattern (reserved .invalid hosts, placeholder
values, digests generated at run time). None is a working payload."""
from __future__ import annotations

import base64
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import poc_fix_denylist as denylist

_BLOB = base64.b64encode(hashlib.sha256(b"fixture").digest() + hashlib.sha256(b"other").digest()).decode()
_BYTES = "".join(f"\\x{value:02x}" for value in hashlib.sha256(b"bytes").digest()[:12])

HOSTILE = {
    "process-spawn": ['system("id");', "subprocess.run(['true'])", "execve(path, argv, envp);",
                      "Runtime.getRuntime().exec(cmd)"],
    "network": ['int s = socket(AF_INET, SOCK_STREAM, 0);', "requests.get(target)",
                "curl http://collector.invalid/x", "exec 3<>/dev/tcp/host.invalid/80"],
    "file-write": ['FILE *f = fopen("/etc/app.conf", "w");', "open('report.txt', 'w').write(x)",
                   "echo data > /etc/motd", "std::ofstream out(\"state.bin\");"],
    "destructive": ["rm -rf /var/lib/app", 'unlink("/var/lib/app/db");', "shutil.rmtree(root)",
                    "DROP TABLE users;"],
    "encoded-blob": [f'blob = "{_BLOB}"', f'shell = "{_BYTES}"', "base64.b64decode(data)",
                     "unsigned char p[] = {" + ", ".join(f"0x{v:02x}" for v in hashlib.sha256(b"a").digest()[:20]) + "};"],
    "interpreter-pipe": ["cat input | sh", "value=$(cat secret)", "eval(user_input)", "bash -c 'true'"],
    "credentials": ["-----BEGIN RSA PRIVATE KEY-----", 'password = "hunter2-placeholder"', "cat /etc/shadow",
                    "~/.ssh/id_rsa"],
    "persistence": ["crontab -l", "echo x >> ~/.bashrc", "cat key >> authorized_keys", "systemctl enable svc"],
    "code-injection": ["mprotect(page, len, PROT_READ | PROT_EXEC);", "VirtualAlloc(NULL, n, MEM_COMMIT, 0x40)",
                       "place the shellcode after the return address", "build a ROP chain"],
    "obfuscation": ["chr(105) + chr(100) + chr(32) + chr(45)", "codecs.decode(s, 'rot13')",
                    "zlib.decompress(data)", "pickle.loads(blob)"],
}

BENIGN = [
    "char buf[300];\nmemset(buf, 'A', sizeof buf - 1);\nbuf[299] = '\\0';\nparse_header(buf, sizeof buf);",
    'payload = b"A" * 4096\nparse_header(payload)',
    's = "' + "\\x41" * 64 + '"',
    "unsigned char pad[] = {" + ", ".join(["0x41"] * 32) + "};",
    "with tempfile.NamedTemporaryFile('wb') as handle:\n    handle.write(b'A' * 512)",
    'FILE *f = fopen("/tmp/poc-input.bin", "wb");',
    "if (len > sizeof(buffer)) return -1;",
    '#include "src/lib/parser/internal/tokenizer/header/state.h"',
    "TEST(Parser, LongHeaderOverflows) { std::string in(300, 'A'); EXPECT_DEATH(parse_header(in), \"\"); }",
]


class DenylistTests(unittest.TestCase):
    def test_every_rule_rejects_its_hostile_fixtures(self):
        self.assertEqual(set(HOSTILE), set(denylist.RULES))
        for rule, samples in HOSTILE.items():
            for sample in samples:
                with self.subTest(rule=rule, sample=sample):
                    self.assertIn(rule, {hit["rule"] for hit in denylist.scan(sample)})

    def test_benign_light_poc_shapes_pass(self):
        for sample in BENIGN:
            with self.subTest(sample=sample):
                self.assertEqual(denylist.scan(sample), [])

    def test_hits_carry_rule_and_line_only(self):
        hits = denylist.scan("int x = 1;\nsystem(\"id\");\n")
        self.assertEqual(hits, [{"rule": "process-spawn", "line": 2}])

    def test_prose_rules_allow_api_names_but_not_material(self):
        prose = "argv[1] reaches parse_header(), which calls strcpy() into a 16-byte stack buffer."
        self.assertEqual(denylist.scan(prose, denylist.PROSE), [])
        self.assertEqual({hit["rule"] for hit in denylist.scan(f"send {_BLOB}", denylist.PROSE)}, {"encoded-blob"})

    def test_added_lines_of_a_diff_are_what_a_fix_introduces(self):
        diff = ("--- a/app/main.cpp\n+++ b/app/main.cpp\n@@ -9 +9 @@\n-    system(cmd);\n"
                "+    std::strncpy(buffer, s, sizeof buffer - 1);\n")
        self.assertEqual(denylist.added_lines(diff), "    std::strncpy(buffer, s, sizeof buffer - 1);")
        self.assertEqual(denylist.scan(denylist.added_lines(diff)), [])


if __name__ == "__main__":
    unittest.main()
