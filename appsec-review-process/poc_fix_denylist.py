#!/usr/bin/env python3
"""Denylist scan for lane-12b proof-of-concept and fix text (brief F guardrails).

A lane-12b PoC is static text that only triggers the crash or overflow (or shows the faulty
control flow) of one verified, Critical, reachable finding. The pipeline never executes it. This
module is the Python gate on that text: every rule below names something a light PoC never needs,
so a hit rejects the text (the caller records a gap and keeps only the rule id, line number and a
hash, never the text). The scan is deliberately conservative: a false positive costs one PoC, a
false negative could publish hostile material.

Rules (stable ids, used in records and gaps):

* ``process-spawn``    -- process creation or exec (``system``, ``popen``, ``exec*``, ``fork``,
  ``subprocess``, ``CreateProcess``, ``Runtime.exec`` ...);
* ``network``          -- sockets, HTTP clients, URLs, network commands (callbacks, exfiltration);
* ``file-write``       -- writing, creating or appending a file whose line names no temp file;
* ``destructive``      -- deleting files or data, killing processes, formatting, permission changes;
* ``encoded-blob``     -- base64/hex runs, escaped byte strings, byte arrays, decode calls
  (a uniform printable filler such as ``"A" * 300`` or ``\\x41\\x41...`` is not a blob);
* ``interpreter-pipe`` -- shell metacharacters or command substitution feeding an interpreter,
  ``eval`` / ``exec`` of strings, ``sh -c`` style one-liners;
* ``credentials``      -- private keys, credential assignments, credential stores;
* ``persistence``      -- cron, services, start-up files, authorized keys, run keys;
* ``code-injection``   -- executable memory, shellcode / ROP wording;
* ``obfuscation``      -- character-code assembly, rot13, compressed or pickled code.
"""
from __future__ import annotations

import re
from typing import Any

_I = re.IGNORECASE

_TEMP_NAME = re.compile(r"tempfile|mkstemp|mkdtemp|tmpfile\s*\(|NamedTemporaryFile|TemporaryDirectory|"
                        r"tmp_path|/tmp/[\w.-]+|%TEMP%|\$TMPDIR|GetTempPath|gettempdir", _I)

RULES: dict[str, tuple[re.Pattern[str], ...]] = {
    "process-spawn": (
        re.compile(r"\b(?:system|_?popen|exec[lv]p?e?|execvpe|fork|vfork|posix_spawnp?|WinExec|"
                   r"CreateProcess(?:AsUser)?[AW]?|ShellExecute(?:Ex)?[AW]?|pcntl_exec|shell_exec|passthru|"
                   r"proc_open)\s*\("),
        re.compile(r"\bsubprocess\b|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*|fork)\b|\bchild_process\b|"
                   r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|\bProcessBuilder\b|\bexec\s*\.\s*Command\b|"
                   r"\bProcess\s*\.\s*Start\b|\bstd::system\b"),
    ),
    "network": (
        re.compile(r"\b(?:socket|connect|bind|listen|accept|sendto|recvfrom|getaddrinfo|gethostbyname|"
                   r"inet_addr|inet_pton|WSAStartup)\s*\("),
        re.compile(r"\b(?:urllib\d?|requests\s*\.|http\s*\.\s*client|httplib|aiohttp|httpx|XMLHttpRequest|"
                   r"WebSocket|net\s*\.\s*Dial|HttpClient|WebClient|curl_easy\w*|libcurl|Net::HTTP|"
                   r"socket\s*\.\s*\w+)", _I),
        re.compile(r"\bfetch\s*\("),
        re.compile(r"(?:^|[\s;|&(])(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|ftp|tftp|rsync|socat)\s"),
        re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://", _I),
        re.compile(r"/dev/(?:tcp|udp)/"),
    ),
    "file-write": (
        re.compile(r"\bfopen\s*\([^;\n]*,\s*[\"'][^\"']*[wa+]"),
        re.compile(r"\bopen\s*\([^;\n]*,\s*[\"'][^\"']*[wax+]"),
        re.compile(r"\bO_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)\b"),
        re.compile(r"\b(?:ofstream|fstream|FileOutputStream|FileWriter|StreamWriter|BufferedWriter)\b"),
        re.compile(r"\.\s*write_(?:text|bytes)\s*\(|\bfs\s*\.\s*(?:write|append)File|\bWriteFile\b|"
                   r"\bCreateFile[AW]?\b|\bFile\s*\.\s*(?:Write|Append)\w*"),
        re.compile(r"(?:^|\s)\d?>>?\s*(?:[~/$%][\w./$%~-]*|[\w-]+\.(?:txt|bin|dat|log|out|sh|py|so|dll|exe|conf|cfg|"
                   r"ini|json|xml|html|php|js)\b)|\btee\b|\bdd\s+[^\n]*\bof="),
    ),
    "destructive": (
        re.compile(r"\brm\s+-[a-zA-Z]*[rf]|\bdel\s+/[sfq]|\bmkfs\b|\bformat\s+[a-z]:|\bshred\b|"
                   r"\bkill\s+-9\b|\bkillall\b|\bpkill\b|:\(\)\s*\{", _I),
        re.compile(r"\b(?:unlink|remove|rmdir|truncate|DeleteFile[AW]?|RemoveDirectory[AW]?)\s*\(\s*(?:L|u8)?[\"']|"
                   r"\b(?:shutil\s*\.\s*rmtree|os\s*\.\s*(?:remove|unlink|rmdir|removedirs)|DeleteFile[AW]?|"
                   r"RemoveDirectory[AW]?)\s*\("),
        re.compile(r"\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b|\bDELETE\s+FROM\b", _I),
        re.compile(r"\bchmod\s+(?:-R\s+)?[0-7]{3,4}\b|\bchown\b|\bsetuid\s*\(|\bsetgid\s*\("),
    ),
    "encoded-blob": (
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
        re.compile(r"\b[0-9a-fA-F]{48,}\b"),
        re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
        re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}"),
        re.compile(r"(?:%[0-9a-fA-F]{2}){8,}"),
        re.compile(r"(?:\\[0-7]{3}){8,}"),
        re.compile(r"(?:0x[0-9a-fA-F]{1,2}\s*,\s*){16,}"),
        re.compile(r"\b(?:b64decode|b32decode|a85decode|base64_decode|atob|FromBase64String|unhexlify|"
                   r"decodestring|decodebytes)\b|\bbytes\s*\.\s*fromhex\b|\bbase64\s+-{1,2}d", _I),
    ),
    "interpreter-pipe": (
        re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|csh|python[0-9.]*|perl|ruby|php|node|lua|"
                   r"powershell|pwsh|cmd(?:\.exe)?|iex|Invoke-Expression)\b", _I),
        re.compile(r"\$\(|`\s*(?:id|whoami|uname|cat|ls|curl|wget|nc|sh|bash|python\w*|perl|echo|env)\b[^`\n]*`"),
        re.compile(r"\b(?:eval|exec|execfile|compile)\s*\(|\bInvoke-Expression\b|\bIEX\b"),
        re.compile(r"\b(?:sh|bash|zsh|python[0-9.]*|perl|ruby|node|php|powershell|pwsh|cmd)(?:\.exe)?\s+"
                   r"(?:-c|-e|/c|-Command|-EncodedCommand|-enc)\b", _I),
    ),
    "credentials": (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|bearer)\b\s*[:=]\s*"
                   r"[\"'][^\"'\s]{4,}", _I),
        re.compile(r"/etc/(?:shadow|passwd|sudoers)|\.ssh/|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials|"
                   r"\.netrc|\bmimikatz\b|\blsass\b|\bkeychain\b|\bSAM\b\s+hive", _I),
    ),
    "persistence": (
        re.compile(r"\bcrontab\b|/etc/cron|\bsystemctl\s+(?:enable|start)|/etc/systemd|\.bashrc|\.bash_profile|"
                   r"\.zshrc|(?:~|\$HOME)/\.profile\b|authorized_keys|CurrentVersion\\+Run|\bschtasks\b|LaunchAgents|"
                   r"LaunchDaemons|/etc/rc\.local|/etc/init\.d|\bat\s+now\b|\bld\.so\.preload\b|LD_PRELOAD", _I),
    ),
    "code-injection": (
        re.compile(r"\bPROT_EXEC\b|\bVirtualAlloc(?:Ex)?\b|\bVirtualProtect(?:Ex)?\b|\bmprotect\s*\(|"
                   r"\bWriteProcessMemory\b|\bCreateRemoteThread\b|\bptrace\s*\("),
        re.compile(r"\bshell\s*code\b|\bshellcode\b|\bnop[\s-]*sled\b|\bret2(?:libc|plt|win)\b|\bROP\s+chain\b|"
                   r"\bROP\s+gadgets?\b|\bmeterpreter\b|\breverse\s+shell\b|\bbind\s+shell\b", _I),
    ),
    "obfuscation": (
        re.compile(r"(?:(?:\bchr|\bString\s*\.\s*fromCharCode|\bchar)\s*\(\s*\d+\s*\)\s*[+,.]\s*){3,}"),
        re.compile(r"\brot_?13\b|\bcodecs\s*\.\s*decode\b|\b(?:zlib|gzip|bz2|lzma)\s*\.\s*decompress\b|"
                   r"\bmarshal\s*\.\s*loads\b|\bpickle\s*\.\s*loads\b|\bFunction\s*\(\s*[\"']", _I),
    ),
}
FULL = tuple(RULES)
_RUNS = RULES["encoded-blob"][:2]   # base64 and bare-hex runs: filtered by _blob_like
# Prose fields (explanation, fix rationale) describe the code path; they are held to the rules
# that carry material rather than name APIs: blobs, pipes into interpreters, credentials.
PROSE = ("encoded-blob", "interpreter-pipe", "credentials", "persistence")


def _blob_like(text: str) -> bool:
    """A base64/hex-shaped run that is not filler and not a slash-separated path of words."""
    if _uniform(text):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", text):
        return True
    if "/" in text and all(re.fullmatch(r"[A-Za-z][a-z0-9]*", part) for part in text.split("/") if part):
        return False   # a path of words, e.g. src/lib/parser/internal/state
    return any(c.isdigit() for c in text) and any(c.isupper() for c in text) and any(c.islower() for c in text)


def _uniform(text: str) -> bool:
    """A padding run (``AAAA...``, ``\\x41\\x41...``, ``0x41, 0x41, ...``): at most two distinct
    printable units. Such filler is how a light overflow PoC makes its oversized input."""
    units = re.findall(r"\\x([0-9a-fA-F]{2})|0x([0-9a-fA-F]{1,2})|%([0-9a-fA-F]{2})", text)
    if units:
        values = {int(a or b or c, 16) for a, b, c in units}
        return len(values) <= 2 and all(0x20 <= value < 0x7f for value in values)
    return len(set(text.rstrip("="))) <= 2


def scan(text: str | None, rules: tuple[str, ...] = FULL) -> list[dict[str, Any]]:
    """Rule hits in ``text`` as ``[{rule, line}]`` (1-based line, sorted, one per rule and line)."""
    if not text:
        return []
    hits: set[tuple[str, int]] = set()
    lines = str(text).splitlines() or [str(text)]
    for number, line in enumerate(lines, start=1):
        for rule in rules:
            for pattern in RULES[rule]:
                for match in pattern.finditer(line):
                    if pattern in _RUNS and not _blob_like(match.group(0)):
                        continue
                    if rule == "encoded-blob" and pattern not in _RUNS and _uniform(match.group(0)):
                        continue
                    if rule == "file-write" and _TEMP_NAME.search(line):
                        continue
                    hits.add((rule, number))
                    break
    return [{"rule": rule, "line": line} for rule, line in sorted(hits, key=lambda item: (item[1], item[0]))]


def added_lines(diff: str) -> str:
    """The lines a unified diff adds (``+`` lines, not the ``+++`` header): what a fix would introduce."""
    return "\n".join(line[1:] for line in str(diff).splitlines()
                     if line.startswith("+") and not line.startswith("+++"))
