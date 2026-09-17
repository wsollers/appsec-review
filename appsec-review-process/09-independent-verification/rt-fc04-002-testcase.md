# Testcase Prompt — RT-FC04-002 UTF-8 Extended Lead-Byte Decoder

Use this prompt to write and run a minimal verification test for `RT-FC04-002`.

## Mission

Verify whether EASTL's UTF-8 conversion path treats unsupported 5-byte and 6-byte UTF-8 lead-byte
patterns as successful conversions with output `0xffff`, instead of rejecting them.

Treat this as independent verification. Do not rely on the red-team or blue-team conclusion except
for the claim id and cited source locations.

## Claim To Verify

`RT-FC04-002`: In `targets/eastl/source/string.cpp`, `UTF8ToUCS4` appears to leave `success == true`
and `c == 0xffff` when it enters the enough-input branches for lead bytes matching:

- `(cChar0 & 0xFC) == 0xF8`
- `(cChar0 & 0xFE) == 0xFC`

Relevant source:

- `targets/eastl/source/string.cpp:84-252`
- `targets/eastl/source/string.cpp:202-214`
- `targets/eastl/source/string.cpp:216-228`
- `targets/eastl/source/string.cpp:241-245`
- `targets/eastl/source/string.cpp:299-317`

The public-ish route to test is `eastl::DecodePart(const char*& pSrc, const char* pSrcEnd,
char32_t*& pDest, char32_t* pDestEnd)`, declared in:

- `targets/eastl/include/EASTL/internal/char_traits.h`

## Required Test Behavior

Create a scratch C++ test outside the tracked target source, for example:

```text
scratch/eastl-engagement/verification/rt-fc04-002/utf8_extended_probe.cpp
```

The test should:

1. Include EASTL's `internal/char_traits.h`.
2. Call the `char` to `char32_t` `DecodePart` overload directly.
3. Test at least these byte sequences:
   - `0xF8 0x80 0x80 0x80`
   - `0xFC 0x80 0x80 0x80 0x80`
4. For each case, print:
   - input label
   - `DecodePart` return value
   - source pointer advancement
   - destination pointer advancement
   - first output code point as hex
5. Treat the issue as verified if either case returns success while producing `0xffff` for an
   unsupported extended UTF-8 form.
6. Treat the issue as refuted only if the observed behavior clearly rejects both forms, such as
   `DecodePart == false`, failure return propagation, or no successful output.

Use exact-width byte literals so sign-extension does not confuse the test.

Suggested test skeleton:

```cpp
#include <EASTL/internal/char_traits.h>
#include <cstdint>
#include <cstdio>

static bool run_case(const char* label, const unsigned char* bytes, size_t len)
{
    const char* src = reinterpret_cast<const char*>(bytes);
    const char* src_begin = src;
    const char* src_end = src + len;
    char32_t out[4] = {};
    char32_t* dst = out;
    char32_t* dst_begin = dst;
    char32_t* dst_end = out + 4;

    bool ok = eastl::DecodePart(src, src_end, dst, dst_end);
    auto src_advanced = static_cast<long long>(src - src_begin);
    auto dst_advanced = static_cast<long long>(dst - dst_begin);

    std::printf("%s ok=%d src_advanced=%lld dst_advanced=%lld out0=0x%08x\n",
                label, ok ? 1 : 0, src_advanced, dst_advanced,
                static_cast<unsigned>(out[0]));

    return ok && dst_advanced > 0 && out[0] == 0xffff;
}

int main()
{
    const unsigned char f8_case[] = {0xF8, 0x80, 0x80, 0x80};
    const unsigned char fc_case[] = {0xFC, 0x80, 0x80, 0x80, 0x80};

    bool issue = false;
    issue |= run_case("f8", f8_case, sizeof(f8_case));
    issue |= run_case("fc", fc_case, sizeof(fc_case));

    if(issue)
    {
        std::puts("VERIFIED_RT_FC04_002");
        return 2;
    }

    std::puts("REFUTED_RT_FC04_002");
    return 0;
}
```

## Build Guidance

Prefer the existing EASTL build configuration if convenient. Otherwise compile the scratch test
against the copied EASTL source and support sources. Use the existing compile database and build
logs to discover include paths if compilation fails.

Start with an intentionally simple command and then add include paths as needed:

```powershell
g++ -std=c++17 `
  -Itargets/eastl/include `
  -Itargets/eastl/test/packages/EABase/include/Common `
  scratch/eastl-engagement/verification/rt-fc04-002/utf8_extended_probe.cpp `
  targets/eastl/source/string.cpp `
  -o scratch/eastl-engagement/verification/rt-fc04-002/utf8_extended_probe.exe
```

If the host compiler path is inconvenient on Windows, run the same idea in WSL or inside the native
audit image. Do not edit EASTL source just to make the test compile.

## Error Handling And Reporting

Do not stop with an unrecorded failure. Every compile, link, and run attempt must be captured in the
markdown and JSON output.

Before compiling, record:

- working directory
- compiler executable path, if known
- compiler version command and output, if available
- source test path
- target EASTL source path
- include paths used

For each attempted command, record:

- command line
- exit code
- stdout
- stderr
- whether the command was compile, link, or run
- short interpretation of the failure or result

Attempt order:

1. Try the simple host compile command from this prompt.
2. If headers are missing, inspect `targets/eastl/build/compile_commands.json` or the engagement
   compile database and add only the missing include/define arguments needed for this test.
3. If host compilation is unavailable, try WSL or the native audit Docker image.
4. If linking against `targets/eastl/source/string.cpp` fails because support symbols are missing,
   identify the missing symbols and add the minimal EASTL support source files required.
5. If the test still cannot compile or link after reasonable attempts, write `verdict: unresolved`
   with `blocked_reason: compile-or-link-failure` and include the exact next command or dependency
   needed to resume.

Verdict rules:

- `verified`: the test compiled, ran, and at least one `0xF8` or `0xFC` enough-input case returned
  success while producing `0xffff`.
- `refuted`: the test compiled, ran, and both cases were rejected or produced behavior that clearly
  contradicts the claim.
- `unresolved`: the test did not compile/link/run, crashed before producing observations, or the
  output is ambiguous.

If the executable crashes, times out, or triggers an assertion, record the crash as observed
behavior. Do not convert a crash to `verified` unless it directly demonstrates the claim.

## Required Output

Write results to:

```text
appsec-review-process/runs/<run_id>/outputs/09-independent-verification/rt-fc04-002-test-result.md
appsec-review-process/runs/<run_id>/outputs/09-independent-verification/rt-fc04-002-test-result.json
```

The markdown must include:

- test source path
- compiler/environment details
- every compile/link/run command attempted
- stdout/stderr for every attempt
- exit code for every attempt
- observed behavior table
- verdict: `verified`, `refuted`, or `unresolved`
- blocked reason, if unresolved
- confidence
- notes on whether the behavior is a vulnerability, correctness issue, hardening item, or only
  relevant when used in security-sensitive contexts

The JSON must include:

```json
{
  "claim_id": "RT-FC04-002",
  "verdict": "verified|refuted|unresolved",
  "confidence": "low|medium|high",
  "blocked_reason": "",
  "test_source": "",
  "attempts": [
    {
      "kind": "compile|link|run",
      "command": "",
      "exit_code": null,
      "stdout": "",
      "stderr": "",
      "interpretation": ""
    }
  ],
  "observations": [
    {
      "case": "f8|fc",
      "ok": null,
      "src_advanced": null,
      "dst_advanced": null,
      "out0_hex": "",
      "supports_claim": null
    }
  ],
  "minimum_next_step": ""
}
```

Do not call this a vulnerability solely because the behavior is verified. Separate observed behavior
from security impact.
