"""Reviewed C/C++ proof procedures for the ASVS chapters a network service admits (T-5013).

Each procedure binds one pinned ASVS 5.0.0 control (exact upstream text) to one recogniser family of
``c_subjects``. The subject is a complete function (or named type) with the entry and sink lines the
family found; the worker is asked to establish the control's invariant for that function only, citing
the complete function excerpt and any resolved caller/callee excerpts. Recognition is lexical and a
review question, never a verdict, and no procedure here applies to another language.
"""
from __future__ import annotations

from typing import Any, Mapping

from . import c_subjects as c


LANGUAGE = c.LANGUAGE
_ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"
_UNKNOWN = (
    "Missing, truncated, redacted, ambiguous, declaration-only or non-resolving evidence cannot "
    "establish a decisive outcome.",
    "Unresolved prerequisites, effective controls or materially relevant alternate paths require "
    "cannot_verify, not an assumption of compliance or a failure inferred from absence.",
)
_C_LIMITS = (
    "Recognition is lexical over the complete function: a call is a name followed by a parenthesis, "
    "macro bodies are not scanned and K&R definitions are not recognised; it is not taint analysis.",
    "The complete function is the subject; callers, callees, the compiler, platform libraries and "
    "build flags are context to resolve from accepted evidence, never assumed.",
)
_INPUT_PREREQUISITES = (
    "Resolve where the function's input bytes come from (socket, file, environment, argv, caller) and "
    "which consumer can influence them.",
    "Resolve the length, encoding and termination assumptions the function makes about that input.",
    "Resolve the callers and the guards they apply before this function is reached.",
)
_INPUT_QUESTIONS = (
    "Is every externally influenced value checked against an explicit bound or allowlist before the "
    "named sink uses it?",
    "Can a caller, an alternate verb or an error path reach the sink with an unchecked value?",
    "Does a guard elsewhere (caller, wrapper, compiler hardening) actually dominate the named sink, "
    "or is it only nearby?",
)
_SESSION_PREREQUISITES = (
    "Resolve how the session or token value is created, where it is stored and which operations read, "
    "reset or destroy it.",
    "Resolve the lifetime of the state: creation, use, timeout, termination and reuse after termination.",
    "Resolve whether the value is a secret the client presents or server-side state keyed by connection.",
)
_SESSION_QUESTIONS = (
    "Is the token or identifier dynamically generated per session with a cryptographically secure source, "
    "or static, predictable or derived from client input?",
    "After termination or reset, can the old state or buffer still be reached by the same or another "
    "connection?",
    "Is a timeout or lifetime bound enforced by code, by documentation only, or not at all?",
)
_LOG_PREREQUISITES = (
    "Resolve what the function writes, to which stream or facility, and which values of the message "
    "are client-controlled.",
    "Resolve the format string and the arguments bound to it at the named call.",
    "Resolve the callers that route client input into this function.",
)
_LOG_QUESTIONS = (
    "Is the format string a literal, and is client-controlled text encoded or bounded before it reaches "
    "the log?",
    "Does the log entry carry the metadata the control names (when, where, who, what) or only the "
    "message?",
    "Does the function write credentials, tokens or payload bytes that the data's protection level "
    "forbids?",
)
_ERROR_PREREQUISITES = (
    "Resolve each error exit of the function: what is returned, what is released, what state is left.",
    "Resolve what the caller does with the error value and what the client is told.",
    "Resolve the failure modes of the external resources the function uses (files, pipes, sockets, "
    "allocations).",
)
_ERROR_QUESTIONS = (
    "Does an error path release what it acquired, or leak, double-release or keep using it?",
    "Is the client-visible message generic, or does it expose internal paths, errno text or memory "
    "contents?",
    "Can an error be ignored so that processing continues as if validation had passed?",
)


def _procedure(control: str, control_text: str, recognizer: str, *, invariant: str, subject_scope: str,
               prerequisites: tuple[str, ...], questions: tuple[str, ...], support: str, contradiction: str,
               satisfied: tuple[str, ...], not_satisfied: tuple[str, ...], cannot_verify: tuple[str, ...] = (),
               static_limits: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "family": "ASVS", "version": "5.0.0", "control": control, "control_text": control_text,
        "upstream_commit": _ASVS_COMMIT, "invariant": invariant, "recognizer": recognizer,
        "subject_scope": subject_scope, "prerequisites": prerequisites, "support": support,
        "contradiction": contradiction, "effective_control_questions": questions, "satisfied": satisfied,
        "not_satisfied": not_satisfied, "cannot_verify": _UNKNOWN + cannot_verify,
        "static_limits": _C_LIMITS + static_limits, "language": LANGUAGE,
    }


C_PROCEDURE_FIELDS: tuple[Mapping[str, Any], ...] = (
    _procedure(
        "V1.2.5",
        "Verify that the application protects against OS command injection and that operating system "
        "calls use parameterized OS queries or use contextual command line output encoding.",
        c.COMMAND_SINK,
        invariant="The named function's operating-system command call cannot carry client-influenced text "
                  "into command structure.",
        subject_scope="One complete function containing popen/system/exec*-family or posix_spawn calls; not "
                      "every process launch in the component.",
        prerequisites=_INPUT_PREREQUISITES,
        questions=_INPUT_QUESTIONS + (
            "Is the command built from a literal and an exec*-style argument vector, or by formatting client "
            "text into a shell string?",),
        support="The command is a fixed literal or an argument vector whose client-influenced elements are "
                "allowlisted or escaped for the shell context, on every path to the call.",
        contradiction="A resolved path formats or concatenates client-influenced text into a string handed to "
                      "a shell interpreter without an effective allowlist or escaping.",
        satisfied=("Cited construction shows a literal command or an exec-style vector with every untrusted "
                   "element bounded by a demonstrated allowlist or escaping at the named call.",
                   "Material callers and alternate paths to this call are resolved."),
        not_satisfied=("Cited source traces a concrete client-influenced value into a shell command string at "
                       "this call.",
                       "The resolved caller path applies no effective allowlist or escaping; the call name alone "
                       "is insufficient."),
        cannot_verify=("An unresolved command buffer or an unknown caller cannot establish separation or injection.",),
    ),
    _procedure(
        "V1.3.3",
        "Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce "
        "safety measures, such as only allowing characters which are safe for this context and trimming input "
        "which is too long.",
        c.INPUT_ENTRY,
        invariant="The named input-reading function bounds and sanitizes what it reads before handing it to a "
                  "dangerous context.",
        subject_scope="One complete function that reads external input (socket, file, environment, argv); the "
                      "sinks it feeds are named by their own procedures.",
        prerequisites=_INPUT_PREREQUISITES,
        questions=_INPUT_QUESTIONS,
        support="The function bounds the length, terminates the buffer and restricts the characters of what it "
                "reads before any dangerous use on every path.",
        contradiction="A resolved path passes the raw input, or an over-long or unterminated copy of it, to a "
                      "dangerous context without the sanitization the control names.",
        satisfied=("Cited source shows the bound, termination and character restriction applied to the input "
                   "before each dangerous use reachable from this function.",
                   "Material dangerous uses reachable from this function are resolved, not assumed benign."),
        not_satisfied=("Cited source traces raw or over-long input from this function into a dangerous context "
                       "with no effective sanitization on that path.",
                       "The dangerous use and the missing bound are both cited; an input call alone is insufficient."),
    ),
    _procedure(
        "V1.3.10",
        "Verify that format strings which might resolve in an unexpected or malicious way when used are "
        "sanitized before being processed.",
        c.FORMAT_SINK,
        invariant="The named function never lets client-influenced text act as a printf-family format string.",
        subject_scope="One complete function with a printf-family call whose format argument is not a string "
                      "literal.",
        prerequisites=_INPUT_PREREQUISITES + ("Resolve the provenance of the non-literal format argument.",),
        questions=("Is the non-literal format a trusted constant (table, macro, translation) or can a client "
                   "influence it?",
                   "Is the value passed as a format or as a %s argument to a literal format?") + _INPUT_QUESTIONS[1:],
        support="The non-literal format argument is a trusted constant on every path, or client text is passed "
                "only as data to a literal format.",
        contradiction="A resolved path lets client-influenced text reach the format argument of a printf-family "
                      "call.",
        satisfied=("Cited source resolves the format argument to trusted constant text on every path to the "
                   "named call.",
                   "Material callers that could supply the format are resolved."),
        not_satisfied=("Cited source traces client-influenced text into the format argument at the named call.",
                       "The resolved path applies no sanitization; a variable format alone is insufficient without "
                       "its provenance."),
    ),
    _procedure(
        "V1.4.1",
        "Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to "
        "detect or prevent stack, buffer, or heap overflows.",
        c.COPY_SINK,
        invariant="Every string or memory copy in the named function is bounded by the destination's actual "
                  "capacity.",
        subject_scope="One complete function with strcpy/strcat/sprintf/memcpy/memmove-family copies; not the "
                      "component's memory safety.",
        prerequisites=("Resolve the destination buffer's declaration and capacity for each copy.",
                       "Resolve the length argument or the source's maximum length and where it is checked.",
                       "Resolve callers that choose the length or the source."),
        questions=("Does the copied length derive from the destination capacity, or from the source or client?",
                   "Is the bound checked on the path that reaches the copy (dominating), or only elsewhere?",
                   "Does the copy leave room for the terminator the later code expects?"),
        support="Each copy's length is derived from or checked against the destination capacity on the path to "
                "the copy, including the terminator.",
        contradiction="A resolved path copies a source- or client-chosen length into a destination of smaller or "
                      "unchecked capacity.",
        satisfied=("Cited declarations and control flow bound every copy in the function by the destination "
                   "capacity.",
                   "Material callers that supply lengths or sources are resolved."),
        not_satisfied=("Cited source shows a concrete copy whose length can exceed the destination capacity on a "
                       "resolved path.",
                       "The destination capacity and the unbounded length are both cited; the call name alone is "
                       "insufficient."),
    ),
    _procedure(
        "V1.4.2",
        "Verify that sign, range, and input validation techniques are used to prevent integer overflows.",
        c.ALLOCATION_SIZE,
        invariant="Every computed allocation size in the named function is range-checked before it can wrap.",
        subject_scope="One complete function with a malloc/calloc/realloc/alloca/new[] size that is computed "
                      "rather than constant.",
        prerequisites=("Resolve the integer types and widths of the operands of the size expression.",
                       "Resolve where each operand comes from and whether a client influences it.",
                       "Resolve how the allocation's later uses rely on the computed size."),
        questions=("Can the multiplication or addition wrap in the operand type before the allocation?",
                   "Is a range check applied before the arithmetic, with the right signedness and width?",
                   "Do later copies trust the unwrapped size while the allocation received the wrapped one?"),
        support="The size expression is range-checked or uses overflow-safe arithmetic before the allocation on "
                "every path, and the later uses rely on the same checked size.",
        contradiction="A resolved path lets client-influenced operands wrap the size expression before the "
                      "allocation, with later uses trusting the unwrapped value.",
        satisfied=("Cited source shows the range check or overflow-safe arithmetic dominating the named "
                   "allocation.",
                   "Material operand provenance is resolved."),
        not_satisfied=("Cited source shows a concrete wrap of the size expression reachable with client-influenced "
                       "operands.",
                       "The operand types and the missing check are both cited."),
    ),
    _procedure(
        "V1.4.3",
        "Verify that dynamically allocated memory and resources are released, and that references or pointers "
        "to freed memory are removed or set to null to prevent dangling pointers and use-after-free "
        "vulnerabilities.",
        c.MEMORY_RELEASE,
        invariant="After each release in the named function no path reads, writes or re-releases the freed "
                  "object through a stale pointer.",
        subject_scope="One complete function with free/delete calls; not the component's ownership model.",
        prerequisites=("Resolve the ownership of each pointer the function releases and who else holds it.",
                       "Resolve every use of the pointer after the release within the function and its callers.",
                       "Resolve whether the pointer is reassigned or nulled after the release."),
        questions=("Is the freed pointer used before it is reassigned, including through aliases or struct "
                   "fields?",
                   "Can the function be entered again with the same object after it was released?",
                   "Does an error path release an object the caller also releases?"),
        support="Every release is followed on every path by reassignment or no further use, and no other owner "
                "releases the same object.",
        contradiction="A resolved path uses or re-releases the object after the named release.",
        satisfied=("Cited control flow shows each released pointer reassigned or unused afterwards on every path "
                   "in the function.",
                   "Material aliases and co-owners are resolved."),
        not_satisfied=("Cited source shows a concrete use or second release of the freed object after the named "
                       "release.",
                       "The release and the stale use are both cited."),
    ),
    _procedure(
        "V2.2.1",
        "Verify that input is validated to enforce business or functional expectations for that input. This "
        "should either use positive validation against an allow list of values, patterns, and ranges, or be "
        "based on comparing the input to an expected structure and logical limits according to predefined "
        "rules. For L1, this can focus on input which is used to make specific business or security decisions. "
        "For L2 and up, this should apply to all input.",
        c.INPUT_ENTRY,
        invariant="The named input-reading function validates what it reads against an explicit structure, "
                  "allowlist or range before acting on it.",
        subject_scope="One complete function that reads external input (socket, file, environment, argv).",
        prerequisites=_INPUT_PREREQUISITES,
        questions=_INPUT_QUESTIONS + (
            "Is validation positive (allowlist, structure, range) or only a denylist or a length check?",),
        support="Each externally influenced value is positively validated against an explicit expectation before "
                "the function or its callees act on it.",
        contradiction="A resolved path acts on an externally influenced value with no positive validation.",
        satisfied=("Cited source shows positive validation of each input value before use on every path from "
                   "this function.",
                   "Material uses in callees are resolved, not assumed validated."),
        not_satisfied=("Cited source traces an unvalidated input value from this function into a decision or "
                       "sink.",
                       "The use and the absence of validation on that path are both cited."),
    ),
    _procedure(
        "V5.3.2",
        "Verify that when the application creates file paths for file operations, instead of user-submitted "
        "filenames, it uses internally generated or trusted data, or if user-submitted filenames or file "
        "metadata must be used, strict validation and sanitization must be applied. This is to protect against "
        "path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) "
        "attacks.",
        c.FILE_PATH,
        invariant="The named function's file paths are trusted or strictly validated before the path operation "
                  "uses them.",
        subject_scope="One complete function with fopen/open/realpath/stat/unlink-family calls on a non-literal "
                      "path.",
        prerequisites=_INPUT_PREREQUISITES + (
            "Resolve how the path is composed and whether canonicalisation precedes the containment check.",),
        questions=("Is the client-supplied component validated (allowlist, no separators or dot segments) or "
                   "canonicalised and checked against the root before the operation?",
                   "Does the containment check compare the canonical path, with a trailing separator, against the "
                   "intended root?",
                   "Does any other path call in the function skip the check that one call applies?"),
        support="Every path operation in the function uses trusted data or a path validated or canonicalised and "
                "contained before the call.",
        contradiction="A resolved path hands a client-influenced path to a file operation without the validation or "
                      "containment the control names.",
        satisfied=("Cited source shows the validation or canonicalisation-and-containment dominating each path "
                   "operation in the function.",
                   "Material callers that supply the path are resolved."),
        not_satisfied=("Cited source traces a client-influenced path into a file operation in this function with "
                       "no effective validation.",
                       "The operation and the missing check are both cited."),
    ),
    _procedure(
        "V7.2.2",
        "Verify that the application uses either self-contained or reference tokens that are dynamically "
        "generated for session management, i.e. not using static API secrets and keys.",
        c.SESSION_STATE,
        invariant="The named session state is identified by a dynamically generated token, not a static value.",
        subject_scope="One complete function or named type that creates, looks up, resets or expires session, "
                      "token or cookie state.",
        prerequisites=_SESSION_PREREQUISITES,
        questions=_SESSION_QUESTIONS,
        support="The session identifier is generated per session at creation and no static key or constant "
                "identifies a session.",
        contradiction="A resolved path identifies the session by a constant, a client-chosen value or a static "
                      "secret.",
        satisfied=("Cited source shows per-session generation of the identifier at the named creation path.",
                   "Material lookup and reset paths are resolved."),
        not_satisfied=("Cited source shows a constant or client-chosen session identifier at the named path.",
                       "The identifier and its static or client origin are both cited."),
        cannot_verify=("A connection-scoped structure with no identifier at all is not a token; the control may "
                       "not apply to it, and that is a scope question, not a failure.",),
    ),
    _procedure(
        "V7.2.3",
        "Verify that if reference tokens are used to represent user sessions, they are unique and generated "
        "using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 "
        "bits of entropy.",
        c.SESSION_STATE,
        invariant="Any reference token the named session code generates comes from a CSPRNG with at least 128 "
                  "bits of entropy and is unique.",
        subject_scope="One complete function or named type that creates or looks up session, token or cookie "
                      "state.",
        prerequisites=_SESSION_PREREQUISITES,
        questions=_SESSION_QUESTIONS,
        support="The token is drawn from a resolved CSPRNG with at least 128 bits of entropy and checked or "
                "structured for uniqueness.",
        contradiction="A resolved path derives the token from rand()/time/counters/client input or fewer than 128 "
                      "bits.",
        satisfied=("Cited source resolves the generator and width of the token at the named creation path.",
                   "Material alternate creation paths are resolved."),
        not_satisfied=("Cited source shows a weak or predictable token source at the named path.",
                       "The generator call and its width are both cited."),
        cannot_verify=("If no reference token exists the control's premise is unmet; record that, not a failure.",),
    ),
    _procedure(
        "V7.3.1",
        "Verify that there is an inactivity timeout such that re-authentication is enforced according to risk "
        "analysis and documented security decisions.",
        c.SESSION_STATE,
        invariant="The named session state carries and enforces an inactivity timeout.",
        subject_scope="One complete function or named type holding or touching session state.",
        prerequisites=_SESSION_PREREQUISITES,
        questions=_SESSION_QUESTIONS,
        support="Session state records last activity and an inactivity bound is enforced before use.",
        contradiction="Session state has no inactivity record or bound and remains usable indefinitely.",
        satisfied=("Cited source shows the activity timestamp and the enforced bound on the named path.",
                   "Material use paths that bypass the check are resolved."),
        not_satisfied=("Cited source shows session state used with no inactivity bound anywhere on the resolved "
                       "paths.",
                       "The state definition and its uses are both cited."),
    ),
    _procedure(
        "V7.3.2",
        "Verify that there is an absolute maximum session lifetime such that re-authentication is enforced "
        "according to risk analysis and documented security decisions.",
        c.SESSION_STATE,
        invariant="The named session state carries and enforces an absolute lifetime bound.",
        subject_scope="One complete function or named type holding or touching session state.",
        prerequisites=_SESSION_PREREQUISITES,
        questions=_SESSION_QUESTIONS,
        support="Session state records creation time and an absolute lifetime is enforced before use.",
        contradiction="Session state has no creation record or lifetime bound and remains usable indefinitely.",
        satisfied=("Cited source shows the creation timestamp and the enforced bound on the named path.",
                   "Material use paths that bypass the check are resolved."),
        not_satisfied=("Cited source shows session state used with no lifetime bound anywhere on the resolved "
                       "paths.",
                       "The state definition and its uses are both cited."),
    ),
    _procedure(
        "V7.4.1",
        "Verify that when session termination is triggered (such as logout or expiration), the application "
        "disallows any further use of the session. For reference tokens or stateful sessions, this means "
        "invalidating the session data at the application backend. Applications using self-contained tokens "
        "will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced "
        "before a per-user date and time or rotating a per-user signing key.",
        c.SESSION_STATE,
        invariant="After the named termination or reset, the session's data cannot be used again.",
        subject_scope="One complete function or named type that terminates, resets or closes session state.",
        prerequisites=_SESSION_PREREQUISITES,
        questions=_SESSION_QUESTIONS + (
            "Between release and reallocation of session buffers, is the released memory written or read?",),
        support="Termination invalidates the backend state and no path uses the state or its buffers afterwards.",
        contradiction="A resolved path uses, writes or re-releases session data or buffers after termination or "
                      "reset.",
        satisfied=("Cited control flow shows invalidation followed by no further use on every path.",
                   "Material callers that hold the session after termination are resolved."),
        not_satisfied=("Cited source shows a concrete use of session data or buffers after the named termination "
                       "or reset.",
                       "The termination and the later use are both cited."),
    ),
    _procedure(
        "V16.2.1",
        "Verify that each log entry includes necessary metadata (such as when, where, who, what) that would "
        "allow for a detailed investigation of the timeline when an event happens.",
        c.LOG_SINK,
        invariant="Each log entry the named function writes carries the metadata an investigation needs.",
        subject_scope="One complete logging function or a function that calls one.",
        prerequisites=_LOG_PREREQUISITES,
        questions=_LOG_QUESTIONS,
        support="The entry records time, origin, actor and event, directly or through the resolved logging "
                "facility.",
        contradiction="The entry is the bare message with no time, origin, actor or event metadata, and the "
                      "facility adds none.",
        satisfied=("Cited source or the resolved facility shows the metadata attached to each entry written by "
                   "the function.",
                   "The facility's behaviour is resolved from accepted evidence, not assumed."),
        not_satisfied=("Cited source shows a bare message written with no metadata and a facility that adds "
                       "none.",
                       "Both the write and the facility are cited."),
    ),
    _procedure(
        "V16.2.5",
        "Verify that when logging sensitive data, the application enforces logging based on the data's "
        "protection level. For example, it may not be allowed to log certain data, such as credentials or "
        "payment details. Other data, such as session tokens, may only be logged by being hashed or masked, "
        "either in full or partially.",
        c.LOG_SINK,
        invariant="The named function writes no credential, token or payload bytes to the log that the data's "
                  "protection level forbids.",
        subject_scope="One complete logging function or a function that calls one.",
        prerequisites=_LOG_PREREQUISITES,
        questions=_LOG_QUESTIONS,
        support="Every value the function logs is resolved to non-sensitive data, or is hashed or masked before "
                "the write.",
        contradiction="A resolved path writes a credential, token or protected payload to the log unmasked.",
        satisfied=("Cited source resolves each logged value's provenance and shows masking where the protection "
                   "level requires it.",),
        not_satisfied=("Cited source traces a protected value unmasked into the named log write.",
                       "The value's provenance and the write are both cited."),
    ),
    _procedure(
        "V16.3.4",
        "Verify that the application logs unexpected errors and security control failures such as backend TLS "
        "failures.",
        c.ERROR_PATH,
        invariant="Each unexpected error exit of the named function is logged.",
        subject_scope="One complete function with error exits (error returns, aborts, exceptions).",
        prerequisites=_ERROR_PREREQUISITES,
        questions=_ERROR_QUESTIONS + (
            "Is each unexpected error path recorded by a log call, or returned silently to the caller?",),
        support="Every unexpected error exit in the function records the failure through a resolved logging "
                "facility, directly or in the resolved caller.",
        contradiction="A resolved unexpected error exit is silent in the function and in every resolved caller.",
        satisfied=("Cited source shows the log call on each unexpected error path or in its resolved caller.",),
        not_satisfied=("Cited source shows an unexpected error path with no log call in the function or its "
                       "resolved callers.",
                       "The error exit and the callers are both cited."),
    ),
    _procedure(
        "V16.4.1",
        "Verify that all logging components appropriately encode data to prevent log injection.",
        c.LOG_SINK,
        invariant="Client-influenced text reaches the log only through a literal format and after encoding or "
                  "bounding.",
        subject_scope="One complete logging function or a function that calls one.",
        prerequisites=_LOG_PREREQUISITES,
        questions=_LOG_QUESTIONS,
        support="The log call uses a literal format, and client text is encoded (newlines, control characters) "
                "or bounded before the write.",
        contradiction="A resolved path writes client-influenced text as the format or unencoded into the log.",
        satisfied=("Cited source shows the literal format and the encoding or bound on each client-influenced "
                   "value at the named write.",),
        not_satisfied=("Cited source traces unencoded client text, or client text as the format, into the named "
                       "write.",
                       "The provenance and the write are both cited."),
    ),
    _procedure(
        "V16.5.1",
        "Verify that a generic message is returned to the consumer when an unexpected or security-sensitive "
        "error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, "
        "secret keys, and tokens.",
        c.ERROR_PATH,
        invariant="The named function's error exits expose no internal detail to the consumer.",
        subject_scope="One complete function with error exits.",
        prerequisites=_ERROR_PREREQUISITES,
        questions=_ERROR_QUESTIONS,
        support="Each error exit returns or sends a generic status and no internal path, errno text, buffer "
                "contents or secret.",
        contradiction="A resolved error path sends internal detail (paths, errno text, memory contents, secrets) "
                      "to the consumer.",
        satisfied=("Cited source shows each error exit's consumer-visible output to be generic.",
                   "Material callers that translate the error for the consumer are resolved."),
        not_satisfied=("Cited source shows internal detail sent to the consumer on a resolved error path.",
                       "The error exit and the send are both cited."),
    ),
    _procedure(
        "V16.5.3",
        "Verify that the application fails gracefully and securely, including when an exception occurs, "
        "preventing fail-open conditions such as processing a transaction despite errors resulting from "
        "validation logic.",
        c.ERROR_PATH,
        invariant="Each error exit of the named function stops the operation and leaves no acquired resource or "
                  "partial state behind.",
        subject_scope="One complete function with error exits.",
        prerequisites=_ERROR_PREREQUISITES,
        questions=_ERROR_QUESTIONS,
        support="Every error exit releases what the function acquired and the caller does not continue the "
                "operation on the error value.",
        contradiction="A resolved error path leaks or corrupts state, or the caller proceeds as if the operation "
                      "succeeded.",
        satisfied=("Cited control flow shows release and a stopping error value on each error path, and the "
                   "resolved caller honours it.",),
        not_satisfied=("Cited source shows a fail-open continuation or a leaked/corrupted resource on a resolved "
                       "error path.",
                       "The error exit and the continuation are both cited."),
    ),
)

C_CONTROL_FAMILIES: Mapping[str, str] = {item["control"]: item["recognizer"] for item in C_PROCEDURE_FIELDS}
