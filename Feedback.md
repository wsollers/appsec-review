## [P2] Make fixture newline expectations independent of Git checkout conversion

The redactor intentionally preserves input bytes, but two acceptance tests assume that tracked text fixtures are always checked out with LF endings. With the common Windows setting `core.autocrlf=true`, Git converts those fixtures to CRLF and the focused suite fails at `appsec-review-process/tests/test_evidence_redaction.py:439` and `:570`, even though the output correctly preserves the fixture bytes. The result here is 2 failed, 63 passed, and 3 skipped.

Either pin these fixtures to LF in `.gitattributes` or derive the assertions from the fixture's actual newline convention. The focused suite should pass on a standard Windows checkout while retaining the explicit byte-preservation checks for generated CRLF and LF inputs.
