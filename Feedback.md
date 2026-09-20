## [P2] Make the symlink cases runnable on supported Windows hosts

The focused suite fails before it exercises the consumer in every symlink scenario when the Windows account does not have symlink-creation privilege. `s_blob_symlink`, `s_snapshot_dir_symlink`, and `s_pointer_symlink` call `Path.symlink_to()` directly (`appsec-review-process/tests/test_sca_nvd_snapshot.py:199`, `:210`, and `:217`), and the parity test does the same at line 841. On a normal Windows checkout these raise `OSError: [WinError 1314]`, causing six failures: the three generated scenarios plus the invariant sweep, no-network sweep, and parity test.

Probe symlink capability once and skip only the link-dependent cases when unavailable (or provide an equivalent Windows-safe setup). The focused test file should pass on the repository's supported Windows workflow without requiring an elevated shell or Developer Mode.
