"""Cross-platform fault injection for the bounded deterministic-child contract."""
from pathlib import Path
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deterministic_child as child


class DeterministicChildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def spec(self, code: str, name: str, *, timeout: float = 5,
             limit: int = 65536, extra: tuple[str, ...] = ()) -> child.ChildExecutionSpec:
        executable = Path(sys.executable).resolve()
        argv = (str(executable), "-B", "-c", code, *extra)
        return child.ChildExecutionSpec(
            argv=argv, argv_prefix=argv[:3], executable=executable, cwd=self.root,
            owner_root=self.root, log_dir=self.root / name, timeout_seconds=timeout,
            stdout_limit_bytes=limit, stderr_limit_bytes=limit,
            env={**{key: value for key, value in os.environ.items()
                    if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"}},
                 "PYTHONDONTWRITEBYTECODE": "1"})

    def test_argv_contract_rejects_shell_and_prefix_changes(self):
        spec = self.spec("print('ok')", "valid")
        child.validate_spec(spec)
        shell = Path(os.environ.get("COMSPEC", "cmd.exe") if os.name == "nt" else "/bin/sh").resolve()
        bad = child.ChildExecutionSpec(
            argv=(str(shell), "-c", "echo unsafe"), argv_prefix=(str(shell),),
            executable=shell, cwd=self.root, owner_root=self.root,
            log_dir=self.root / "shell", timeout_seconds=1,
            stdout_limit_bytes=1024, stderr_limit_bytes=1024, env={})
        with self.assertRaisesRegex(ValueError, "shell executables"):
            child.validate_spec(bad)
        changed = child.ChildExecutionSpec(**{**spec.__dict__, "argv_prefix": (spec.argv[0], "-m")})
        with self.assertRaisesRegex(ValueError, "prefix"):
            child.validate_spec(changed)

    def test_concurrent_pressure_is_drained_and_retained_logs_are_bounded(self):
        code = ("import sys,threading;"
                "a=threading.Thread(target=lambda:sys.stdout.buffer.write(b'O'*2097152));"
                "b=threading.Thread(target=lambda:sys.stderr.buffer.write(b'E'*2097152));"
                "a.start();b.start();a.join();b.join()")
        result = child.execute_child(self.spec(code, "pressure", limit=32768))
        self.assertEqual(result["exit_code"], 0)
        for name, expected in (("stdout", b"O"), ("stderr", b"E")):
            record = result["streams"][name]
            self.assertEqual(record["observed_bytes"], 2097152)
            self.assertEqual(record["written_bytes"], 32768)
            self.assertTrue(record["truncated"])
            data = (self.root / "pressure" / f"{name}.log").read_bytes()
            self.assertEqual((len(data), set(data)), (32768, {expected[0]}))

    def test_timeout_and_cancellation_kill_descendant_tree(self):
        descendant = ("import pathlib,sys,time;time.sleep(1);"
                      "pathlib.Path(sys.argv[1]).write_text('escaped')")
        parent = ("import subprocess,sys,time;"
                  "subprocess.Popen([sys.executable,'-B','-c',sys.argv[1],sys.argv[2]]);"
                  "print('ready',flush=True);time.sleep(30)")
        timeout_marker = self.root / "timeout-escaped"
        timed = child.execute_child(self.spec(
            parent, "timeout", timeout=.2, extra=(descendant, str(timeout_marker))))
        self.assertTrue(timed["timed_out"])
        cancel_marker = self.root / "cancel-escaped"
        cancel = threading.Event()
        timer = threading.Timer(.2, cancel.set)
        timer.start()
        cancelled = child.execute_child(self.spec(
            parent, "cancel", extra=(descendant, str(cancel_marker))), cancel=cancel)
        timer.join()
        self.assertTrue(cancelled["cancelled"])
        time.sleep(1.1)
        self.assertFalse(timeout_marker.exists())
        self.assertFalse(cancel_marker.exists())

    def test_child_loss_is_recorded_without_false_success(self):
        result = child.execute_child(self.spec(
            "import os,sys;print('before loss',flush=True);"
            "print('diagnostic',file=sys.stderr,flush=True);os._exit(23)", "loss"))
        self.assertEqual(result["exit_code"], 23)
        self.assertFalse(result["timed_out"])
        self.assertIn(b"before loss", (self.root / "loss/stdout.log").read_bytes())
        self.assertIn(b"diagnostic", (self.root / "loss/stderr.log").read_bytes())

    def test_log_write_failure_fails_closed_and_stops_child(self):
        original = child._write_log_chunk
        calls = 0

        def fail_once(stream, chunk):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise PermissionError("injected log write failure")
            return original(stream, chunk)

        with patch.object(child, "_write_log_chunk", side_effect=fail_once):
            result = child.execute_child(self.spec(
                "import sys,time;print('trigger',flush=True);time.sleep(30)", "log-failure"))
        self.assertIn("diagnostic stream failure", result["error"])
        self.assertNotEqual(result["exit_code"], 0)
        self.assertTrue((self.root / "log-failure/command.json").is_file())

    def test_keyboard_interrupt_is_persisted_then_propagated(self):
        real_sleep = time.sleep
        calls = 0

        def interrupt(_seconds):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt("fixture cancellation")
            real_sleep(0.01)

        spec = self.spec("import time;time.sleep(30)", "keyboard")
        with patch.object(child.time, "sleep", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                child.execute_child(spec)
        record = (self.root / "keyboard/command.json").read_text(encoding="utf-8")
        self.assertIn('"cancelled": true', record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
