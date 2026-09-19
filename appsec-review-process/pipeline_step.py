"""Separate-stream compatibility adapter for explicitly invoked legacy pipeline steps."""
import argparse
from pathlib import Path
from execution_state import execute, emergency


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--logs', required=True); p.add_argument('--cwd', required=True)
    p.add_argument('--timeout', type=int, default=3600)
    p.add_argument('argv', nargs=argparse.REMAINDER)
    a = p.parse_args()
    try:
        result = execute(a.argv[1:] if a.argv[:1] == ['--'] else a.argv, Path(a.cwd), Path(a.logs), a.timeout)
        return 1 if result.get('error') else (result['exit_code'] or 0)
    except Exception as exc:
        emergency(exc); return 1


if __name__ == '__main__':
    raise SystemExit(main())
