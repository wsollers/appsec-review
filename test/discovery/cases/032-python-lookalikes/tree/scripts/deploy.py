import sys


def main() -> int:
    print("deploy", sys.argv[1:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
