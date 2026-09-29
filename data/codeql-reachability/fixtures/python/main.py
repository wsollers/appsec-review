"""Smoke fixture: vulnlib stands in for a PyPI dependency with an advisory on parse."""
import sys

import vulnlib


def handle(value):
    return vulnlib.parse(value)


if __name__ == "__main__":
    print(handle(sys.argv[1]))
