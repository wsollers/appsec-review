"""``python -m appsec_review ...`` is the command line inside the application container, where the
``appsec-review`` console script is not installed (the package is mounted on ``PYTHONPATH``)."""

import sys

from appsec_review.cli import main

if __name__ == "__main__":
    sys.exit(main())
