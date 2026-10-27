"""Allow ``python -m litaudit``."""

import sys

from .cli import run

sys.exit(run())
