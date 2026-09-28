"""Entry point: ``python main.py scan <file_or_directory>``."""

import sys

from app.cli import main

if __name__ == "__main__":
    sys.exit(main())
