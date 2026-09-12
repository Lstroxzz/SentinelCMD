"""Convenience launcher: python sentinel.py."""

import sys

if sys.version_info < (3, 12):
    raise SystemExit("SentinelCMD requer Python 3.12 ou superior.")

try:
    from sentinelcmd.cli import main
except ModuleNotFoundError as exc:
    if exc.name == "psutil":
        raise SystemExit("Instale as dependencias: python -m pip install -e .") from exc
    raise

if __name__ == "__main__":
    raise SystemExit(main())
