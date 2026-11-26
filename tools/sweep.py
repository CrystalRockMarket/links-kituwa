#!/usr/bin/env python3
"""Delete spent and expired link content. Run every minute by a timer.

The app also runs this in a background thread; the timer is the belt to that
brace, and the only copy on a host where the thread is disabled.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, store  # noqa: E402
from app.config import load_settings  # noqa: E402


def main() -> int:
    settings = load_settings()
    conn = db.connect(db.db_path(settings.data_dir))
    try:
        result = store.sweep(conn)
    finally:
        conn.close()
    print(" ".join(f"{k}={v}" for k, v in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
