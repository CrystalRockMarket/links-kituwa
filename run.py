#!/usr/bin/env python3
"""Web entry point: python run.py [--host H] [--port P]."""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Secret Link")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args(argv)

    from app.config import load_settings
    from app.httpd import create_app

    settings = load_settings()
    if args.host or args.port:
        settings = replace(settings, host=args.host or settings.host,
                           port=args.port or settings.port)
    app = create_app(settings)
    from waitress import serve
    serve(app, host=settings.host, port=settings.port, threads=8, channel_timeout=120)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
