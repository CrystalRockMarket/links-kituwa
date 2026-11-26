#!/usr/bin/env python3
"""Check a deployed tree or a tarball against a signed release manifest.

    tools/verify_release.py --manifest dist/release.json --dir /path/to/current
    tools/verify_release.py --manifest dist/release.json --tarball dist/x.tar.gz

Exits 0 only when every file in the manifest is present with the same SHA-256
and the recomputed tree hash matches. With ``--write-state`` it writes a small
``state.json`` next to the manifest for the /verify page.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

IGNORE_DIRS = {".git", ".venv", "__pycache__", "data", "dist", "releases",
               "node_modules", ".pytest_cache"}
IGNORE_SUFFIX = {".pyc", ".secret", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm",
                 ".log", ".eml"}
IGNORE_NAMES = {"secret.key", "current"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(files: dict[str, str]) -> str:
    body = "".join(f"{files[path]}  {path}\n" for path in sorted(files))
    return hashlib.sha256(body.encode()).hexdigest()


def walk(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in IGNORE_DIRS for part in rel.parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in IGNORE_NAMES or path.suffix in IGNORE_SUFFIX:
            continue
        found[str(rel)] = sha256_bytes(path.read_bytes())
    return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--dir")
    parser.add_argument("--tarball")
    parser.add_argument("--write-state", action="store_true")
    args = parser.parse_args(argv)

    manifest = json.loads(Path(args.manifest).read_text())
    expected: dict[str, str] = manifest["files"]

    if args.tarball:
        tmp = Path(tempfile.mkdtemp())
        with tarfile.open(args.tarball) as tar:
            tar.extractall(tmp, filter="data")
        root = next(p for p in tmp.iterdir() if p.is_dir())
        actual = walk(root)
    elif args.dir:
        root = Path(args.dir)
        actual = walk(root)
    else:
        print("give --dir or --tarball", file=sys.stderr)
        return 2

    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(p for p in set(expected) & set(actual) if expected[p] != actual[p])

    ok = not (missing or changed)
    tree = tree_hash({p: actual[p] for p in expected if p in actual})

    print(f"commit        {manifest.get('commit', '?')}")
    print(f"version       {manifest.get('version', '?')}")
    print(f"files         {len(expected)} expected, {len(actual)} present")
    print(f"tree          {tree}")
    print(f"expected tree {manifest.get('tree')}")
    if missing:
        print("MISSING       " + ", ".join(missing[:10]))
    if changed:
        print("CHANGED       " + ", ".join(changed[:10]))
    if extra:
        print(f"extra files   {len(extra)} (not in the manifest)")
    print("RESULT        " + ("MATCH" if ok and tree == manifest.get("tree") else "MISMATCH"))

    if args.write_state:
        state = {
            "tree": tree,
            "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "files_checked": len(expected),
            "missing": len(missing),
            "changed": len(changed),
            "unexpected": len(extra),
            "match": bool(ok and tree == manifest.get("tree")),
            "commit": manifest.get("commit"),
            "version": manifest.get("version"),
        }
        out = Path(args.manifest).with_name("state.json")
        out.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        print(f"state         {out}")

    return 0 if ok and tree == manifest.get("tree") else 1


if __name__ == "__main__":
    raise SystemExit(main())
