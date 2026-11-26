#!/usr/bin/env python3
"""Build a deterministic, signed release of links.kituwa.com.

The artifact is ``git archive`` of HEAD, which is byte-identical for the same
commit on any machine. The manifest lists a SHA-256 for every file and one root
hash, and is signed with an Ed25519 key that never leaves the operator's
machine. Anyone can rebuild the artifact from the public commit and compare.

    tools/build_release.py [--dist dist] [--key ~/.config/links-kituwa/release.key]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEY = Path.home() / ".config" / "links-kituwa" / "release.key"
REPO_URL = "https://github.com/CrystalRockMarket/links-kituwa"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(files: dict[str, str]) -> str:
    body = "".join(f"{files[path]}  {path}\n" for path in sorted(files))
    return hashlib.sha256(body.encode()).hexdigest()


def ensure_key(path: Path) -> Path:
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)],
                   check=True, capture_output=True)
    path.chmod(0o600)
    print(f"created a new release key at {path} — back it up, it signs every release")
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", default=str(ROOT / "dist"))
    parser.add_argument("--key", default=str(DEFAULT_KEY))
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args(argv)

    if git("status", "--porcelain") and not args.allow_dirty:
        print("working tree is dirty; commit first so the artifact matches a commit",
              file=sys.stderr)
        return 2

    commit = git("rev-parse", "HEAD")
    short = commit[:7]
    commit_date = git("show", "-s", "--format=%cI", commit)
    version = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "0.0.0"
    dist = Path(args.dist).resolve()
    dist.mkdir(parents=True, exist_ok=True)

    tarball = f"links-kituwa-{version}-{short}.tar.gz"
    target = dist / tarball
    with target.open("wb") as fh:
        subprocess.run(["git", "archive", "--format=tar.gz",
                        "--prefix=links-kituwa/", commit], cwd=ROOT, check=True, stdout=fh)

    listing = git("ls-tree", "-r", "--full-tree", commit)
    files: dict[str, str] = {}
    for line in listing.splitlines():
        meta, path = line.split("\t", 1)
        mode, kind, obj = meta.split()
        if kind != "blob":
            continue
        blob = subprocess.run(["git", "cat-file", "blob", obj], cwd=ROOT,
                              check=True, capture_output=True).stdout
        files[path] = hashlib.sha256(blob).hexdigest()

    manifest = {
        "schema": 1,
        "project": "links-kituwa",
        "version": version,
        "commit": commit,
        "commit_short": short,
        "commit_date": commit_date,
        "built_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repo": REPO_URL,
        "tarball": tarball,
        "sha256": sha256_file(target),
        "size": target.stat().st_size,
        "tree": tree_hash(files),
        "files": files,
    }
    manifest_path = dist / "release.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    key = ensure_key(Path(args.key))
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin",
                    "-in", str(manifest_path), "-out", str(dist / "release.json.sig")],
                   check=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout",
                    "-out", str(dist / "release.pub")], check=True)

    print(f"artifact   {target}  ({manifest['size']} bytes)")
    print(f"sha256     {manifest['sha256']}")
    print(f"tree       {manifest['tree']}")
    print(f"commit     {commit}")
    print(f"manifest   {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
