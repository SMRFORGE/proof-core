"""Report CI images whose pinned digest is no longer what the tag points to (a newer image is out).

    python tools/check_image_pins.py .gitlab-ci.yml

Reads every `image: NAME:TAG@sha256:...` line, asks Docker Hub what NAME:TAG resolves to now, and prints one
line per image. Exit 1 if any pin is stale (run it from a scheduled, non-blocking CI job), 0 if all are current.
Standard library only; it fetches nothing but the registry's public manifest digests.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import urllib.request

PIN = re.compile(r"\b([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})")
ACCEPT = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
          "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")


def current_digest(name: str, tag: str) -> str:
    repo = name if "/" in name else f"library/{name}"
    token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    with urllib.request.urlopen(token_url, timeout=30) as r:
        token = json.load(r)["token"]
    req = urllib.request.Request(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", method="HEAD",
                                 headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.headers["Docker-Content-Digest"]


def main(paths: list[str]) -> int:
    pins = sorted({m.groups() for p in paths for m in PIN.finditer(pathlib.Path(p).read_text(encoding="utf-8"))})
    if not pins:
        print("no digest-pinned images found")
        return 0
    stale = 0
    for name, tag, pinned in pins:
        try:
            now = current_digest(name, tag)
        except Exception as exc:  # noqa: BLE001 -- a registry hiccup is reported, not fatal for the others
            print(f"?     {name}:{tag}  could not check ({type(exc).__name__}: {exc})")
            stale += 1
            continue
        if now == pinned:
            print(f"ok    {name}:{tag}")
        else:
            stale += 1
            print(f"STALE {name}:{tag}  pinned {pinned[:19]}...  now {now}")
    if stale:
        print(f"\n{stale} pin(s) to refresh: replace the digest after `@` with the 'now' value above.")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or [".gitlab-ci.yml"]))
