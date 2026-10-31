#!/usr/bin/env sh
# Vendoring check: bin/<pkg>/ must be a VERBATIM copy of the upstream package at the commit VENDORED.md
# records. Usage: check_vendored.sh <repo-url> <commit> <upstream-dir>:<vendored-dir> [...]
# Exits non-zero on any byte difference (ignoring __pycache__ / *.pyc), so an edit made here instead of
# upstream, or a half-done re-vendor, fails the build.
set -eu
url="$1"; sha="$2"; shift 2
[ -n "$sha" ] || { echo "check_vendored: no commit recorded in VENDORED.md for $url" >&2; exit 2; }
work=$(mktemp -d)
# FULL clone on purpose: VENDORED.md records a short SHA, which a --depth 1 clone cannot resolve.
git clone --quiet "$url" "$work/up"
git -C "$work/up" checkout --quiet "$sha"
rc=0
for pair in "$@"; do
  src="${pair%%:*}"; dst="${pair#*:}"
  if diff -r -q -x __pycache__ -x '*.pyc' "$work/up/$src" "$dst"; then
    echo "ok: $dst == $url@$sha:$src"
  else
    echo "DRIFT: $dst differs from $url@$sha:$src (fix upstream, then re-vendor)" >&2; rc=1
  fi
done
exit $rc
