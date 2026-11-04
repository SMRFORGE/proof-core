"""``python -m proof_core <seal|verify|reproduce> [args...]`` -- a thin dispatcher to the three CLIs.

Handy when the source is VENDORED (copied into another tree, e.g. a plugin) rather than ``pip install``-ed,
so the ``proof-seal`` / ``proof-verify`` / ``proof-reproduce`` console-script entry points are not on PATH.
Each verb's CLI is imported LAZILY inside its branch, so ``seal``/``reproduce`` never import ``proof_verify``
unless ``verify`` is asked for (the verify CLI lives in the sibling ``proof_verify`` package)."""
from __future__ import annotations

import sys

_USAGE = "usage: python -P -m proof_core <seal|verify|reproduce|policy> [args...]"
_HELP = (
    _USAGE + "\n\n"
    "  seal       seal a pre-computed result (inputs + outputs JSON) into a signed bundle\n"
    "  verify     independently verify a bundle (integrity + origin); --json for a machine verdict\n"
    "  reproduce  re-derive a bundle's numbers with the open engine; --json for a machine verdict\n"
    "  policy     explain a receiver policy (its policy_sha256, what it requires) or init one from a preset\n\n"
    "-P matters: under -m Python puts the current directory first on the import path, so a planted\n"
    "proof_verify/ or profile module there would win over the installed one.\n\n"
    "run `python -P -m proof_core <verb> --help` for that verb's own options.")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(_USAGE, file=sys.stderr)
        return 2
    verb, rest = argv[0], argv[1:]
    if verb in ("-h", "--help"):
        print(_HELP)
        return 0
    if verb == "seal":
        from .seal_cli import main as seal_main
        return seal_main(rest)
    if verb == "reproduce":
        from .reproduce_cli import main as reproduce_main
        return reproduce_main(rest)
    if verb == "verify":
        from proof_verify.__main__ import main as verify_main
        return verify_main(rest)
    if verb == "policy":
        from proof_verify.policy_cli import main as policy_main
        return policy_main(rest)
    print(f"error: unknown verb {verb!r}; use one of seal | verify | reproduce | policy", file=sys.stderr)
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
