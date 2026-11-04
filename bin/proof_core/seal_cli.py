"""``proof-seal`` -- seal a PRE-COMPUTED result into a signed, tamper-evident evidence bundle from the
command line.

proof-core's SEAL verb is a library call (``build_bundle``): a producer that holds the Case/Result in
Python seals in-process. This CLI is the AGENT / SHELL use case -- a step (an agent, a CI job, a plugin)
has already computed a result and written its inputs and outputs as JSON, and wants a bundle WITHOUT
writing Python. It reads those JSON files, builds the Case + Result, and emits the bundle.

It changes NOTHING about the trust model. The signing identity is whatever the process is configured with:
the PUBLIC DEMO key by DEFAULT (so ``proof-verify`` reads integrity-only, never a production origin), or a
production identity supplied out-of-band via ``PROOF_SIGNING_SEED`` (a secret manager / air-gapped machine;
see proof_core.signing). This CLI never takes a key on the command line and never wires a hardware key.

Exit codes:
  0  sealed -- the bundle was written (to --output, else stdout).
  2  usage error, or an input/output JSON file could not be read, parsed, or sealed.
"""
from __future__ import annotations

import argparse
import json
import sys

from proof_verify import _spec_loader

from .contract import Case, Fidelity, Result, Verdict
from .envelope import build_bundle

#: the JSON `kind` discriminator for a `proof-seal --json` summary (lets an agent tell verdict shapes apart).
SEAL_RESULT_KIND = "proof_core.seal_result.v1"


def _resolve_profile(spec: str):
    """Import a reviewer-named ``pkg.module:attr`` dialect Profile (a class is instantiated with no args; a
    constructed Profile is used as-is). Reads ONLY the command-line ``spec``. Raises ValueError on failure.
    Mirrors the resolver in ``reproduce_cli`` / ``proof_verify.__main__``."""
    module_name, attr_path = _spec_loader.split_spec(spec, "--profile", "pkg.module:attr")
    try:  # never the cwd: a module from the normal import path, or an absolute /abs/path/file.py
        obj = _spec_loader.import_spec_module(module_name, "profile")
    except ImportError as exc:
        raise ValueError(f"cannot import profile module {module_name!r}: {exc}") from exc
    except Exception as exc:
        raise ValueError(
            f"profile module {module_name!r} failed to import: {type(exc).__name__}: {exc}") from exc
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise ValueError(f"profile {spec!r} not found: {exc}") from exc
    try:
        return obj() if isinstance(obj, type) else obj
    except Exception as exc:
        raise ValueError(f"cannot construct profile {spec!r}: {type(exc).__name__}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="proof-seal",
        description="Seal a pre-computed result (inputs + outputs JSON) into a signed evidence bundle.",
        epilog="signing identity: the PUBLIC DEMO key by default (proof-verify then reads integrity-only, "
               "NOT a production origin pass); a production key is injected out-of-band via PROOF_SIGNING_SEED "
               "(see proof_core.signing). This CLI never takes a key on the command line.")
    p.add_argument("--capability", required=True,
                   help="the capability string (its (capability, inputs) pair is the deterministic identity)")
    p.add_argument("--engine", required=True, help="the engine / tool that produced the result")
    p.add_argument("--engine-version", required=True, help="the engine / tool version")
    p.add_argument("--inputs", required=True, metavar="inputs.json",
                   help="path to a JSON object of the capability's inputs")
    p.add_argument("--outputs", required=True, metavar="outputs.json",
                   help="path to a JSON object of the result's outputs")
    p.add_argument("--verdict", choices=[v.value for v in Verdict], default=Verdict.PASS.value,
                   help="the result verdict (default: pass)")
    p.add_argument("--fidelity", choices=[f.value for f in Fidelity], default=Fidelity.SCREENING.value,
                   help="the result fidelity (default: screening)")
    p.add_argument("--caveat", action="append", default=[], metavar="TEXT",
                   help="a caveat string, repeatable")
    p.add_argument("--provenance", metavar="prov.json",
                   help="path to a JSON object of run-scoped provenance pins (OS-independent facts only)")
    p.add_argument("--data-label", metavar="ID",
                   help="identifier of the data set this run read (must be given with --data-sha)")
    p.add_argument("--data-sha", metavar="sha256:HEX",
                   help="content hash of the data set this run read (must be given with --data-label)")
    p.add_argument("--tolerance", metavar="tol.json",
                   help="path to a JSON reproduce_tolerance for a stochastic producer (sampled run/model)")
    p.add_argument("--profile", metavar="pkg.module:attr",
                   help="mint under this dialect Profile (duck-typed); None -> the neutral evidence.* dialect. "
                        "Imported from the import path (PYTHONPATH / installed), never the current directory; "
                        "or name a file by absolute path, /abs/path/file.py:attr")
    p.add_argument("-o", "--output", metavar="bundle.json",
                   help="write the bundle here (default: stdout)")
    p.add_argument("--json", action="store_true",
                   help="emit a JSON summary {kind, bundle_sha256, demo_identity, output_path, capability, "
                        "verdict, fidelity} to stdout (requires -o, since stdout then carries the summary)")
    return p


def _load_json_object(path: str, flag: str):
    with open(path, encoding="utf-8") as fh:
        obj = json.load(fh)
    if not isinstance(obj, dict):
        # ValueError (not TypeError) on purpose: main() maps a bad JSON argument to exit 2 via
        # `except (OSError, ValueError)`, so this malformed-shape case must be a ValueError too.
        raise ValueError(f"{flag} must be a JSON object (got {type(obj).__name__})")  # noqa: TRY004
    return obj


def main(argv: list[str] | None = None) -> int:
    from . import signing  # read-only: only to word the demo-vs-production note honestly

    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        ns = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse usage error (-> 2) or --help (-> 0)
        return int(exc.code) if exc.code is not None else 2

    if (ns.data_label is None) != (ns.data_sha is None):
        print("error: --data-label and --data-sha must be given together", file=sys.stderr)
        return 2

    if ns.json and not ns.output:
        print("error: --json requires -o/--output (stdout carries the JSON summary, so the bundle needs a "
              "file)", file=sys.stderr)
        return 2

    profile = None
    if ns.profile is not None:
        try:
            profile = _resolve_profile(ns.profile)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        inputs = _load_json_object(ns.inputs, "--inputs")
        outputs = _load_json_object(ns.outputs, "--outputs")
        provenance = _load_json_object(ns.provenance, "--provenance") if ns.provenance else {}
        tolerance = None
        if ns.tolerance:
            with open(ns.tolerance, encoding="utf-8") as fh:
                tolerance = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read a JSON argument: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    case = Case(capability=ns.capability, inputs=inputs)
    result = Result(
        capability=ns.capability,
        fidelity=Fidelity(ns.fidelity),
        verdict=Verdict(ns.verdict),
        outputs=outputs,
        caveats=tuple(ns.caveat),
        provenance=provenance,
        reproduce_tolerance=tolerance,
    )
    try:
        bundle = build_bundle(
            case, result,
            engine=ns.engine, engine_version=ns.engine_version,
            data_library=((ns.data_label, ns.data_sha) if ns.data_label is not None else None),
            profile=profile,
        )
    except Exception as exc:  # noqa: BLE001 -- a bad tolerance/profile is a seal-time arg error, not a crash
        print(f"error: could not seal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(bundle, sort_keys=True)
    if ns.output:
        try:
            with open(ns.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"error: cannot write {ns.output!r}: {exc}", file=sys.stderr)
            return 2
    else:
        print(text)

    demo_identity = signing.is_demo_identity()
    if ns.json:
        # machine summary to stdout (the bundle went to --output, required under --json). `demo_identity`
        # is the honesty bit: True means proof-verify reads integrity-only, NOT a production origin pass.
        print(json.dumps({"kind": SEAL_RESULT_KIND, "bundle_sha256": bundle["bundle_sha256"],
                          "demo_identity": demo_identity, "output_path": ns.output,
                          "capability": ns.capability, "verdict": ns.verdict, "fidelity": ns.fidelity},
                         sort_keys=True))
        return 0
    note = ("signed under the PUBLIC DEMO identity -- proof-verify will read integrity-only, NOT a production "
            "origin pass" if demo_identity else "signed under an injected production identity")
    print(f"sealed {bundle['bundle_sha256']} ({note})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
