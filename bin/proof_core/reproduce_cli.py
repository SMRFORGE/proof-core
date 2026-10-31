"""``proof-reproduce <bundle.json> --runner pkg.module:ClassName`` / ``--command "<cmd>"`` --
re-derive a sealed bundle's numbers with the OPEN engine and print a plain verdict.

``reproduce`` is proof-core's real differentiator: verify answers "was this record edited and whose
key signed it" using NO domain code; reproduce answers "do these numbers actually fall out of the code,
or were they just asserted" by RE-RUNNING the producer on the bundle's own sealed inputs and checking
the result core comes back identical (or, for a stochastic producer, inside the sealed statistical band).
This CLI makes that a first-class, no-container step.

Two ways to name the re-run, BOTH supplied by the reviewer on the command line (never read from the
bundle -- see SECURITY):

  --runner pkg.module:ClassName
      Import that object and use it as a ``proof_core.contract.ReproduceRunner`` (two methods:
      ``can_run(capability)`` and ``run(capability, inputs)``). A class is instantiated with no args; an
      already-constructed runner (e.g. a function decorated with ``proof_core.sealed``) is used as-is. The
      reviewer points this at the SAME producer that minted the bundle.

  --command "<cmd>"
      A built-in subprocess runner, so a reviewer can reproduce with their OWN installed tool and no
      adapter code. The contract (also in --help):
        1. the bundle's sealed case ``{"capability", "inputs"}`` is written as JSON to a fresh temp dir;
           the path is handed to the command in the env var ``PROOF_INPUTS``.
        2. ``<cmd>`` is run with that temp dir as its working directory (``shell=True``). It must not rely
           on the network; it reads ``PROOF_INPUTS`` and recomputes the result.
        3. the command writes the recomputed OUTPUTS -- a JSON object of the capability's output keys,
           the same shape as the sealed ``result[<capability>]`` -- to the path in ``PROOF_OUTPUT``.
        4. those fresh outputs are spliced onto the sealed bundle's shape (same inputs, fidelity, verdict,
           tolerance and provenance pins) and fed into the SAME comparison as --runner.

SECURITY (hard line): the CLI NEVER imports or executes anything named ONLY inside the bundle. The
capability string, the inputs, and every other field in the bundle are treated strictly as DATA. The only
code the CLI runs is what the reviewer named on the command line (``--runner`` target or ``--command``).
So a hostile bundle cannot cause code execution merely by being pointed at -- see
``tests/test_reproduce_cli.py::test_bundle_alone_cannot_cause_code_execution``.

Exit codes:
  0  reproduced -- the sealed numbers re-derive from the open run (within the sealed band if stochastic).
  1  NOT reproduced, or verify failed (the bundle's integrity does not hold, so it is never re-run).
  2  usage error, or the bundle file could not be read / parsed, or the --runner target is unusable.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile

from .certify import ReproduceError, reproduce_bundle
from .contract import Case, Fidelity, ReproduceRunner, Result, Verdict
from .envelope import build_bundle

EXIT_REPRODUCED = 0
EXIT_NOT_REPRODUCED = 1          # also: verify failed (a bundle whose integrity fails is never re-run)
EXIT_USAGE = 2                   # usage / unreadable bundle / unusable --runner target

#: env vars naming the input/output JSON files for the built-in --command runner (the documented contract).
ENV_INPUTS = "PROOF_INPUTS"
ENV_OUTPUT = "PROOF_OUTPUT"

#: the JSON `kind` discriminator for a reproduce verdict, so an agent can tell verdict shapes apart and
#: detect schema evolution. Bump the trailing version if the reproduce JSON contract changes shape.
REPRODUCE_VERDICT_KIND = "proof_core.reproduce_verdict.v1"


# --------------------------------------------------------------------------------------------------- #
# runner resolution -- the ONLY code the CLI runs is what the reviewer named here, never a bundle field
# --------------------------------------------------------------------------------------------------- #
def _resolve_runner(spec: str) -> ReproduceRunner:
    """Import the reviewer-named ``pkg.module:attr`` (dotted ``attr`` allowed) and return a ReproduceRunner.

    A class is instantiated with no args; an already-constructed runner object (e.g. a ``@sealed`` function,
    which IS a runner) is used as-is. Raises ValueError with a plain reason if the spec is malformed, the
    import fails, or the resolved object is not a ReproduceRunner. This reads ONLY the command-line ``spec``;
    it never consults the bundle."""
    if ":" not in spec:
        raise ValueError(f"--runner must be 'pkg.module:ClassName' (got {spec!r})")
    module_name, _, attr_path = spec.partition(":")
    if not module_name or not attr_path:
        raise ValueError(f"--runner must be 'pkg.module:ClassName' (got {spec!r})")
    # The `proof-reproduce` console-script entry point puts the launcher's bin directory on sys.path[0], NOT
    # the current directory -- so `--runner mymodule:ClassName` for a module in the cwd would fail to import,
    # unlike `python -m proof_core.reproduce_cli` (which adds the cwd). The runner is a deliberate,
    # command-line-named target (never a bundle field), so make the cwd importable here to match `-m`.
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        obj = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"cannot import runner module {module_name!r}: {exc}") from exc
    except SystemExit as exc:  # a module that calls sys.exit() at import is an unusable --runner arg
        raise ValueError(
            f"runner module {module_name!r} called sys.exit() at import ({exc})") from exc
    except Exception as exc:  # any import-time failure is a bad --runner arg, not a CLI crash
        raise ValueError(
            f"runner module {module_name!r} failed to import: {type(exc).__name__}: {exc}") from exc
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise ValueError(f"runner {spec!r} not found: {exc}") from exc
    # a class object also carries can_run/run as attributes, so instantiate BEFORE the Protocol check.
    # a __init__ that raises (needs args, fails setup) is an unusable --runner arg, not a CLI crash.
    try:
        runner = obj() if isinstance(obj, type) else obj
    except SystemExit as exc:
        raise ValueError(f"instantiating runner {spec!r} called sys.exit() ({exc})") from exc
    except Exception as exc:  # a runner whose __init__ raises is an unusable --runner arg, not a CLI crash
        raise ValueError(
            f"cannot instantiate runner {spec!r}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(runner, ReproduceRunner):
        # ValueError (not TypeError) on purpose: main() maps a bad --runner CLI arg to EXIT_USAGE via
        # `except ValueError`, so every failure of this resolver must be a ValueError.
        raise ValueError(  # noqa: TRY004
            f"runner {spec!r} is not a ReproduceRunner (needs can_run(capability) and run(capability, "
            "inputs)); name a ReproduceRunner class, or a function decorated with proof_core.sealed")
    return runner


def _resolve_profile(spec: str):
    """Import the reviewer-named ``pkg.module:attr`` dialect Profile and return it (a class is instantiated
    with no args; an already-constructed Profile is used as-is). Duck-typed: the verifier reads a profile
    attribute-only, so any object carrying the dialect fields works. Mirrors ``_resolve_runner`` -- it reads
    ONLY the command-line ``spec``, never the bundle, and raises ValueError with a plain reason on failure."""
    if ":" not in spec:
        raise ValueError(f"--profile must be 'pkg.module:attr' (got {spec!r})")
    module_name, _, attr_path = spec.partition(":")
    if not module_name or not attr_path:
        raise ValueError(f"--profile must be 'pkg.module:attr' (got {spec!r})")
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        obj = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"cannot import profile module {module_name!r}: {exc}") from exc
    except Exception as exc:  # any import-time failure is a bad --profile arg, not a CLI crash
        raise ValueError(
            f"profile module {module_name!r} failed to import: {type(exc).__name__}: {exc}") from exc
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise ValueError(f"profile {spec!r} not found: {exc}") from exc
    try:
        return obj() if isinstance(obj, type) else obj
    except Exception as exc:  # a Profile whose construction raises is a bad --profile arg, not a crash
        raise ValueError(f"cannot construct profile {spec!r}: {type(exc).__name__}: {exc}") from exc


# --------------------------------------------------------------------------------------------------- #
# the built-in --command runner: write sealed inputs, run the reviewer's tool, read the outputs back
# --------------------------------------------------------------------------------------------------- #
def _capability_of(bundle: dict) -> str | None:
    try:
        return bundle["manifest"]["inputs"]["value"]["capability"]
    except (KeyError, TypeError):
        return None


def _subject_canon_version(bundle: dict) -> int:
    """The subject's sealed canon_version when it is one this producer can mint, else 1 (a subject sealed under
    an unknown canon cannot have been verified intact, so the re-mint's comparison fails on its own)."""
    from .envelope import _CANON
    sv = (bundle.get("sha256sums") or {}).get("canon_version")
    return sv if type(sv) is int and sv in _CANON else 1


def _rebuild_with_outputs(bundle: dict, fresh_outputs: dict, profile=None) -> dict:
    """A fresh bundle that mirrors ``bundle`` but carries ``fresh_outputs`` in place of the sealed outputs.

    The sealed inputs, fidelity, verdict, caveats, reproduce_tolerance and provenance pins are copied from
    the subject so the only thing a reviewer's own tool supplies is the re-derived OUTPUTS; everything else
    is held to what the bundle committed to. The result is a genuine, freshly built+signed bundle the spine
    compares against the sealed one exactly as it would a --runner re-run."""
    manifest = bundle["manifest"]
    case_value = manifest["inputs"]["value"]
    capability = case_value["capability"]
    core = manifest["result"]["value"]
    prov = manifest["provenance"]["value"]
    # run-scoped provenance that mirrors the sealed shape (seed + producer). NOTE: the --command path runs
    # an EXTERNAL tool that returns only the recomputed outputs -- it cannot capture its own data
    # environment, so this fresh bundle must NOT assert that the sealed data pins were re-derived. Mark the
    # environment as not-captured so certify reports the data environment UNVERIFIABLE, rather than comparing
    # the sealed pins against copies of themselves (a false clean match the external tool never confirmed).
    run_prov: dict = dict(prov.get("data") or {})
    run_prov["rng_seed"] = prov.get("rng_seed")
    run_prov["produced_by"] = prov.get("produced_by")
    run_prov["environment_captured"] = False
    result = Result(
        capability=capability,
        fidelity=Fidelity(core["fidelity"]),
        verdict=Verdict(core["verdict"]),
        outputs=fresh_outputs,
        caveats=tuple(core.get("caveats") or ()),
        provenance=run_prov,
        reproduce_tolerance=core.get("reproduce_tolerance"),
    )
    return build_bundle(
        Case(capability=capability, inputs=case_value["inputs"]), result,
        engine=prov["engine"], engine_version=prov["engine_version"],
        reproduce=prov.get("reproduce"),
        data_library=(prov.get("data_library"), prov.get("data_library_sha256")),
        applicability=prov.get("applicability"),
        completeness=prov.get("completeness"),
        derived_from=prov.get("derived_from"),
        # re-mint under the subject's sealed canon (ADR-053/054): a v2 subject's links were digested under v2,
        # so a v1 re-mint would be refused by the binding belt (and would not be the same computation's seal).
        canon_version=_subject_canon_version(bundle),
        # re-mint the fresh bundle under the SAME dialect as the subject, so a branded --command
        # reproduce rebuilds a matching result core instead of a neutral-dialect one. None -> neutral.
        profile=profile,
    )


class CommandRunner:
    """A ReproduceRunner backed by a reviewer-supplied shell command (the --command path).

    The command is named on the CLI, never read from the bundle. ``run`` writes the bundle's sealed case to
    a temp dir, runs the command there with ``PROOF_INPUTS`` / ``PROOF_OUTPUT`` pointing at it, reads the
    recomputed outputs back, and rebuilds the fresh bundle to mirror the subject's shape (see
    ``_rebuild_with_outputs``)."""

    def __init__(self, command: str, bundle: dict, profile=None):
        self.command = command
        self._bundle = bundle
        self._profile = profile

    def can_run(self, capability: str) -> bool:
        # the reviewer chose this command for THIS bundle's capability
        return capability == _capability_of(self._bundle)

    def run(self, capability: str, inputs: dict) -> dict:
        with tempfile.TemporaryDirectory(prefix="proof-reproduce-") as workdir:
            in_path = os.path.join(workdir, "inputs.json")
            out_path = os.path.join(workdir, "output.json")
            with open(in_path, "w", encoding="utf-8") as fh:
                json.dump({"capability": capability, "inputs": inputs}, fh, sort_keys=True)
            env = dict(os.environ)
            env[ENV_INPUTS] = in_path
            env[ENV_OUTPUT] = out_path
            try:
                proc = subprocess.run(self.command, shell=True, cwd=workdir, env=env,
                                      capture_output=True, text=True, check=False)
            except OSError as exc:
                raise ReproduceError(f"could not run --command {self.command!r}: {exc}") from exc
            if proc.returncode != 0:
                raise ReproduceError(
                    f"--command exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:500]}")
            try:
                with open(out_path, encoding="utf-8") as fh:
                    fresh_outputs = json.load(fh)
            except OSError as exc:
                raise ReproduceError(
                    f"--command wrote no {ENV_OUTPUT} file ({out_path}); it must write the recomputed "
                    f"outputs there as JSON: {exc}") from exc
            except ValueError as exc:
                raise ReproduceError(f"{ENV_OUTPUT} is not valid JSON: {exc}") from exc
            if not isinstance(fresh_outputs, dict):
                raise ReproduceError(f"{ENV_OUTPUT} must be a JSON object of the capability's output keys")
            return _rebuild_with_outputs(self._bundle, fresh_outputs, profile=self._profile)


# --------------------------------------------------------------------------------------------------- #
# verdict printing
# --------------------------------------------------------------------------------------------------- #
def _result_core(bundle, cap):
    try:
        return bundle["manifest"]["result"]["value"]["result"].get(cap, {})
    except (KeyError, TypeError, AttributeError):
        return {}


def _print_numbers(report: dict, out) -> None:
    """The sealed-vs-fresh numbers, read in the shape the comparison used."""
    detail = report.get("reproduce_detail") or {}
    mode = detail.get("mode")
    cap = report.get("capability")
    fresh = report.get("fresh_bundle")
    if mode == "stat":
        q = detail.get("quantity")
        sealed_val = report.get("_sealed_core", {}).get(q)
        fresh_val = _result_core(fresh, cap).get(q) if fresh else None
        print(f"  comparison: statistical band on {q!r}", file=out)
        print(f"    sealed {q} = {sealed_val}   fresh {q} = {fresh_val}", file=out)
        print(f"    delta = {detail.get('delta'):.6g}   combined sigma = {detail.get('sigma'):.6g}   "
              f"n_sigma = {detail.get('n_sigma'):.3g}  (band = {detail.get('sigmas')} sigma)", file=out)
        print(f"    within band: {detail.get('within_tolerance')}   "
              f"rest-of-core identical: {detail.get('rest_identical')}", file=out)
    else:
        if mode and mode != "exact":
            print(f"  comparison: {mode}" + (f" ({detail['reason']})" if detail.get("reason") else ""),
                  file=out)
        else:
            print("  comparison: exact result-core match", file=out)
        sealed_core = report.get("_sealed_core", {})
        fresh_core = _result_core(fresh, cap) if fresh else {}
        diffs = [k for k in sorted(set(sealed_core) | set(fresh_core))
                 if sealed_core.get(k) != fresh_core.get(k)]
        if report.get("reproduced"):
            print("    every sealed output re-derived identically", file=out)
        elif fresh:
            for k in diffs[:12]:
                print(f"    {k}: sealed={sealed_core.get(k)!r} fresh={fresh_core.get(k)!r}", file=out)
            if not diffs:
                print("    outputs match; a non-output field of the result core differs", file=out)


def _print_report(path: str, report: dict, out) -> None:
    cap = report.get("capability")
    print(f"reproduce: {path}", file=out)
    print(f"  capability: {cap}", file=out)
    if report.get("integrity_ok"):
        origin = ("origin established" if report.get("origin_ok")
                  else "origin NOT established (demo pin)" if report.get("pinned_key_is_demo")
                  else "origin NOT established")
        print(f"  verify: integrity OK, {origin}", file=out)
    if report.get("reproduced"):
        print("  RESULT: REPRODUCED -- the sealed numbers re-derive from the open run", file=out)
    else:
        print("  RESULT: NOT reproduced", file=out)
    _print_numbers(report, out)
    if not report.get("inputs_identical", True):
        print("  NOTE: the re-run did NOT use the sealed inputs (a substituted or ignored input); "
              "this is not a reproduction of the sealed case", file=out)
    env_mismatch = report.get("environment_mismatch") or {}
    if env_mismatch:
        print("  environment pins that differ (sealed vs fresh):", file=out)
        for pin, diff in env_mismatch.items():
            print(f"    {pin}: sealed={diff.get('sealed')!r} fresh={diff.get('fresh')!r}", file=out)
    if report.get("environment_unverifiable"):
        print(f"  environment: {report['environment_unverifiable']}", file=out)


def _epilog() -> str:
    return (
        "the --command contract:\n"
        f"  the sealed case {{capability, inputs}} is written as JSON to a temp dir; its path is in\n"
        f"  the env var {ENV_INPUTS}. The command runs there (shell, no network) and writes the\n"
        f"  recomputed outputs -- a JSON object of the capability's output keys -- to {ENV_OUTPUT}.\n"
        "  Those fresh outputs are compared against the sealed ones (exactly, or within the sealed band).\n\n"
        "security: the runner/command is ALWAYS supplied here, never read from the bundle; a bundle's\n"
        "fields are data and can never cause code to be imported or executed.")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="proof-reproduce",
        description="Re-derive a sealed bundle's numbers with the open engine and print a verdict.",
        epilog=_epilog(), formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("bundle", help="path to the evidence bundle JSON to reproduce")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--runner", metavar="pkg.module:ClassName",
                   help="import this ReproduceRunner (or @sealed function) and re-run the producer")
    g.add_argument("--command", metavar='"<cmd>"',
                   help="run this command as the reproducer (reads PROOF_INPUTS, writes PROOF_OUTPUT)")
    p.add_argument("--profile", metavar="pkg.module:attr",
                   help="import this dialect Profile (duck-typed) and verify + reproduce under it; needed "
                        "for a branded consumer whose bundle is not the neutral evidence.* dialect")
    p.add_argument("--pubkey", metavar="HEX",
                   help="pin this 64-hex Ed25519 public key as the origin trust root for the verify step "
                        "(a convenience for a dialect with no Profile; profile.pinned_pubkey wins if both)")
    p.add_argument("--json", action="store_true",
                   help="emit the verdict as a JSON object (same exit code) instead of human text")
    return p


def _emit_json_report(path: str, report: dict, code: int) -> int:
    """Machine-readable reproduce verdict: the report minus internal/bulky keys (``_sealed_core``, the whole
    ``fresh_bundle``), plus the path and exit code. ``default=str`` is a guard; the kept fields are plain
    JSON. Returns ``code`` so the caller's exit code is unchanged from the prose path."""
    out = {k: v for k, v in report.items() if not k.startswith("_") and k != "fresh_bundle"}
    out["kind"] = REPRODUCE_VERDICT_KIND
    out["path"] = path
    out["exit_code"] = code
    out["state"] = "reproduced" if report.get("reproduced") else "not-reproduced"
    # the SAME gate field as verify: a production-origin pass is origin_ok True (a real production pin,
    # never the demo pin), so one key -- production_origin_pass -- works across verify AND reproduce.
    out["production_origin_pass"] = report.get("origin_ok") is True
    out["not_a_production_pass"] = report.get("origin_ok") is not True
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def _emit_json_error(path: str, state: str, code: int, *, integrity_ok=None, **extra) -> int:
    """A JSON error verdict for the paths that never build a full report (unreadable bundle, usage error,
    integrity failed before reproduce, reproduction could not finish). Carries the SAME guaranteed-core keys
    as the success path -- kind, path, exit_code, integrity_ok, state, production_origin_pass,
    not_a_production_pass -- so an agent parses any reproduce verdict uniformly. ``integrity_ok`` is True for
    the post-verify gaps (cannot-reproduce / error), False for an integrity failure, and None where it was
    never checked (a usage or unreadable error). An error is never a production pass. Returns ``code``."""
    out = {"kind": REPRODUCE_VERDICT_KIND, "path": path, "reproduced": False, "state": state,
           "exit_code": code, "integrity_ok": integrity_ok,
           "production_origin_pass": False, "not_a_production_pass": True, **extra}
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def main(argv: list[str] | None = None) -> int:
    # independent verifier + the ONE guarded loader + the origin-pin setter (for --pubkey)
    from proof_verify.verify import classify_bundle, loads, pin_key

    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse usage error (-> 2) or --help (-> 0)
        return int(exc.code) if exc.code is not None else EXIT_USAGE

    # the on-disk DIALECT to verify/reproduce under, named on the command line (never read from the bundle).
    profile = None
    if args.profile is not None:
        try:
            profile = _resolve_profile(args.profile)
        except ValueError as exc:
            if args.json:
                return _emit_json_error(args.bundle, "usage", EXIT_USAGE, error=str(exc))
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    if args.pubkey is not None:
        try:
            pin_key(args.pubkey)
        except (ValueError, TypeError) as exc:
            if args.json:
                return _emit_json_error(args.bundle, "usage", EXIT_USAGE,
                                        error=f"--pubkey must be 64 lowercase hex characters: {exc}")
            print(f"error: --pubkey must be 64 lowercase hex characters: {exc}", file=sys.stderr)
            return EXIT_USAGE

    try:
        with open(args.bundle, "rb") as fh:
            # bytes + strict UTF-8, exactly as proof-verify reads: no newline translation before the size cap,
            # and an invalid byte is unreadable (UnicodeDecodeError is a ValueError), never U+FFFD
            bundle = loads(fh.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        if args.json:
            return _emit_json_error(args.bundle, "unreadable", EXIT_USAGE,
                                    error=f"{type(exc).__name__}: {exc}")
        print(f"error: cannot read bundle {args.bundle!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # VERIFY FIRST (integrity): a bundle whose integrity does not hold is edited/forged/malformed and is
    # never re-derived -- re-running a tampered record proves nothing. Fail closed before any runner work.
    ver = classify_bundle(bundle, profile=profile)
    if not ver["integrity_ok"]:
        if args.json:
            return _emit_json_error(args.bundle, "integrity-fail", EXIT_NOT_REPRODUCED,
                                    integrity_ok=False, problems=ver.get("problems", []))
        print(f"FAIL  integrity does not hold; not reproducing: {args.bundle}", file=sys.stderr)
        for problem in ver["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_NOT_REPRODUCED

    # the runner/command comes ONLY from the command line (never the bundle) -- the security line.
    if args.runner is not None:
        try:
            runner: ReproduceRunner = _resolve_runner(args.runner)
        except ValueError as exc:
            # integrity already held (verified above); the runner the reviewer NAMED is unusable. This is the
            # one error branch that must also honor --json, like its siblings.
            if args.json:
                return _emit_json_error(args.bundle, "unusable-runner", EXIT_USAGE,
                                        error=str(exc), integrity_ok=True)
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    else:
        runner = CommandRunner(args.command, bundle, profile)

    try:
        report = reproduce_bundle(bundle, runner, profile=profile)
    except ReproduceError as exc:
        # a named gap: inputs/result withheld, or the capability is not available to this runner.
        if args.json:
            return _emit_json_error(args.bundle, "cannot-reproduce", EXIT_NOT_REPRODUCED,
                                    error=str(exc), integrity_ok=True)
        print(f"reproduce: {args.bundle}", file=sys.stderr)
        print(f"  cannot reproduce: {exc}", file=sys.stderr)
        return EXIT_NOT_REPRODUCED
    except Exception as exc:  # noqa: BLE001 -- reproduction re-runs arbitrary producer/reviewer code
        if args.json:
            return _emit_json_error(args.bundle, "error", EXIT_NOT_REPRODUCED,
                                    error=f"{type(exc).__name__}: {exc}", integrity_ok=True)
        print(f"reproduce: {args.bundle}", file=sys.stderr)
        print(f"  reproduction could not finish: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_NOT_REPRODUCED

    # stash the sealed result core for the printer (read here, once, from the verified bundle)
    report["_sealed_core"] = _result_core(bundle, report.get("capability"))
    code = EXIT_REPRODUCED if report.get("reproduced") else EXIT_NOT_REPRODUCED
    if args.json:
        return _emit_json_report(args.bundle, report, code)
    _print_report(args.bundle, report, sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
