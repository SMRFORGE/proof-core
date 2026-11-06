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
      reviewer points this at the SAME producer that minted the bundle. The module comes from the normal
      import path (installed, or ``PYTHONPATH``), never the current directory: a reviewer often runs this
      inside an unpacked bundle folder, where a sender could plant a same-named module. Name a file
      explicitly by an ABSOLUTE path, ``/abs/path/file.py:ClassName`` (a relative one is refused).

  --command "<cmd>"
      A built-in subprocess runner, so a reviewer can reproduce with their OWN installed tool and no
      adapter code. The contract (also in --help):
        1. the bundle's sealed case ``{"capability", "inputs"}`` is written as JSON to a fresh temp dir;
           the path is handed to the command in the env var ``PROOF_INPUTS``.
        2. ``<cmd>`` is run with that temp dir as its working directory (``shell=True``). It must not rely
           on the network; it reads ``PROOF_INPUTS`` and recomputes the result. Nothing enforces that: the
           command is not sandboxed and runs with the reviewer's own access, network included.
        3. the command writes the recomputed OUTPUTS -- a JSON object of the capability's output keys,
           the same shape as the sealed ``result[<capability>]`` -- to the path in ``PROOF_OUTPUT``.
        4. those fresh outputs are spliced onto the sealed bundle's shape (same inputs, fidelity, verdict,
           caveats, tolerance and provenance pins) and compared OUTPUTS ONLY: --command cannot re-derive
           fidelity, verdict, caveats, reproduce_tolerance or produced_by (they are taken from the bundle, and
           the report says so), and it never applies the bundle's own sealed statistical band, which is the
           producer's claim. Every output must match exactly (JSON numbers by value: 20 equals 20.0, a
           boolean or a numeric string never equals a number), unless the REVIEWER passes a band with
           ``--stochastic QUANTITY --sigma-key KEY [--sigmas N]``; the result is then labelled as compared
           under the reviewer's band. To hold a capability to its sealed claim, use --runner.

SECURITY (hard line): the CLI NEVER imports or executes anything named ONLY inside the bundle. The
capability string, the inputs, and every other field in the bundle are treated strictly as DATA. The only
code the CLI runs is what the reviewer named on the command line (``--runner`` target or ``--command``).
So a hostile bundle cannot cause code execution merely by being pointed at -- see
``tests/test_reproduce_cli.py::test_bundle_alone_cannot_cause_code_execution``.

ONE GATE. Whether the bundle is accepted is proof-verify's decision, never this tool's: the verify step is
``proof_verify.gate.gate`` under the receiver's trust inputs, resolved exactly as proof-verify resolves them
(``--policy FILE | preset:NAME``, else ``$PROOF_POLICY``, else the built-in default; ``--no-policy-discovery``,
``--pubkey``, ``--allow-self-verify``, ``--as-of``, ``--expect-policy``). The verdict carries that decision as
``gate`` (``gate.exit_code`` is proof-verify's single-bundle exit code for the same bytes and trust inputs), and
``production_origin_pass`` is literally ``gate.passed``.

Exit codes:
  0  reproduced (--runner only), and ONLY when all three hold: (a) the gate passes (proof-verify would exit 0:
     intact, signed under a non-demo pin of the receiver, every sign-off valid, accepted by the receiver's policy);
     (b) the re-run used the sealed inputs (``inputs_identical``); (c) the environment is pinned and matches: the
     sealed run pinned its data environment and no sealed pin differs (``environment_mismatch`` empty, no
     ``environment_unverifiable``). The sealed numbers and the sealed claim re-derive from the open run (within
     the sealed band if the re-run is itself stochastic).
  1  NOT reproduced: the numbers or the claim do not re-derive; or verify fails the bundle closed (integrity does
     not hold, or the receiver decision rejects it -- a signed rejection, an invalid sign-off -- exactly where
     proof-verify exits 1). A bundle whose integrity fails is never re-run.
  2  usage error, the bundle file could not be read / parsed, the --runner target is unusable, or the receiver
     policy is refused (malformed, unreadable, or not the one --expect-policy names) -- no verdict, as proof-verify.
  3  outputs reproduced, claims NOT re-derived (--command only): every output matches exactly, or within the
     reviewer's --stochastic band, and (a)-(c) hold, but fidelity, verdict, caveats, reproduce_tolerance and
     produced_by were taken from the bundle. Mirrors proof-verify's exit 3: a partial result, never a pass.
  4  UNSUPPORTED CANON, as proof-verify's 4: sealed under a canon this verifier does not implement; never re-run.
  6  UNSUPPORTED ALG, as proof-verify's 6: signed with a suite this verifier does not implement; never re-run.
  7  PARTIAL, not reproduced: the numbers re-derive, but (a), (b) or (c) does not hold -- the gate did not pass
     (origin not established under the receiver's pins and policy, e.g. the public demo pin; proof-verify exit 3),
     the re-run did not use the sealed inputs, or the environment does not match: a sealed environment pin differs,
     or the data environment was never pinned (``environment_unverifiable``; certify never certifies it either).
     ``shortfalls`` names which. Like 3, a partial result, never a pass. (5 is proof-verify's chain-incomplete code
     and is not used here.)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

from proof_verify import _spec_loader

from .certify import (
    SHORTFALL_ENV_UNVERIFIABLE,
    SHORTFALL_ENVIRONMENT,
    SHORTFALL_GATE,
    SHORTFALL_INPUTS,
    ReproduceError,
    differing_output_keys,
    reproduce_bundle,
    subject_canon,
)
from .committed import disclosed_values as _disclosed
from .contract import Case, Fidelity, ReproduceRunner, Result, Verdict
from .envelope import build_bundle

EXIT_REPRODUCED = 0
EXIT_NOT_REPRODUCED = 1          # also: verify failed (a bundle whose integrity fails is never re-run)
EXIT_USAGE = 2                   # usage / unreadable bundle / unusable --runner target
EXIT_OUTPUTS_ONLY = 3            # --command: outputs reproduced, claims NOT re-derived (mirrors proof-verify's 3)
EXIT_UNSUPPORTED_CANON = 4       # as proof-verify: a canon this verifier does not implement (never re-run)
EXIT_UNSUPPORTED_ALG = 6         # as proof-verify: a signature suite this verifier does not implement (never re-run)
EXIT_PARTIAL = 7                 # numbers re-derive, but the gate did not pass / other inputs / environment not ok

#: env vars naming the input/output JSON files for the built-in --command runner (the documented contract).
ENV_INPUTS = "PROOF_INPUTS"
ENV_OUTPUT = "PROOF_OUTPUT"

#: the JSON `kind` discriminator for a reproduce verdict, so an agent can tell verdict shapes apart and
#: detect schema evolution. Bump the trailing version if the reproduce JSON contract changes shape.
REPRODUCE_VERDICT_KIND = "proof_core.reproduce_verdict.v3"

#: the `shortfalls` a numbers-match can carry, each blocking exit 0 (exit 7): certify.reproduction_shortfalls, the
#: ONE rule the library report, certify and the Adapter use too (gate_not_passed, inputs_not_identical,
#: environment_mismatch, environment_unverifiable)


# --------------------------------------------------------------------------------------------------- #
# runner resolution -- the ONLY code the CLI runs is what the reviewer named here, never a bundle field
# --------------------------------------------------------------------------------------------------- #
def _resolve_runner(spec: str) -> ReproduceRunner:
    """Import the reviewer-named ``pkg.module:attr`` (dotted ``attr`` allowed) and return a ReproduceRunner.

    A class is instantiated with no args; an already-constructed runner object (e.g. a ``@sealed`` function,
    which IS a runner) is used as-is. Raises ValueError with a plain reason if the spec is malformed, the
    import fails, or the resolved object is not a ReproduceRunner. This reads ONLY the command-line ``spec``;
    it never consults the bundle."""
    module_name, attr_path = _spec_loader.split_spec(spec, "--runner", "pkg.module:ClassName")
    # The current directory is NEVER added to the import path: a reviewer often runs this inside an unpacked
    # bundle folder, and a sender-planted `myrunner.py` there would replace the reviewer's runner (a "re-run"
    # that hands back the sealed value). A module comes from the normal import path (PYTHONPATH / installed);
    # a file is named explicitly by an absolute path, `/abs/path/file.py:ClassName` (relative is refused).
    try:
        obj = _spec_loader.import_spec_module(module_name, "runner")
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
    module_name, attr_path = _spec_loader.split_spec(spec, "--profile", "pkg.module:attr")
    try:  # never the cwd (see _resolve_runner): a planted profile would pin the sender's key
        obj = _spec_loader.import_spec_module(module_name, "profile")
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
    """The subject's sealed canon_version, which the re-mint uses. SPEC v4 draft section 15 step 3 (closes open
    issue 17.3.10): the subject's own canon N, for every N this kernel implements -- no fallback to v1 for a
    canon it does not implement (ReproduceError instead; unreachable after the integrity check, which an
    unsupported canon never passes)."""
    return subject_canon(bundle)[0]


def _remint_links(links, sealed_inputs, canon_version: int):
    """The subject's `derived_from` links the re-mint can carry. A canon-3 link whose consumed input holds a
    committed item was sealed over that input's PROJECTED (commitment) form; the re-mint carries the disclosed
    values with fresh salts, so such a link can never bind again and the mint would refuse it. It is left out of
    the fresh bundle (which is only compared by its outputs); every other link is kept."""
    if canon_version != 3 or not isinstance(links, list) or not isinstance(sealed_inputs, dict):
        return links
    from proof_verify.verify import _has_committed_member
    kept = [link for link in links
            if not (isinstance(link, dict) and isinstance(link.get("consumed"), dict)
                    and _has_committed_member(sealed_inputs.get(link["consumed"].get("input"))))]
    return kept or None


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
    # the claim fields below are COPIED from the subject (an outputs-only reproducer cannot re-derive them); the
    # comparison knows this (CommandRunner.outputs_only) and never applies the copied sealed band
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
        # a canon-3 subject is re-minted on its DISCLOSED values: salts are never reused across bundles (SPEC 6.6.4),
        # and the comparison is by value (15 step 3)
        Case(capability=capability, inputs=(_disclosed(case_value["inputs"]) if _subject_canon_version(bundle) == 3
                                            else case_value["inputs"])), result,
        engine=prov["engine"], engine_version=prov["engine_version"],
        reproduce=prov.get("reproduce"),
        data_library=(prov.get("data_library"), prov.get("data_library_sha256")),
        applicability=prov.get("applicability"),
        completeness=prov.get("completeness"),
        derived_from=_remint_links(prov.get("derived_from"), case_value["inputs"], _subject_canon_version(bundle)),
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

    #: the comparison is OUTPUTS ONLY: the fresh core's claim fields are copies of the sealed ones (certify.py)
    outputs_only = True

    def __init__(self, command: str, bundle: dict, profile=None, reviewer_tolerance: dict | None = None):
        self.command = command
        self._bundle = bundle
        self._profile = profile
        #: a `stat` tolerance the REVIEWER passed (--stochastic); None = exact match of every output
        self.reviewer_tolerance = reviewer_tolerance

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


def _is_number(value) -> bool:
    """A real int or float (never a bool): the only values the band line formats with a numeric spec."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _print_numbers(report: dict, out) -> None:
    """The sealed-vs-fresh numbers, read in the shape the comparison used."""
    detail = report.get("reproduce_detail") or {}
    mode = detail.get("mode")
    cap = report.get("capability")
    fresh = report.get("fresh_bundle")
    if mode in ("stat", "stat-deterministic", "stat-reviewer"):
        q = detail.get("quantity")
        sealed_val = report.get("_sealed_core", {}).get(q)
        fresh_val = _result_core(fresh, cap).get(q) if fresh else None
        source = ("the REVIEWER's band (--stochastic), not the bundle's sealed reproduce_tolerance"
                  if mode == "stat-reviewer" else "the producer's sealed band")
        print(f"  comparison: statistical band on {q!r} -- {source}", file=out)
        # a non-number is shown quoted (repr), so the string "100.2" never reads as the number 100.2
        shown = [v if _is_number(v) else repr(v) for v in (sealed_val, fresh_val)]
        print(f"    sealed {q} = {shown[0]}   fresh {q} = {shown[1]}", file=out)
        # delta / sigma / n_sigma exist only when both values were numbers: a string or boolean quantity (or sigma)
        # is a closed mismatch whose detail carries a `reason` instead (certify._stat_match), never a crash here
        if all(_is_number(detail.get(k)) for k in ("delta", "sigma", "n_sigma")):
            band = f"  (band = {detail['sigmas']} sigma)" if _is_number(detail.get("sigmas")) else ""
            print(f"    delta = {detail['delta']:.6g}   combined sigma = {detail['sigma']:.6g}   "
                  f"n_sigma = {detail['n_sigma']:.3g}{band}", file=out)
        if detail.get("reason"):
            print(f"    {detail['reason']}", file=out)
        rest = (f"   rest-of-core identical: {detail['rest_identical']}" if "rest_identical" in detail else "")
        print(f"    within band: {detail.get('within_tolerance')}{rest}", file=out)
    else:
        if mode and mode != "exact":
            print(f"  comparison: {mode}" + (f" ({detail['reason']})" if detail.get("reason") else ""),
                  file=out)
        else:
            print("  comparison: exact result-core match", file=out)
        sealed_core = report.get("_sealed_core", {})
        fresh_core = _result_core(fresh, cap) if fresh else {}
        # the keys that differ under the SAME rule the verdict used (subject canon; by value for --command), never
        # Python `!=` (True == 1 and 1 == 1.0 there, which would hide a real output difference)
        diffs = report.get("_output_diffs", [])
        if report.get("result_rederived"):
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
    gate = report.get("gate") or {}
    if report.get("integrity_ok"):
        origin = ("origin established" if report.get("origin_ok")
                  else "origin NOT established (demo pin)" if report.get("pinned_key_is_demo")
                  else "origin NOT established")
        print(f"  verify: integrity OK, {origin}", file=out)
    if gate:
        verdict = ("PASS (proof-verify exit 0)" if gate.get("passed")
                   else f"NOT passed (proof-verify exit {gate.get('exit_code')}): {report.get('_gate_why')}")
        print(f"  gate: {verdict}", file=out)
    detail = report.get("reproduce_detail") or {}
    mode = detail.get("mode")
    code = report.get("_exit_code")
    shortfalls = report.get("shortfalls") or []
    rederived = report.get("result_rederived") is True
    if rederived and code == EXIT_REJECTED_BY_GATE_MARK:
        print("  RESULT: NOT reproduced -- the numbers re-derive, but proof-verify rejects this bundle (see gate)",
              file=out)
    elif rederived and shortfalls:
        print("  RESULT: PARTIAL, NOT reproduced -- the numbers re-derive, but: " + "; ".join(
            _SHORTFALL_TEXT[s] for s in shortfalls), file=out)
    elif not rederived:
        print("  RESULT: NOT reproduced", file=out)
    elif report.get("outputs_only") and mode == "stat-reviewer":
        print(f"  RESULT: REPRODUCED (outputs only) within the REVIEWER's band ({detail.get('sigmas')} sigma on "
              f"{detail.get('quantity')!r}) -- the outputs agree within that band; this is not an exact "
              "re-derivation", file=out)
    elif report.get("outputs_only"):
        print("  RESULT: REPRODUCED (outputs only) -- every fresh output equals the sealed output exactly", file=out)
    elif mode == "stat":
        print(f"  RESULT: REPRODUCED within the producer's sealed statistical band ({detail.get('sigmas')} sigma) "
              "-- the fresh STOCHASTIC run agrees within that band; this is not a bit-exact re-derivation",
              file=out)
    else:
        print("  RESULT: REPRODUCED -- the sealed numbers re-derive exactly from the open run", file=out)
    _print_numbers(report, out)
    if report.get("outputs_only"):
        print("  NOTE: --command compares OUTPUTS ONLY. fidelity, verdict, caveats, reproduce_tolerance and "
              "produced_by were taken from the bundle and NOT re-derived.", file=out)
        sealed_tol = (report.get("_sealed_full_core") or {}).get("reproduce_tolerance")
        if isinstance(sealed_tol, dict) and sealed_tol.get("kind") == "stat" and mode != "stat-reviewer":
            print("  NOTE: the bundle seals its own statistical band; --command never applies it (it is the "
                  "producer's claim). Pass --stochastic QUANTITY --sigma-key KEY [--sigmas N] to compare under "
                  "a band you choose, or use --runner.", file=out)
    if mode == "stat-deterministic":
        print(f"  NOTE: {detail.get('reason')}", file=out)
    claim_drift = report.get("claim_drift") or {}
    if claim_drift:
        print("  sealed claim fields the fresh run re-declares differently (sealed vs fresh):", file=out)
        for key, diff in claim_drift.items():
            if key == "caveats" and diff.get("missing_from_sealed"):
                print(f"    caveats: the fresh run declares {diff['missing_from_sealed']!r}, which the sealed "
                      "bundle omits (a removed caveat widens the claim)", file=out)
            else:
                print(f"    {key}: sealed={diff.get('sealed')!r} fresh={diff.get('fresh')!r}", file=out)
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


#: why a numbers-match is not a reproduction, one plain phrase per shortfall (text output)
_SHORTFALL_TEXT = {
    SHORTFALL_GATE: "the gate did not pass (proof-verify would not exit 0 for this bundle under your trust inputs)",
    SHORTFALL_INPUTS: "the re-run did not use the sealed inputs",
    SHORTFALL_ENVIRONMENT: "a sealed environment pin differs",
    SHORTFALL_ENV_UNVERIFIABLE: "the data environment was never pinned, so a re-run on other data cannot be told apart",
}
#: the print-layer marker for "the gate rejects" (verify fails closed; the exit is 1 although the numbers matched)
EXIT_REJECTED_BY_GATE_MARK = "rejected"
#: the one-word verdict for an exit code, for the fallback line when a detail cannot be printed
_RESULT_WORD = {EXIT_REPRODUCED: "REPRODUCED", EXIT_OUTPUTS_ONLY: "REPRODUCED (outputs only)",
                EXIT_NOT_REPRODUCED: "NOT reproduced", EXIT_PARTIAL: "PARTIAL, NOT reproduced",
                EXIT_UNSUPPORTED_CANON: "NOT reproduced (unsupported canon)",
                EXIT_UNSUPPORTED_ALG: "NOT reproduced (unsupported signature suite)"}


def _epilog() -> str:
    return (
        "the --command contract:\n"
        f"  the sealed case {{capability, inputs}} is written as JSON to a temp dir; its path is in\n"
        f"  the env var {ENV_INPUTS}. The command runs there through the shell and writes the recomputed\n"
        f"  outputs -- a JSON object of the capability's output keys -- to {ENV_OUTPUT}. It must not rely on\n"
        "  the network, but it is NOT sandboxed: it runs with your user's full access (network included).\n"
        "  Those fresh outputs are compared against the sealed ones OUTPUTS ONLY and EXACTLY: --command never\n"
        "  applies the bundle's sealed statistical band, and it cannot re-derive fidelity, verdict, caveats,\n"
        "  reproduce_tolerance or produced_by (they are taken from the bundle; the report says so). For a\n"
        "  stochastic tool, pass YOUR band: --stochastic QUANTITY --sigma-key KEY [--sigmas N]. To hold the\n"
        "  capability to its sealed claim, use --runner.\n\n"
        "trust inputs: the verify step is proof-verify's own gate, under the same --policy / PROOF_POLICY /\n"
        "  --no-policy-discovery / --pubkey / --allow-self-verify / --as-of / --expect-policy as proof-verify.\n\n"
        "exit codes: 0 reproduced (--runner: numbers and claim) AND the gate passes (proof-verify exit 0) AND the\n"
        "  sealed inputs were used AND the environment is pinned and matches; 1 not reproduced, or proof-verify\n"
        "  fails the bundle closed; 2 usage error or the policy is refused; 3 outputs reproduced but claims NOT\n"
        "  re-derived (--command); 4 / 6 unsupported canon / suite (as proof-verify); 7 partial: the numbers re-derive but\n"
        "  the gate did not pass, the re-run used other inputs, or the environment differs or was never pinned\n"
        "  (`shortfalls` names which). Only 0 is a pass.\n\n"
        "--json: `reproduced` is true ONLY for exit 0; an outputs-only pass (exit 3) reads\n"
        "  `reproduced: false, outputs_reproduced: true, state: outputs-reproduced`; a partial (exit 7) reads\n"
        "  `reproduced: false, outputs_reproduced: true, state: partial`. `gate` is proof-verify's decision.\n\n"
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
                   help="import this ReproduceRunner (or @sealed function) and re-run the producer; the "
                        "module comes from the import path (PYTHONPATH / installed), never the current "
                        "directory; or name a file by absolute path, /abs/path/file.py:ClassName")
    g.add_argument("--command", metavar='"<cmd>"',
                   help="run this command as the reproducer (reads PROOF_INPUTS, writes PROOF_OUTPUT)")
    p.add_argument("--profile", metavar="pkg.module:attr",
                   help="import this dialect Profile (duck-typed) and verify + reproduce under it; needed "
                        "for a branded consumer whose bundle is not the neutral evidence.* dialect (import "
                        "path only, never the current directory; or /abs/path/file.py:attr)")
    p.add_argument("--pubkey", metavar="HEX",
                   help="pin this 64-hex Ed25519 public key as the origin trust root for the verify step, as "
                        "proof-verify --pubkey (merged into a receiver policy when one is in effect)")
    p.add_argument("--policy", metavar="FILE",
                   help="the receiver policy (evidence.receiver-policy.v1) the verify step decides under, as "
                        "proof-verify --policy (FILE or preset:NAME); without it $PROOF_POLICY, else the default")
    p.add_argument("--no-policy-discovery", dest="no_policy_discovery", action="store_true",
                   help="do not read PROOF_POLICY (only --policy, else the default policy), as proof-verify")
    p.add_argument("--expect-policy", dest="expect_policy", metavar="sha256:HEX",
                   help="exit 2 with no verdict unless the effective policy's policy_sha256 is this, as proof-verify")
    p.add_argument("--allow-self-verify", dest="allow_self_verify", action="store_true",
                   help="as proof-verify --allow-self-verify (sets allow_self_verify in the effective policy)")
    p.add_argument("--as-of", dest="as_of", metavar="T",
                   help="the evaluation instant for the verify step, YYYY-MM-DDTHH:MM:SSZ (default: now)")
    p.add_argument("--stochastic", metavar="QUANTITY",
                   help="--command only: compare the output QUANTITY within YOUR statistical band (needs "
                        "--sigma-key) instead of exactly; the bundle's sealed band is never used")
    p.add_argument("--sigma-key", metavar="KEY", help="--command --stochastic: the output key holding the 1-sigma")
    p.add_argument("--sigmas", metavar="N", type=float, default=None,
                   help="--command --stochastic: the band width in sigmas (default 3, at most 10)")
    p.add_argument("--json", action="store_true",
                   help="emit the verdict as a JSON object (same exit code) instead of human text; "
                        "`reproduced` is true only for a full reproduction (exit 0), `outputs_reproduced` "
                        "is true whenever the outputs matched (exit 0 or 3)")
    return p


def _emit_json_report(path: str, report: dict, code: int) -> int:
    """Machine-readable reproduce verdict: the report minus internal/bulky keys (``_sealed_core``, the whole
    ``fresh_bundle``), plus the path and exit code. ``default=str`` is a guard; the kept fields are plain
    JSON. Returns ``code`` so the caller's exit code is unchanged from the prose path.

    ``reproduced`` is True only for a full reproduction (exit 0); ``outputs_reproduced`` is True whenever the
    outputs matched (exit 0 or 3). So an outputs-only pass reads ``reproduced: false, outputs_reproduced: true``
    (kind v2; v1 reported ``reproduced: true`` for it)."""
    out = {k: v for k, v in report.items() if not k.startswith("_") and k != "fresh_bundle"}
    out["kind"] = REPRODUCE_VERDICT_KIND
    out["path"] = path
    out["exit_code"] = code
    out["state"] = {EXIT_REPRODUCED: "reproduced", EXIT_OUTPUTS_ONLY: "outputs-reproduced",
                    EXIT_PARTIAL: "partial"}.get(code, "not-reproduced")
    # `reproduced` is True ONLY for exit 0 (the library report's `reproduced`, the same rule). `outputs_reproduced`
    # is the raw comparison (`result_rederived`): true whenever the numbers re-derived, also for exit 3, exit 7 and a
    # bundle the gate rejects (exit 1), as the text says ("the numbers re-derive, but ...").
    out["outputs_reproduced"] = report.get("result_rederived") is True
    out["reproduced"] = code == EXIT_REPRODUCED
    # literally the ONE gate's verdict (proof-verify's exit 0 for these bytes under these trust inputs): one key,
    # production_origin_pass, means the same thing across verify AND reproduce
    gate = report.get("gate") or {}
    out["production_origin_pass"] = gate.get("passed") is True
    out["not_a_production_pass"] = gate.get("passed") is not True
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def _emit_json_error(path: str, state: str, code: int, *, integrity_ok=None, **extra) -> int:
    """A JSON error verdict for the paths that never build a full report (unreadable bundle, usage error,
    integrity failed before reproduce, reproduction could not finish). Carries the SAME guaranteed-core keys
    as the success path -- kind, path, exit_code, integrity_ok, state, production_origin_pass,
    not_a_production_pass -- so an agent parses any reproduce verdict uniformly. ``integrity_ok`` is True for
    the post-verify gaps (cannot-reproduce / error), False for an integrity failure, and None where it was
    never checked (a usage or unreadable error). An error is never a production pass. Returns ``code``."""
    out = {"kind": REPRODUCE_VERDICT_KIND, "path": path, "reproduced": False, "outputs_reproduced": False,
           "state": state,
           "exit_code": code, "integrity_ok": integrity_ok,
           "production_origin_pass": False, "not_a_production_pass": True, **extra}
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def _reviewer_tolerance(args) -> tuple[dict | None, str | None]:
    """The REVIEWER's band from --stochastic / --sigma-key / --sigmas: (tolerance or None, usage error or None)."""
    import math
    if args.stochastic is None:
        if args.sigma_key is not None or args.sigmas is not None:
            return None, "--sigma-key and --sigmas need --stochastic QUANTITY"
        return None, None
    if args.command is None:
        return None, ("--stochastic is for --command only; --runner re-runs the producer, whose own declared "
                      "tolerance governs")
    if not args.sigma_key:
        return None, "--stochastic needs --sigma-key KEY (the output key holding the 1-sigma)"
    if args.sigma_key == args.stochastic:
        return None, "--sigma-key must differ from the --stochastic quantity"
    sigmas = 3.0 if args.sigmas is None else args.sigmas
    if not math.isfinite(sigmas) or not 0 < sigmas <= 10:
        return None, "--sigmas must be a finite number above 0 and at most 10"
    return {"kind": "stat", "quantity": args.stochastic, "sigma_key": args.sigma_key, "sigmas": sigmas}, None


def main(argv: list[str] | None = None) -> int:
    from proof_verify.verify import safe_terminal_output

    argv = list(sys.argv[1:] if argv is None else argv)
    # text mode: everything printed is escaped to printable ASCII (bundle text never reaches the terminal raw)
    with safe_terminal_output(enabled="--json" not in argv):
        return _main(argv)


def _exit_code(report: dict) -> tuple[int, list[str]]:
    """(exit code, shortfalls) for a finished report. The gate (proof-verify's decision) comes first: a bundle it fails
    closed is exit 1 whatever the numbers did. A numbers-match (`result_rederived`) with any shortfall of the library
    report (certify.reproduction_shortfalls: gate, inputs, environment mismatch or unpinned) is a partial (7); with
    none it is 0, or 3 for --command (outputs only). Exit 0 is exactly the report's `reproduced`."""
    gate = report.get("gate") or {}
    if gate.get("exit_code") not in (0, 3) or not report.get("result_rederived"):
        return EXIT_NOT_REPRODUCED, []
    shortfalls = list(report.get("shortfalls") or [])
    if shortfalls:
        return EXIT_PARTIAL, shortfalls
    if report.get("outputs_only"):
        return EXIT_OUTPUTS_ONLY, []
    if report.get("reproduced") is not True:
        # exit 0 is exactly the library's `reproduced`; a report that disagrees is never read as a pass
        return EXIT_NOT_REPRODUCED, []
    return EXIT_REPRODUCED, []


def _usage(args, msg: str) -> int:
    if args.json:
        return _emit_json_error(args.bundle, "usage", EXIT_USAGE, error=msg)
    print(f"error: {msg}", file=sys.stderr)
    return EXIT_USAGE


def _policy_refused(args, exc) -> int:
    """A refused receiver policy: exit 2 with no verdict, as proof-verify (SPEC 13.4.1)."""
    from proof_verify import policy_source as _ps
    source = getattr(exc, "source", None)
    msg = str(exc)
    if source is not None and source.get("kind") != "flag" and _ps.describe(source) not in msg:
        msg = f"{msg} ({_ps.describe(source)})"
    if args.json:
        return _emit_json_error(args.bundle, "policy-refused", EXIT_USAGE, error=msg,
                                policy_error=getattr(exc, "kind", "policy"),
                                **({"policy_source": source} if source is not None else {}))
    print(f"error: policy refused: {msg}", file=sys.stderr)
    return EXIT_USAGE


def _main(argv: list[str]) -> int:
    # independent verifier + the ONE guarded loader; the ONE gate and its trust-input resolver
    from proof_verify import policy_source as _ps
    from proof_verify.gate import apply_single_pin, gate, resolve_trust
    from proof_verify.verify import PolicyError, _utc_or_null, loads

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
    if args.as_of is not None and not _utc_or_null(args.as_of):
        return _usage(args, f"--as-of must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ (SPEC 2.3): {args.as_of!r}")
    # the receiver's trust inputs, resolved EXACTLY as proof-verify resolves them (one helper, proof_verify.gate)
    try:
        trust = resolve_trust(policy_arg=args.policy, pubkey=args.pubkey, no_discovery=args.no_policy_discovery,
                              allow_self_verify=args.allow_self_verify, expect_policy=args.expect_policy,
                              as_of=args.as_of)
    except _ps.PolicyUsageError as exc:
        if getattr(exc, "source", None) is None:
            return _usage(args, str(exc))
        return _policy_refused(args, exc)
    except PolicyError as exc:
        return _policy_refused(args, exc)
    note = _ps.ignored_note(trust.source)
    if note:
        print(note, file=sys.stderr)
    if profile is not None:
        # a --profile origin pin is not a trust root under a receiver policy: refuse rather than drop it (as verify)
        from proof_verify.__main__ import _profile_pin_conflict
        conflict = _profile_pin_conflict(profile, args.profile, trust.policy, trust.pins, trust.source,
                                         args.allow_self_verify and trust.source.get("kind") == "default")
        if conflict is not None:
            return _usage(args, conflict)
    try:
        apply_single_pin(args.pubkey, trust.pins)
    except (ValueError, TypeError) as exc:
        return _usage(args, f"--pubkey must be 64 lowercase hex characters: {exc}")

    reviewer_tol, why = _reviewer_tolerance(args)
    if why:
        if args.json:
            return _emit_json_error(args.bundle, "usage", EXIT_USAGE, error=why)
        print(f"error: {why}", file=sys.stderr)
        return EXIT_USAGE

    try:
        with open(args.bundle, "rb") as fh:
            # bytes + strict UTF-8, exactly as proof-verify reads: no newline translation before the size cap,
            # and an invalid byte is unreadable (UnicodeDecodeError is a ValueError), never U+FFFD
            raw = fh.read()
            bundle = loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        if args.json:
            return _emit_json_error(args.bundle, "unreadable", EXIT_USAGE,
                                    error=f"{type(exc).__name__}: {exc}")
        print(f"error: cannot read bundle {args.bundle!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # VERIFY FIRST, through the ONE gate (proof-verify's own decision under the receiver's trust inputs). A bundle
    # whose integrity does not hold is edited/forged/malformed and is never re-derived -- re-running a tampered record
    # proves nothing. Fail closed before any runner work.
    # ONE evaluation instant for the gate here and the one reproduce_bundle runs, so the two can never fall on either
    # side of a trusted_until boundary (SPEC 7.13)
    from proof_verify.verify import utc_now
    trust_kw = {"policy": trust.policy, "pins": trust.pins, "as_of": trust.as_of or utc_now()}
    try:
        decision = gate(raw, profile=profile, policy_source=trust.source, expect_policy=trust.expect_policy,
                        **trust_kw)
    except PolicyError as exc:
        return _policy_refused(args, exc)
    if decision.exit_code in (EXIT_UNSUPPORTED_CANON, EXIT_UNSUPPORTED_ALG):
        # as proof-verify: an unsupported canon or suite is "use a newer verifier", not a tampered record
        state = "unsupported-canon" if decision.exit_code == EXIT_UNSUPPORTED_CANON else "unsupported-alg"
        if args.json:
            return _emit_json_error(args.bundle, state, decision.exit_code, integrity_ok=False,
                                    problems=decision.problems, gate=decision.summary())
        print(f"UNSUPPORTED  {decision.why_not()}; not reproducing (exit {decision.exit_code}, as proof-verify; "
              f"use a newer verifier): {args.bundle}", file=sys.stderr)
        return decision.exit_code
    if not decision.integrity_ok:
        if args.json:
            return _emit_json_error(args.bundle, "integrity-fail", EXIT_NOT_REPRODUCED,
                                    integrity_ok=False, problems=decision.problems, gate=decision.summary())
        print(f"FAIL  integrity does not hold; not reproducing: {args.bundle}", file=sys.stderr)
        for problem in decision.problems:
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
        runner = CommandRunner(args.command, bundle, profile, reviewer_tolerance=reviewer_tol)

    try:
        report = reproduce_bundle(raw, runner, profile=profile, **trust_kw)      # the bytes as read (SPEC 4)
    except ReproduceError as exc:
        # a named gap: inputs/result withheld, or the capability is not available to this runner.
        if args.json:
            return _emit_json_error(args.bundle, "cannot-reproduce", EXIT_NOT_REPRODUCED,
                                    error=str(exc), integrity_ok=True, gate=decision.summary())
        print(f"reproduce: {args.bundle}", file=sys.stderr)
        print(f"  cannot reproduce: {exc}", file=sys.stderr)
        return EXIT_NOT_REPRODUCED
    except Exception as exc:  # noqa: BLE001 -- reproduction re-runs arbitrary producer/reviewer code
        if args.json:
            return _emit_json_error(args.bundle, "error", EXIT_NOT_REPRODUCED,
                                    error=f"{type(exc).__name__}: {exc}", integrity_ok=True, gate=decision.summary())
        print(f"reproduce: {args.bundle}", file=sys.stderr)
        print(f"  reproduction could not finish: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_NOT_REPRODUCED

    # stash the sealed result core for the printer (read here, once, from the verified bundle)
    report["_sealed_core"] = _result_core(bundle, report.get("capability"))
    report["_output_diffs"] = differing_output_keys(
        bundle, report["_sealed_core"], _result_core(report.get("fresh_bundle"), report.get("capability")),
        outputs_only=report.get("outputs_only") is True)
    try:
        report["_sealed_full_core"] = bundle["manifest"]["result"]["value"]
    except (KeyError, TypeError):
        report["_sealed_full_core"] = {}
    report["gate"] = decision.summary()          # the same decision reproduce_bundle made, with its policy_source
    code, _shortfalls = _exit_code(report)       # report["shortfalls"] is the library's (certify.reproduction_shortfalls)
    report["_exit_code"] = (EXIT_REJECTED_BY_GATE_MARK if decision.rejected and report.get("result_rederived")
                            else code)
    report["_gate_why"] = decision.why_not()
    if args.json:
        return _emit_json_report(args.bundle, report, code)
    try:
        _print_report(args.bundle, report, sys.stdout)
    except Exception as exc:  # noqa: BLE001 -- the verdict is decided; a detail line must never replace it with a traceback
        print(f"  (a detail of this report could not be printed: {type(exc).__name__}: {exc})", file=sys.stdout)
        print(f"  RESULT: {_RESULT_WORD.get(code, 'NOT reproduced')} (exit {code})", file=sys.stdout)
    if code == EXIT_PARTIAL:
        print(f"  exit {EXIT_PARTIAL}: PARTIAL, NOT a reproduction -- see the reasons above. Only exit 0 is a pass.",
              file=sys.stdout)
    print(f"    policy: {_ps.describe(trust.source)}; policy_sha256 {decision.policy_sha256}")
    return code


if __name__ == "__main__":
    # `python -m` without -P: say the cwd could shadow this tool (stderr only; see _spec_loader)
    from proof_verify._spec_loader import warn_if_cwd_on_path
    warn_if_cwd_on_path()
    raise SystemExit(main())
