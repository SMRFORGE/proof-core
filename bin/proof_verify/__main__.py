"""``python -m proof_verify <bundle.json>`` -- verify an evidence bundle with the standalone
verifier. Imports nothing but the stdlib and this package's own ``verify`` (no producer code), so a
passing check is a genuine second opinion, not the producer marking its own homework.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

# The parse-time guards (duplicate-key / NaN / depth / size) live in ONE place, `verify.loads`, so every
# bundle reader shares them. Re-exported here (``cli._text_depth_ok``, ``cli.loads``) for callers/tests
# that reach for them on the CLI module.
from .verify import (  # noqa: F401 -- re-exported for backward-compatible access
    _MAX_JSON_DEPTH,
    _reject_duplicate_keys,
    _reject_non_finite,
    _text_depth_ok,
    classify_bundle,
    key_label,
    loads,
    pin_key,
    pinned_key_fingerprint,
)

_USAGE = ("usage: proof-verify <bundle.json> [--profile pkg.module:attr] [--pubkey HEX]   "
          "(or: python -m proof_verify ...)")

#: Exit codes. 0 is reserved for INTEGRITY + ORIGIN (a valid signature under a real PRODUCTION pin),
#: so a `verify && trust` gate never lets a non-production record through. While proof-core pins the
#: public DEMO identity, origin can never be established, so a pin-signed bundle exits 3, not 0. The
#: integrity-only state gets its OWN nonzero code -- distinct from 1 (a genuine integrity failure:
#: edited, forged, malformed) and from 2 (usage / the file could not be read or parsed), so a script
#: can tell "untampered, but origin not established" apart from both without parsing the text.
EXIT_VERIFIED = 0
EXIT_FAIL = 1
EXIT_UNREADABLE = 2
EXIT_INTEGRITY_ONLY = 3

#: the JSON `kind` discriminator for a verify verdict, so an agent can tell verdict shapes apart and detect
#: schema evolution. Bump the trailing version if the verify JSON contract changes shape.
VERIFY_VERDICT_KIND = "proof_core.verify_verdict.v1"


def _print_attestations(rep: dict) -> None:
    """Show human sign-offs (countersignatures) if the bundle carries any -- a separate dimension from the
    decision's integrity/origin above. Every sign-off is reported with the SAME honest boundary the origin
    check carries: a valid Ed25519 signature proves only that the key-holder signed this exact decision, not
    that the key belongs to the named person (that is an approver-registry / hardware-key / SSO question)."""
    atts = rep.get("attestations") or []
    if not atts:
        return
    print(f"    human sign-offs ({len(atts)}):")
    for a in atts:
        if a.get("valid"):
            print(f"      - {a.get('name')} ({a.get('role')}): valid under the key it carries; "
                  "approver identity NOT established")
        else:
            print(f"      - {a.get('name')} ({a.get('role')}): INVALID -- this sign-off does not verify")
    if not rep.get("attestations_ok", True):
        print("    NOTE: a sign-off did not verify. Until approver keys are pinned, even a valid sign-off")
        print("          establishes only that the key-holder signed; binding a key to a named person is an")
        print("          identity step (an approver registry).")


def _attestation_gate(rep: dict, code: int) -> int:
    """A present-but-INVALID human sign-off must fail the CLI closed: a forged or edited countersignature
    rides a bundle whose decision seal is still intact, so integrity/origin alone would exit 0 (or 3) and a
    `verify && trust` gate would wave the forged sign-off through. If any sign-off does not verify, override
    the exit code to FAIL -- the decision is untampered, but a claim of human approval on it is not."""
    if not rep.get("attestations_ok", True):
        print("FAIL  a human sign-off on this bundle does not verify -- failing closed.", file=sys.stderr)
        return EXIT_FAIL
    return code


def _json_exit_code(rep: dict) -> int:
    """The SAME exit code the prose path returns, computed purely (no printing). Integrity failure -> 1;
    else integrity+origin -> 0 or integrity-only -> 3; then the attestation gate overrides a present-but-
    INVALID human sign-off to 1 (exactly as ``_attestation_gate`` does for the prose branches)."""
    if not rep["integrity_ok"]:
        return EXIT_FAIL
    code = EXIT_VERIFIED if rep["origin_ok"] else EXIT_INTEGRITY_ONLY
    if not rep.get("attestations_ok", True):
        return EXIT_FAIL
    return code


def _emit_json(path: str, bundle: dict, rep: dict) -> int:
    """Emit the machine-readable verdict (the classify_bundle report plus a few CLI-level facts) and return
    the matching exit code. The demo-pin / not-a-production-pass fact is made UNAMBIGUOUS via
    ``production_origin_pass`` so an automated gate never mistakes an integrity-only (exit 3) record for a
    pass. ``default=str`` is a belt-and-braces guard; the report is plain JSON already. Guaranteed-core keys
    present on EVERY verify JSON path (success and the unreadable error): ``kind, path, exit_code,
    integrity_ok, state, production_origin_pass, not_a_production_pass``; an agent gates on ``exit_code`` /
    ``production_origin_pass``, never the ``state`` string."""
    code = _json_exit_code(rep)
    out = dict(rep)
    out["kind"] = VERIFY_VERDICT_KIND
    out["path"] = path
    out["exit_code"] = code
    out["withheld"] = sorted((bundle.get("redaction") or {}).get("withheld", []))
    out["pinned_key_fingerprint"] = pinned_key_fingerprint()
    # the one fact an origin gate keys on: exit 0 under a real PRODUCTION pin is the only pass.
    out["production_origin_pass"] = code == EXIT_VERIFIED
    out["not_a_production_pass"] = code != EXIT_VERIFIED
    # reconcile the headline `state` with the exit code: a present-but-INVALID human sign-off overrides the
    # code to FAIL while classify's `state` still reads integrity-only / integrity+origin (the decision seal
    # is intact). Never let `state` read non-fail while the CLI failed closed -- an agent keying on `state`
    # must see the failure too, not only one keying on exit_code. A genuine integrity fail already reads
    # "fail", so only the attestation-gate override is rewritten.
    if code == EXIT_FAIL and out.get("state") != "fail":
        out["state"] = "fail (invalid sign-off)"
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def verify_path(path: str, *, profile=None, as_json: bool = False) -> int:
    """Verify the bundle JSON at ``path``; print a human-readable result; return an exit code:

      0  verified (integrity + origin): every hash recomputes and the signature is valid under a real
         PRODUCTION pin. The only green. Unreachable while proof-core pins the public demo identity.
      1  FAIL: a hash/seal/schema problem, or the signature is invalid under the key the bundle
         itself carries -- edited, forged or malformed. Never re-derive such a record.
      2  the file could not be read or parsed (or a usage error).
      3  integrity verified, origin NOT established: every hash recomputes and the signature is valid
         under the bundle's own key, but origin is not proven -- either that key is not the pinned one
         (e.g. a dev machine's own key), OR the pin itself is the public demo identity (proof-core's
         shipped default), under which NO bundle can prove origin. Untampered, so `reproduce` can
         re-derive it; not a production pass, so an automated origin gate must still reject it.

    A bundle may also carry human sign-offs (countersignatures). A present-but-INVALID sign-off
    overrides the code above to 1 (FAIL): the decision seal may be intact, but a claim of human
    approval riding on it does not verify, so the CLI fails closed rather than exit 0 or 3.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            # RFC 8259: `NaN` / `Infinity` are not JSON tokens -- Python's parser accepts them by default,
            # a browser's does not. Reject at parse time (like duplicate keys and pathological nesting), so
            # this verifier can never attest a bundle another conformant parser cannot even read.
            bundle = loads(handle.read())
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        # ValueError covers JSONDecodeError + the parse guards (dup key / NaN / depth / size); MemoryError
        # covers an input too large to hold or parse. Either is an UNREADABLE verdict, never a traceback.
        if as_json:
            print(json.dumps({"kind": VERIFY_VERDICT_KIND, "path": path, "state": "unreadable",
                              "integrity_ok": False, "error": f"{type(exc).__name__}: {exc}",
                              "exit_code": EXIT_UNREADABLE, "production_origin_pass": False,
                              "not_a_production_pass": True}, sort_keys=True))
            return EXIT_UNREADABLE
        print(f"error: cannot read bundle {path!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    rep = classify_bundle(bundle, profile=profile)
    if as_json:
        # machine-readable verdict: the SAME exit code as the prose path, no prose printed.
        return _emit_json(path, bundle, rep)
    if not rep["integrity_ok"]:
        print(f"FAIL  {path}", file=sys.stderr)
        for problem in rep["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_FAIL
    if not rep["origin_ok"]:
        # untampered, but origin not established: say exactly that, calmly. The number is still
        # checkable (by re-derivation, not by us). Two shapes: signed under the pin but the pin is the
        # public demo identity (proof-core's normal verdict today), or signed under some other key.
        signer_hex = (rep["signer"] or "").removeprefix("ed25519:")
        if rep.get("pinned_key_is_demo") and rep.get("key_matches_pin"):
            print(f"OK  integrity verified -- origin NOT established (demo pin): {path}")
            print("    every hash recomputes and the Ed25519 signature is valid under the pinned key, so")
            print("    the record is UNEDITED since it was signed. But that pinned key is the public DEMO")
            print("    identity (its seed ships in signing.py); anyone can reproduce a signature under it,")
            print("    so this proves INTEGRITY, not that the record came from a production signer (ORIGIN).")
            print(f"      signed by:  {key_label(signer_hex)}")
            print(f"      pinned key: {pinned_key_fingerprint()}  (public demo key -- not a trust anchor)")
        else:
            print(f"OK  integrity verified -- origin NOT established: {path}")
            print("    every hash recomputes and the Ed25519 signature is valid under the key this bundle")
            print("    carries, so the record is UNEDITED since it was signed -- but that key is not the pin:")
            print(f"      signed by:  {key_label(signer_hex)}")
            print(f"      pinned key: {pinned_key_fingerprint()}")
            print("    Anyone can sign with a public seed, so this proves INTEGRITY, not that the record came")
            print("    from the pinned signer (ORIGIN). Expected for a bundle you signed yourself (on a")
            print("    machine without the pinned signer's key).")
        print(f"    next:  proof-reproduce {path} --runner <your ReproduceRunner>   (or --command \"<cmd>\")")
        print("           re-derives the number from its sealed inputs (integrity holds, so it is safe to re-run)")
        print(f"    exit {EXIT_INTEGRITY_ONLY}: NOT a production pass -- an automated origin gate must reject this.")
        _print_withheld(bundle)
        _print_attestations(rep)
        _print_frontier(rep)
        return _attestation_gate(rep, EXIT_INTEGRITY_ONLY)
    # origin_ok is True only under a real production pin (never under the demo pin), so reaching here
    # means a pinned-production-key signature over an intact bundle.
    print(f"OK  verified (integrity + origin): {path}")
    print(f"    pinned key: {pinned_key_fingerprint()}")
    print("    cross-check this fingerprint against the published trust root before")
    print("    relying on origin -- see docs/TRUST_ROOT.md. Origin holds only if it matches.")
    _print_withheld(bundle)
    _print_attestations(rep)
    _print_frontier(rep)
    return _attestation_gate(rep, EXIT_VERIFIED)


def _print_withheld(bundle: dict) -> None:
    withheld = sorted((bundle.get("redaction") or {}).get("withheld", []))
    if withheld:
        print(f"    NOTE: sections withheld ({', '.join(withheld)}); their values are not present in")
        print("          this bundle -- only their sealed digests were checked, so NO value for those")
        print("          sections (e.g. the result core) was verified here.")


def _print_frontier(rep: dict) -> None:
    """Show the optional frontier assertion slots the bundle sealed, if any. Said honestly: the signature
    proves the producer ASSERTED these and nobody edited them, NOT that the claims are true. Whether the
    model applies (applicability) is the domain adapter's evidence, never something this verifier judges."""
    f = rep.get("frontier") or {}
    app, comp, dfrom = f.get("applicability"), f.get("completeness"), (f.get("derived_from") or [])
    if not (app or comp or dfrom):
        return
    if isinstance(app, dict):
        ind = app.get("in_distribution")
        ind_s = ("in-distribution" if ind is True else "OUT of distribution" if ind is False
                 else "not determined")
        print(f"    applicability: producer asserts assessed={app.get('assessed')}, {ind_s} -- a sealed,")
        print("      tamper-evident PRODUCER claim; NOT verified or vouched for here (whether the model")
        print("      applies to this input is the domain adapter's evidence, not the seal's).")
    if isinstance(comp, dict):
        c = comp.get("complete")
        c_s = ("complete" if c is True else "INCOMPLETE" if c is False else "completeness unknown")
        # defensive only: via the CLI this is unreachable (a non-str item FAILs the shape check, so the
        # printer is never called on such a bundle), but a library caller could hand us an unchecked
        # report -- str() keeps the printer total so verify_path can never throw.
        cap = ", ".join(str(x) for x in (comp.get("captured") or [])) or "(unspecified)"
        print(f"    provenance completeness: {c_s}  (captured: {cap}) -- the producer's declaration.")
    if dfrom:
        print(f"    derived from {len(dfrom)} prior record(s): this bundle is cryptographically bound to their")
        print("      exact seals (editing a link breaks this seal). Verify each independently to walk the chain:")
        for link in dfrom:
            if isinstance(link, dict):
                # a BINDING link records FACTS only (ADR-049): the upstream seal, the role, and WHAT this
                # record consumed from it -- never a verdict about the upstream (that is this walker's call).
                consumed = link.get("consumed") or {}
                print(f"      - {link.get('bundle_sha256')}   (role: {link.get('role')}; consumed "
                      f"{consumed.get('path')} -- re-verify the upstream yourself, not checked here)")


def _resolve_profile(spec: str):
    """Import the reviewer-named ``pkg.module:attr`` dialect Profile and return it (a class is instantiated
    with no args; a constructed Profile is used as-is). Duck-typed and read attribute-only by the verifier,
    so any object carrying the dialect fields works. This imports the CONSUMER's module, NEVER proof_core --
    the verifier stays stdlib-only. Reads ONLY the command-line ``spec``, never the bundle. Raises ValueError
    with a plain reason on failure, so main() can map it to a usage exit."""
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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["-h"], ["--help"]):
        print(_USAGE)
        return 0
    p = argparse.ArgumentParser(prog="proof-verify", add_help=False,
                                description="Independently verify an evidence bundle (integrity + origin).")
    p.add_argument("bundle")
    p.add_argument("--profile", metavar="pkg.module:attr",
                   help="verify under this dialect Profile (duck-typed; needed for a non-neutral bundle)")
    p.add_argument("--pubkey", metavar="HEX",
                   help="pin this 64-hex Ed25519 public key as the origin trust root")
    p.add_argument("--json", action="store_true",
                   help="emit the verdict as a JSON object (same exit code) instead of human text")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        print("error: expected a bundle path", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return EXIT_UNREADABLE
    profile = None
    if ns.profile is not None:
        try:
            profile = _resolve_profile(ns.profile)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_UNREADABLE
    if ns.pubkey is not None:
        try:
            pin_key(ns.pubkey)
        except (ValueError, TypeError) as exc:
            print(f"error: --pubkey must be 64 lowercase hex characters: {exc}", file=sys.stderr)
            return EXIT_UNREADABLE
    return verify_path(ns.bundle, profile=profile, as_json=ns.json)


if __name__ == "__main__":
    raise SystemExit(main())
