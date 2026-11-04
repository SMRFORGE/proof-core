"""``python -m proof_verify <bundle.json>`` -- verify an evidence bundle with the standalone
verifier. Imports nothing but the stdlib and this package's own ``verify`` (no producer code), so a
passing check is a genuine second opinion, not the producer marking its own homework.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# The parse-time guards (duplicate-key / NaN / depth / size) live in ONE place, `verify.loads`, so every
# bundle reader shares them. Re-exported here (``cli._text_depth_ok``, ``cli.loads``) for callers/tests
# that reach for them on the CLI module.
from . import _spec_loader
from . import policy_source as _ps
from .render import (
    RenderError,
    claims_lines,
    decision_hint_lines,
    headline,
    seal_signer_lines,
    signoff_lines,
    time_lines,
)
from .verify import (  # noqa: F401 -- re-exported for backward-compatible access
    _MAX_JSON_DEPTH,
    _SUITE_NAME,
    BUILTIN_DEMO_PINS,
    CHAIN_FAIL,
    CHAIN_INCOMPLETE,
    CHAIN_INTEGRITY_ONLY,
    CHAIN_NONE,
    CHAIN_UNKNOWN,
    DEMO_KEY_ID,
    STATE_UNSUPPORTED_ALG,
    STATE_UNSUPPORTED_CANON,
    PolicyError,
    _classify_parsed,
    _index_upstreams_parsed,
    _int_digits,
    _reject_duplicate_keys,
    _reject_non_finite,
    _text_depth_ok,
    _utc_or_null,
    _verify_chain_parsed,
    effective_policy,
    key_id,
    key_label,
    loads,
    pin_key,
    pinned_key_fingerprint,
    policy_sha256,
    safe_terminal_output,
)

_USAGE = ("usage: proof-verify <bundle.json> [--profile pkg.module:attr] [--pubkey HEX] [--json]\n"
          "                    [--policy FILE | --policy preset:NAME] [--no-policy-discovery]\n"
          "                    [--expect-policy sha256:HEX] [--allow-self-verify] [--as-of T] [--upstream PATH ...]\n"
          "                    (or: python -P -m proof_verify ...;\n"
          "                     -P: under -m Python puts the cwd first on the import\n"
          "                     path, so a planted proof_verify/ or profile module would win)\n"
          "  --profile SPEC   a dialect Profile: pkg.module:attr from the import path (PYTHONPATH / installed),\n"
          "                   or /abs/path/file.py:attr (an absolute path; a relative one exits 2). The current\n"
          "                   directory is never searched (a sender could plant a module in an unpacked bundle\n"
          "                   folder); python -m itself puts the current directory on the path, so there prefer\n"
          "                   the proof-verify script or python -P -m.\n"
          "  --policy FILE    a receiver policy (evidence.receiver-policy.v1) whose pins replace the built-in demo\n"
          "                   pin; --pubkey is then merged into it. A malformed policy exits 2 with no verdict.\n"
          "                   preset:NAME uses a shipped preset only if it needs no filling (none does today:\n"
          "                   use proof-policy init). Without --policy: the file $PROOF_POLICY names, else the\n"
          "                   built-in default policy; no folder is searched (a .proof-policy.json is never read).\n"
          "                   The verdict names the source (policy_source). A malformed PROOF_POLICY file exits 2.\n"
          "  --no-policy-discovery  ignore PROOF_POLICY (also PROOF_NO_POLICY_DISCOVERY=1)\n"
          "  --expect-policy sha256:HEX  exit 2 with no verdict unless the effective policy_sha256 is HEX\n"
          "  --allow-self-verify  accept a verifier or approver sign-off made with an originator's key or signer\n"
          "                   id (sets allow_self_verify in the effective policy; rejected by default).\n"
          "  --as-of T        the evaluation instant, a UTC timestamp YYYY-MM-DDTHH:MM:SSZ (default: now, whole\n"
          "                   seconds); echoed in the JSON verdict. A malformed value exits 2.\n"
          "  --upstream PATH  walk the bundle's derived_from chain through these earlier bundles (a file or a\n"
          "                   folder of *.json; repeatable). Offline: nothing is fetched.")

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
#: ADR-050 fail-FORWARD: the bundle is sealed under a canon_version NEWER than this verifier supports (its
#: header seal + signature are valid; this verifier simply cannot check its sections). Its OWN code, distinct
#: from 1 (a genuine integrity failure) and 3 (integrity-only), so a CI gate or an air-gapped script tells
#: "out of date" from "broken" without parsing text. It is a FAIL for every gate until the verifier is updated.
EXIT_UNSUPPORTED_CANON = 4
#: SPEC v4 13.5: the bundle's header seals, but its only problem is a seal signature suite this verifier does not
#: implement (reserved or unknown). Its OWN code, distinct from 4 (a newer canon) so a gate tells "newer format"
#: from "newer signature suite" without parsing text. A FAIL for every gate, like 4.
EXIT_UNSUPPORTED_ALG = 6
#: CHAIN INCOMPLETE (only with --upstream): the bundle itself verifies, but its derived_from chain could not be
#: fully walked -- a cited earlier record was not supplied, was sealed under a newer canon, or the bundle's
#: provenance is withheld. NOT a pass: nothing about the unwalked links was checked. Its OWN code, distinct
#: from 1 (a link that was checked and does NOT hold), so a gate can tell "supply the missing record" from
#: "the chain is broken".
EXIT_CHAIN_INCOMPLETE = 5

#: the JSON `kind` discriminator for a verify verdict, so an agent can tell verdict shapes apart and detect
#: schema evolution. Bump the trailing version if the verify JSON contract changes shape.
VERIFY_VERDICT_KIND = "proof_core.verify_verdict.v1"


def _withheld_list(bundle) -> list:
    """The withheld section names as a sorted list of strings, or [] when absent/malformed -- the CLI must print a
    verdict on ANY input, never crash formatting a field the verifier already reported as malformed. Reads the v3
    record (`redaction.withheld`) and the v4 record (`redaction.withheld_sections`), and also names any section
    whose manifest value is absent, so a withheld section is never left unreported."""
    if not isinstance(bundle, dict):
        return []
    red = bundle.get("redaction")
    names = set()
    if isinstance(red, dict):
        for key in ("withheld", "withheld_sections"):
            wh = red.get(key)
            if isinstance(wh, list):
                names.update(w for w in wh if isinstance(w, str))
    manifest = bundle.get("manifest")
    if isinstance(manifest, dict):
        names.update(s for s in ("inputs", "result", "provenance")
                     if isinstance(manifest.get(s), dict) and "value" not in manifest[s])
    return sorted(names)


def _withheld_items(rep: dict) -> list:
    """The withheld committed items of a v4 bundle (`items.withheld_paths`, SPEC 6.6.8): [{path, marks}]."""
    items = rep.get("items") if isinstance(rep, dict) else None
    paths = items.get("withheld_paths") if isinstance(items, dict) else None
    return [e for e in paths if isinstance(e, dict)] if isinstance(paths, list) else []


def _print_canon_note(bundle) -> None:
    """ADR-053/054: under canon_version 2 (JCS) the seal covers numeric VALUES, not their spelling, so say so
    next to "UNEDITED" -- a reader must not infer that `1` vs `1.0` in the text was sealed."""
    sums = bundle.get("sha256sums") if isinstance(bundle, dict) else None
    cv = sums.get("canon_version") if isinstance(sums, dict) else None
    if type(cv) is int and cv == 2:
        print("    NOTE: canon v2 seals number VALUES: a whole number written 1, 1.0 or 1e0 verifies the same,")
        print("          so 'UNEDITED' means no value changed, not that the text is byte-identical. A reader")
        print("          may get 2.0 where 2 was sealed; treat whole numbers as interchangeable.")


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


def _primary_signer(rep: dict) -> dict | None:
    """The `signers` entry of the reported `signer` (7.15): the first verified block, or on the newer-canon branch
    (11.6) the primary. None when no block verified."""
    return next((e for e in rep.get("signers") or [] if e.get("checked") and e.get("valid")), None)


def _suite_signature(rep: dict) -> str:
    """"the <suite> signature", named from the suite of the reported signer, never assumed to be Ed25519."""
    first = _primary_signer(rep)
    return f"{_SUITE_NAME.get(first['alg'], first['alg']) if first else 'Ed25519'} signature"


def _pinned_line(rep: dict) -> str:
    """The pin a verified block matched, as the matched pin-set entry's key id. Only on the single-pin path (no policy
    or caller pins) does a match on the module pin keep its legacy fingerprint."""
    matched = next((e for e in rep.get("signers") or []
                    if e.get("checked") and e.get("valid") and e.get("pinned")), None)
    if matched is None:
        return _pins_text(rep)
    if rep.get("pin_set") is None and matched.get("alg") == "ed25519"             and matched.get("key_id") == DEMO_KEY_ID_OF(pinned_key_fingerprint()):
        return pinned_key_fingerprint()
    return matched["key_id"]


def DEMO_KEY_ID_OF(fingerprint: str) -> str:
    return key_id("ed25519", fingerprint.removeprefix("ed25519:"))


def _pins_text(rep: dict) -> str:
    """What the verdict was pinned to: on the single-pin path the pin it used (a --profile's pinned_pubkey, else the
    module pin, as the verdict reports it in ``pinned_key``), else the pin set."""
    ps = rep.get("pin_set")
    if ps is None:
        pk = rep.get("pinned_key")
        return pk if isinstance(pk, str) else pinned_key_fingerprint()
    return "the pin set: " + (", ".join(e["key_id"] for e in ps) if ps else "empty")


def _matched_pins(rep: dict) -> list[str]:
    """The pin(s) the origin decision matched: under a pin set (--policy, --pubkey merged into it) the key id of every
    verified seal signature whose key is pinned, in E order; on the single-pin path the one pin, when it matched."""
    if rep.get("pin_set") is None:
        pk = rep.get("pinned_key")
        return [pk] if rep.get("key_matches_pin") and isinstance(pk, str) else []
    out: list[str] = []
    for e in rep.get("signers") or []:
        if e.get("checked") and e.get("valid") and e.get("pinned") and e.get("key_id") not in out:
            out.append(e["key_id"])
    return out


def _origin_pin_text(rep: dict) -> str:
    """The key(s) actually used for the origin decision: the matched pin(s), else what the verdict was pinned to."""
    matched = _matched_pins(rep)
    return ", ".join(matched) if matched else _pins_text(rep)


def _print_seal_keys(rep: dict, signer_hex: str | None) -> None:
    """The seal signer lines. v4 input (SPEC 13.6): "A seal signer MUST be shown as `sealed by key <key_id>` and
    never as a person's sign-off", one line per verified seal signature. v3 input keeps its v3 line."""
    if rep.get("canon_version") == 3:
        for line in seal_signer_lines(rep):
            print(f"      {line}")
    elif signer_hex is not None:
        print(f"      signed by:  {key_label(signer_hex)}")


def _print_signoffs(rep: dict, policy) -> None:
    """Sign-offs and seal signers. v3 input keeps its v1 rendering (`_print_attestations`) unchanged. v4 input is
    rendered per SPEC 13.6 (`proof_verify.render`): the seal signers as `sealed by key <key_id>`, then each
    sign-off's role, meaning and statement, printed name, signer id, key and roster status, the claimed time, the
    reviewed copy and prior relations, and its validity, with the caveat sentence. Every bundle string goes through
    the escape E. A renderer that cannot show a required field refuses and says so."""
    if rep.get("canon_version") != 3:
        _print_attestations(rep)
        return
    roster = policy.get("roster") if isinstance(policy, dict) else None
    for line in time_lines(rep):
        print(f"    {line}")
    try:
        lines = signoff_lines(rep, roster)
    except RenderError as exc:
        print(f"    sign-offs: cannot render: {exc}", file=sys.stderr)
        return
    for line in lines:
        print(f"    {line}")


def _attestation_gate(rep: dict, code: int) -> int:
    """A present-but-INVALID human sign-off must fail the CLI closed: a forged or edited countersignature
    rides a bundle whose decision seal is still intact, so integrity/origin alone would exit 0 (or 3) and a
    `verify && trust` gate would wave the forged sign-off through. If any sign-off does not verify, override
    the exit code to FAIL -- the decision is untampered, but a claim of human approval on it is not."""
    if rep.get("canon_version") != 3 and not rep.get("attestations_ok", True):
        if rep.get("attestations_null") is True:
            print("FAIL  the bundle's attestations field is present but null (malformed) -- failing closed.",
                  file=sys.stderr)
        else:
            print("FAIL  a human sign-off on this bundle does not verify -- failing closed.", file=sys.stderr)
        return EXIT_FAIL
    reasons = _decision_rejects(rep)
    if reasons:
        print(f"FAIL  the receiver decision rejects this bundle ({', '.join(reasons)}) -- failing closed.")
        return EXIT_FAIL
    return code


def _decision_rejects(rep: dict) -> list[str]:
    """SPEC v4 draft 13.5: a decision reason other than `state_not_accepted` turns exit 0 or 3 into 1."""
    decision = rep.get("decision") or {}
    return [r for r in decision.get("reasons", []) if r != "state_not_accepted"]


def _json_exit_code(rep: dict) -> int:
    """The SAME exit code the prose path returns, computed purely (no printing). Integrity failure -> 1;
    else integrity+origin -> 0 or integrity-only -> 3; then the attestation gate overrides a present-but-
    INVALID human sign-off to 1 (exactly as ``_attestation_gate`` does for the prose branches)."""
    if rep.get("state") == STATE_UNSUPPORTED_CANON:
        return EXIT_UNSUPPORTED_CANON        # unsupported / use a newer verifier -- not an integrity failure
    if rep.get("state") == STATE_UNSUPPORTED_ALG:
        return EXIT_UNSUPPORTED_ALG          # an unimplemented signature suite -- not an integrity failure
    if not rep["integrity_ok"]:
        return EXIT_FAIL
    code = EXIT_VERIFIED if rep["origin_ok"] else EXIT_INTEGRITY_ONLY
    if not rep.get("attestations_ok", True) or _decision_rejects(rep):
        return EXIT_FAIL
    return code


def _now_utc() -> str:
    """SPEC 7.13: the default `as_of`, the current time floored to whole seconds."""
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _emit_json(path: str, bundle: dict, rep: dict, chain: dict | None = None, as_of: str | None = None,
               policy_source: dict | None = None) -> int:
    """Emit the machine-readable verdict (the classify_bundle report plus a few CLI-level facts) and return
    the matching exit code. The demo-pin / not-a-production-pass fact is made UNAMBIGUOUS via
    ``production_origin_pass`` so an automated gate never mistakes an integrity-only (exit 3) record for a
    pass. ``default=str`` is a belt-and-braces guard; the report is plain JSON already. Guaranteed-core keys
    present on EVERY verify JSON path (success and the unreadable error): ``kind, path, exit_code,
    integrity_ok, state, production_origin_pass, not_a_production_pass``; an agent gates on ``exit_code`` /
    ``production_origin_pass``, never the ``state`` string."""
    code = _chain_gate(chain, _json_exit_code(rep))
    out = dict(rep)
    if chain is not None:
        out["chain"] = chain
    out["kind"] = VERIFY_VERDICT_KIND
    out["path"] = path
    out["exit_code"] = code
    out["as_of"] = rep.get("as_of") or as_of or _now_utc()     # SIG-29: the output echoes the as_of used
    out["withheld"] = _withheld_list(bundle)
    # what this run did NOT check: the values of withheld sections and of withheld committed items (only their
    # sealed digests / commitments were checked)
    out["withheld_items"] = [e.get("path") for e in _withheld_items(rep)]
    out["not_checked"] = ([f"section {s}" for s in out["withheld"]]
                          + [f"item {e.get('path')}" for e in _withheld_items(rep)])
    # the key the ORIGIN decision used, never the module pin when a --profile or --policy supplied the pin: on the
    # single-pin path the profile / module pin; under a pin set the first matched pin (null when none matched).
    # `matched_pins` lists every pin a verified seal signature matched.
    out["pinned_key_fingerprint"] = (_pins_text(rep) if rep.get("pin_set") is None
                                     else (_matched_pins(rep) or [None])[0])
    out["matched_pins"] = _matched_pins(rep)
    # the one fact an origin gate keys on: exit 0 under a real PRODUCTION pin is the only pass.
    out["production_origin_pass"] = code == EXIT_VERIFIED
    out["not_a_production_pass"] = code != EXIT_VERIFIED
    if policy_source is not None:
        out["policy_source"] = policy_source            # which policy this verdict was made under (policy_source.py)
    # SPEC v4 draft 13.5: `state` is ALWAYS the 13.1 state, never rewritten -- the former strings
    # "fail (invalid sign-off)", "fail (chain)" and "incomplete (chain)" are retired for every input. Why the CLI
    # failed closed is in `exit_code`, `decision` (reasons such as `signoffs_invalid`), `dims` and the `chain`
    # member (set above when --upstream walked a chain). Exit codes are unchanged.
    print(json.dumps(out, sort_keys=True, default=str))
    return code


def _policy_error(exc: Exception, as_json: bool, source: dict | None = None) -> int:
    """SPEC 13.4.1: a malformed policy is refused; "the CLI exits 2 with no verdict". Runner protocol v2 (13.3):
    print ``{"error": "<kind>", "message": "..."}`` with no ``state``. A policy not named by ``--policy FILE`` (a
    preset, or a discovered one) also names its source, so the refusal says which file was read; the output for
    ``--policy FILE`` is unchanged."""
    kind = getattr(exc, "kind", "policy")       # "policy" (malformed) or "policy_unsupported" (not evaluated by this release)
    msg = str(exc)
    shown = source is not None and source["kind"] != "flag"
    if shown and _ps.describe(source) not in msg:
        msg = f"{msg} ({_ps.describe(source)})"
    if as_json:
        out = {"error": kind, "message": msg}
        if shown:
            out["policy_source"] = source
        print(json.dumps(out, sort_keys=True))
    else:
        print(f"error: policy refused: {msg}", file=sys.stderr)
    return EXIT_UNREADABLE


def _source_member(source: dict | None) -> dict:
    return {} if source is None else {"policy_source": source}


def _expect_refused(expect: str | None, actual: str | None, source: dict, as_json: bool) -> int | None:
    """--expect-policy: EXIT_UNREADABLE (2, no verdict) when the effective policy_sha256 is not ``expect``."""
    if expect is None or actual == expect:
        return None
    exc = _ps.PolicyMismatch(f"--expect-policy {expect}: the effective policy ({_ps.describe(source)}) has "
                             f"policy_sha256 {actual}; no verdict is given under a policy other than the one expected")
    if as_json:
        print(json.dumps({"error": exc.kind, "message": str(exc), "expected": expect, "policy_sha256": actual,
                          "policy_source": source}, sort_keys=True))
    else:
        print(f"error: policy refused: {exc}", file=sys.stderr)
    return EXIT_UNREADABLE


def verify_path(path: str, *, profile=None, as_json: bool = False, upstreams: list[str] | None = None,
                policy=None, pins=None, as_of: str | None = None, policy_source: dict | None = None,
                expect_policy: str | None = None) -> int:
    """See `_verify_path`. In text mode everything printed is escaped to printable ASCII (`safe_text`): problem
    lists and link details carry bundle text, and a bundle must never drive the reader's terminal.

    ``policy_source`` (from `policy_source.resolve`) is reported with the verdict: the ``policy_source`` member in
    JSON, a final ``policy:`` line in text. ``expect_policy`` (``sha256:<64 hex>``) refuses with exit 2 and no
    verdict unless the verdict's ``policy_sha256`` equals it. Neither changes the verdict."""
    with safe_terminal_output(enabled=not as_json):
        return _verify_path(path, profile=profile, as_json=as_json, upstreams=upstreams, policy=policy, pins=pins,
                            as_of=as_of, policy_source=policy_source, expect_policy=expect_policy)


def _verify_path(path: str, *, profile=None, as_json: bool = False, upstreams: list[str] | None = None,
                 policy=None, pins=None, as_of: str | None = None, policy_source: dict | None = None,
                 expect_policy: str | None = None) -> int:
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
      4  UNSUPPORTED CANON (ADR-050): the bundle is sealed under a canon_version newer than this verifier
         supports. Its header seal and signature are valid -- it is NOT tampered -- but this verifier
         cannot recompute its sections under that newer canon. Use a newer verifier; a gate must reject
         this until the verifier is updated (it is not a pass).
      5  CHAIN INCOMPLETE (only with ``upstreams``): the bundle verifies, but a cited earlier record was not
         supplied (or could not be checked), so part of its derived_from chain was NOT walked. Not a pass.
      6  UNSUPPORTED ALG (SPEC v4 13.5): the header seals, but the only problem is a seal signature suite this
         verifier does not implement (reserved or unknown). Integrity and origin are undetermined; use a newer
         verifier. Not a pass.

    With ``upstreams`` (paths to earlier bundles, or folders of them), the bundle's derived_from chain is also
    walked offline (``verify_chain``): a link that does not hold fails the run (1), an unwalked link leaves it
    incomplete (5), and a chain whose weakest link is integrity-only caps the code at 3.

    A bundle may also carry human sign-offs (countersignatures). A present-but-INVALID sign-off
    overrides the code above to 1 (FAIL): the decision seal may be intact, but a claim of human
    approval riding on it does not verify, so the CLI fails closed rather than exit 0 or 3.
    """
    try:
        with open(path, "rb") as handle:
            # BYTES, decoded as strict UTF-8 here: no newline translation (the size cap counts the file's real
            # bytes) and an invalid byte is UNREADABLE (UnicodeDecodeError is a ValueError), never U+FFFD.
            # RFC 8259: `NaN` / `Infinity` are not JSON tokens -- Python's parser accepts them by default,
            # a browser's does not. Reject at parse time (like duplicate keys and pathological nesting), so
            # this verifier can never attest a bundle another conformant parser cannot even read.
            bundle = loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        # ValueError covers JSONDecodeError + the parse guards (dup key / NaN / depth / size); MemoryError
        # covers an input too large to hold or parse. Either is an UNREADABLE verdict, never a traceback.
        if as_json:
            print(json.dumps({"kind": VERIFY_VERDICT_KIND, "path": path, "state": "unreadable",
                              "integrity_ok": False, "error": f"{type(exc).__name__}: {exc}",
                              "exit_code": EXIT_UNREADABLE, "production_origin_pass": False,
                              "not_a_production_pass": True, **_source_member(policy_source)}, sort_keys=True))
            return EXIT_UNREADABLE
        print(f"error: cannot read bundle {path!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE
    ups = None
    if upstreams is not None:
        try:
            ups = _load_upstreams(upstreams)
        except ValueError as exc:
            if as_json:
                print(json.dumps({"kind": VERIFY_VERDICT_KIND, "path": path, "state": "unreadable",
                                  "integrity_ok": False, "error": str(exc),
                                  "exit_code": EXIT_UNREADABLE, "production_origin_pass": False,
                                  "not_a_production_pass": True, **_source_member(policy_source)},
                                 sort_keys=True))
                return EXIT_UNREADABLE
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_UNREADABLE
    try:
        # the subject was read with the hardened loader above (`loads`: SPEC 4), so the private parsed-object path
        # is the public one's verdict on these bytes
        rep = _classify_parsed(bundle, profile=profile, policy=policy, pins=pins, as_of=as_of)
    except PolicyError as exc:
        return _policy_error(exc, as_json, policy_source)
    # --expect-policy: the verdict records the policy_sha256 it was made under (13.4.2); nothing is printed unless it
    # is the one the receiver meant
    refused = _expect_refused(expect_policy, rep.get("policy_sha256"), policy_source or {"kind": "default"}, as_json)
    if refused is not None:
        return refused
    # SPEC 9.3: every upstream is judged under the SAME trust inputs as the root (policy pins, origin quorum, required
    # suites, aging at as_of), never under the profile pin alone
    judge = {"profile": profile, "policy": policy, "pins": pins, "as_of": as_of}
    chain = None if ups is None else _verify_chain_parsed(bundle, _index_upstreams_parsed(ups, **judge).get, **judge)
    if as_json:
        # machine-readable verdict: the SAME exit code as the prose path, no prose printed.
        return _emit_json(path, bundle, rep, chain, as_of, policy_source)
    try:
        return _verify_text(path, bundle, rep, chain, ups, policy)
    finally:
        if policy_source is not None:
            print(f"    policy: {_ps.describe(policy_source)}; policy_sha256 {rep.get('policy_sha256')}")


def _verify_text(path: str, bundle, rep: dict, chain: dict | None, ups: list | None, policy) -> int:
    """The human-readable verdict of `_verify_path` (unchanged; moved here so the policy line follows it)."""
    if rep.get("state") == STATE_UNSUPPORTED_CANON:
        # ADR-050 fail-FORWARD: a signed record sealed under a canon this verifier does not support. The
        # header seals and its signature verifies, so the sha256sums header is unedited since signing -- but
        # this verifier LACKS that canon and cannot recompute the sections, so it does NOT (and cannot) say
        # the record is untampered. Per Decision 4, report whether the version claim is signed under the PIN.
        # The primary's own suite and key id (11.6 checks it under the 7.5 suite table), and the pin it matched in the
        # effective pin set, demo or not (the `signers` entry, 7.15)
        primary = _primary_signer(rep) or {}
        signed_under_pin = bool(primary.get("pinned"))
        print(f"UNSUPPORTED  {path}", file=sys.stderr)
        print(f"    this bundle declares canon_version {rep.get('canon_version')}; this verifier supports up to "
              f"{rep.get('supported_canon_max')}.", file=sys.stderr)
        print(f"    its sha256sums header seals and the {_suite_signature(rep)} over it verifies, so the header is",
              file=sys.stderr)
        print("    UNEDITED since signing -- but this verifier lacks that canon, so it CANNOT recompute or", file=sys.stderr)
        print("    vouch for the inputs / result / provenance sections. This is not a claim that the record", file=sys.stderr)
        print("    is untampered; it is this verifier saying it cannot check it.", file=sys.stderr)
        if signed_under_pin and not primary.get("demo"):
            what = "the pinned production key" if rep.get("pin_set") is None else "a non-demo pin of the receiver policy"
            print(f"    the version claim IS signed under {what} ({_pinned_line(rep)}),", file=sys.stderr)
            print("    so it comes from a trusted origin: get a newer verifier and re-check.", file=sys.stderr)
        elif signed_under_pin and primary.get("alg") == "ed25519":
            print("    the version claim is signed under the pinned key, but that pin is the public DEMO identity", file=sys.stderr)
            print("    (anyone can sign under it), so this proves integrity of the header, not a trusted origin.", file=sys.stderr)
        elif signed_under_pin:
            print(f"    the version claim is signed under {key_label(primary.get('key_id'))}, a demo pin", file=sys.stderr)
            print("    (anyone can sign under it), so this proves integrity of the header, not a trusted origin.", file=sys.stderr)
        else:
            print(f"    WARNING: the signature is NOT under {'the pinned key' if rep.get('pin_set') is None else 'a pinned key'} "
                  f"({_pins_text(rep)}); it is", file=sys.stderr)
            print(f"    {key_label(primary.get('key_id'))}. This canon_version claim is not from a trusted origin and could be", file=sys.stderr)
            print('    attacker-planted -- do not read "use a newer verifier" as trust in this record.', file=sys.stderr)
        # any unsigned top-level keys riding outside the seal (ADR-050 trust-surface check on fail-forward)
        for problem in rep.get("problems", []):
            if "unexpected top-level keys" in problem:
                print(f"    - {problem}", file=sys.stderr)
        print(f"    exit {EXIT_UNSUPPORTED_CANON}: NOT a pass -- a gate must reject this until the verifier is updated.",
              file=sys.stderr)
        return EXIT_UNSUPPORTED_CANON
    if rep.get("state") == STATE_UNSUPPORTED_ALG:
        print(f"UNSUPPORTED  {path}", file=sys.stderr)
        print("    signed with a signature suite this verifier cannot check (a newer/unknown algorithm).",
              file=sys.stderr)
        print("    integrity and origin are UNDETERMINED -- NOT a claim the record is untampered, NOT a pass.",
              file=sys.stderr)
        for problem in rep["problems"]:
            print(f"    - {problem}", file=sys.stderr)
        print(f"    exit {EXIT_UNSUPPORTED_ALG}: NOT a pass -- use a newer verifier.", file=sys.stderr)
        return EXIT_UNSUPPORTED_ALG
    if not rep["integrity_ok"]:
        print(f"FAIL  {path}", file=sys.stderr)
        for problem in rep["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        if isinstance(bundle, dict) and "attestations" in bundle:
            print("  sign-offs are not shown: the record failed integrity, so nothing on it is presented as signed.",
                  file=sys.stderr)
        return EXIT_FAIL
    # SPEC 13.5 "Human-readable headline": when the decision turns the exit into 1, the first line names the first
    # reason other than `state_not_accepted`; the verdict lines below then lose their "OK" mark.
    hl = headline((rep.get("decision") or {}).get("reasons") or [])
    lead = "OK  "
    if hl is not None:
        print(f"FAIL  {hl}: {path}")
        lead = "    "
    if not rep["origin_ok"]:
        # untampered, but origin not established: say exactly that, calmly. The number is still
        # checkable (by re-derivation, not by us). Two shapes: signed under the pin but the pin is the
        # public demo identity (proof-core's normal verdict today), or signed under some other key.
        signer_hex = (rep["signer"] or "").removeprefix("ed25519:")
        if rep.get("pinned_key_is_demo") and rep.get("key_matches_pin"):
            print(f"{lead}integrity verified -- origin NOT established (demo pin): {path}")
            _print_withheld(bundle, rep)
            print(f"    every hash recomputes and the {_suite_signature(rep)} is valid under the pinned key, so")
            print("    the record is UNEDITED since it was signed. But that pinned key is the public DEMO")
            print("    identity (its seed ships in signing.py); anyone can reproduce a signature under it,")
            print("    so this proves INTEGRITY, not that the record came from a production signer (ORIGIN).")
            _print_seal_keys(rep, signer_hex)
            print(f"      pinned key: {_pinned_line(rep)}  (public demo key -- not a trust anchor)")
        elif rep.get("key_matches_pin"):
            # a verified seal signature IS under a pinned (non-demo) key, but the receiver policy's origin rules
            # (quorum, required suites, aging; SPEC 7.13) are not met: say so, never "that key is not the pin"
            print(f"{lead}integrity verified -- origin NOT established: {path}")
            _print_withheld(bundle, rep)
            print(f"    every hash recomputes and the {_suite_signature(rep)} is valid under a PINNED key, so the")
            print("    record is UNEDITED since it was signed -- but origin does not hold under this receiver policy:")
            for problem in rep.get("origin_problems") or []:
                print(f"      - {problem}")
            if any("aged suite or hash" in p for p in rep.get("origin_problems") or []):
                print("    the signature has AGED under the pinned key: its suite or hash is past its trusted_until at")
                print(f"    as_of {rep.get('as_of')}, and no valid archive shows that it existed before then (SPEC 7.13).")
            _print_seal_keys(rep, signer_hex)
        else:
            print(f"{lead}integrity verified -- origin NOT established: {path}")
            _print_withheld(bundle, rep)
            print(f"    every hash recomputes and the {_suite_signature(rep)} is valid under the key this bundle")
            print("    carries, so the record is UNEDITED since it was signed -- but that key is not the pin:")
            _print_seal_keys(rep, signer_hex)
            print(f"      pinned key: {_pins_text(rep)}")
            print("    Anyone can sign with a public seed, so this proves INTEGRITY, not that the record came")
            print("    from the pinned signer (ORIGIN). Expected for a bundle you signed yourself (on a")
            print("    machine without the pinned signer's key).")
        print(f"    next:  proof-reproduce {path} --runner <your ReproduceRunner>   (or --command \"<cmd>\")")
        print("           re-derives the number from its sealed inputs (integrity holds, so it is safe to re-run)")
        if hl is None:
            print(f"    exit {EXIT_INTEGRITY_ONLY}: NOT a production pass -- an automated origin gate must reject this.")
        else:
            print(f"    exit {EXIT_FAIL}: the receiver decision rejects this record ({hl}); see the first line.")
        _print_canon_note(bundle)
        _print_signoffs(rep, policy)
        _print_frontier(rep, walked=chain is not None)
        for line in claims_lines(rep, bundle) + decision_hint_lines(rep):
            print(f"    {line}")
        _print_chain(chain, len(ups or []))
        return _chain_gate(chain, _attestation_gate(rep, EXIT_INTEGRITY_ONLY), announce=True)
    # origin_ok is True only under a real production pin (never under the demo pin), so reaching here
    # means a pinned-production-key signature over an intact bundle.
    print(f"{lead}verified (integrity + origin): {path}")
    _print_withheld(bundle, rep)
    basis = rep.get("origin_basis") or "current"
    if basis.startswith("archived-before:"):
        # SPEC 13.6 "Origin through the archive": never let a rescued origin read like a current one
        t0 = basis.removeprefix("archived-before:")
        print(f"    ORIGIN THROUGH THE ARCHIVE: a seal signature's suite or hash has aged at as_of {rep.get('as_of')};")
        print(f"    origin holds only through the archive, which shows the seal signatures existed no later than {t0}")
        print("    (archive rescue, SPEC 7.13). It is only as good as the archive's TSAs.")
    _print_seal_keys(rep, None)
    print(f"    pinned key: {_origin_pin_text(rep)}")
    print("    cross-check this fingerprint against the published trust root before")
    print("    relying on origin -- see docs/TRUST_ROOT.md. Origin holds only if it matches.")
    _print_canon_note(bundle)
    _print_signoffs(rep, policy)
    _print_frontier(rep, walked=chain is not None)
    for line in claims_lines(rep, bundle) + decision_hint_lines(rep):
        print(f"    {line}")
    _print_chain(chain, len(ups or []))
    return _chain_gate(chain, _attestation_gate(rep, EXIT_VERIFIED), announce=True)


#: The most withheld item paths the text output lists (the JSON lists every one).
_MAX_PRINTED_ITEMS = 20


def _print_withheld(bundle: dict, rep: dict | None = None) -> None:
    """Say plainly what this run did NOT check: withheld sections and withheld committed items."""
    withheld = _withheld_list(bundle)
    if withheld:
        print(f"    NOTE: sections withheld ({', '.join(withheld)}): NOT CHECKED. Their values are not present in")
        print("          this bundle -- only their sealed digests were checked, so NO value for those")
        print("          sections (e.g. the result core) was verified here. 'UNEDITED' below covers only what is")
        print("          present.")
    items = _withheld_items(rep or {})
    if items:
        print(f"    NOTE: {len(items)} committed item(s) withheld: NOT CHECKED. Only their sealed commitments were")
        print("          checked; the withheld values are not in this bundle and were not verified here")
        print("          ('UNEDITED' below covers only what is present):")
        for e in items[:_MAX_PRINTED_ITEMS]:
            marks = e.get("marks") or []
            print(f"            {e.get('path')}" + (f"  (marks: {', '.join(str(m) for m in marks)})" if marks else ""))
        if len(items) > _MAX_PRINTED_ITEMS:
            print(f"            ... and {len(items) - _MAX_PRINTED_ITEMS} more (see --json)")


def _print_frontier(rep: dict, *, walked: bool = False) -> None:
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
        if walked:
            print("      exact seals (editing a link breaks this seal). Walked below against the supplied records:")
        else:
            print("      exact seals (editing a link breaks this seal). They are NOT checked by this run; walk the")
            print("      chain with:  proof-verify <this bundle> --upstream <the earlier bundles, or their folder>")
        for link in dfrom:
            if isinstance(link, dict):
                # a BINDING link records FACTS only (ADR-049): the upstream seal, the role, and WHAT this
                # record consumed from it -- never a verdict about the upstream (that is this walker's call).
                consumed = link.get("consumed") or {}
                tail = "" if walked else " -- not checked here"
                print(f"      - {link.get('bundle_sha256')}   (role: {link.get('role')}; consumed "
                      f"{consumed.get('path')}{tail})")


def _read_bundle_file(path: str):
    """Read one bundle with the SAME hardened loader as the subject (strict UTF-8, duplicate keys, NaN,
    depth, size, digit limit). Raises ValueError with a plain reason on any failure."""
    try:
        with open(path, "rb") as handle:
            return loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        raise ValueError(f"cannot read upstream bundle {path!r}: {type(exc).__name__}: {exc}") from exc


def _load_upstreams(paths: list[str]) -> list:
    """The supplied earlier bundles: each PATH is a bundle file, or a folder whose *.json files (not recursive)
    are all read. Any unreadable file is an error (fail closed: a record the reviewer handed over but this run
    could not read must not silently drop out of the walk)."""
    bundles = []
    for p in paths:
        if os.path.isdir(p):
            files = sorted(os.path.join(p, f) for f in os.listdir(p) if f.lower().endswith(".json"))
            if not files:
                raise ValueError(f"--upstream folder {p!r} holds no *.json files")
            bundles.extend(_read_bundle_file(f) for f in files)
        else:
            bundles.append(_read_bundle_file(p))
    return bundles


def _chain_gate(chain: dict | None, code: int, *, announce: bool = False) -> int:
    """Fold the chain walk into the exit code. Only a passing single-bundle code (0 / 3) is ever changed: a
    link that does not hold -> 1, an unwalked link -> 5, an integrity-only link caps a 0 at 3. No chain
    report (no --upstream), or a bundle that cites nothing, leaves the code as it was."""
    if chain is None or code not in (EXIT_VERIFIED, EXIT_INTEGRITY_ONLY):
        return code
    c = chain.get("chain")
    if c == CHAIN_FAIL:
        if announce:
            print("FAIL  the derived_from chain does not hold (see the links above) -- failing closed.",
                  file=sys.stderr)
        return EXIT_FAIL
    if c in (CHAIN_INCOMPLETE, CHAIN_UNKNOWN):
        if announce:
            print(f"INCOMPLETE  part of the derived_from chain was not walked -- exit {EXIT_CHAIN_INCOMPLETE}: "
                  "NOT a pass; supply the missing earlier records.", file=sys.stderr)
        return EXIT_CHAIN_INCOMPLETE
    if c == CHAIN_INTEGRITY_ONLY and code == EXIT_VERIFIED:
        return EXIT_INTEGRITY_ONLY
    return code


def _print_chain(chain: dict | None, supplied: int) -> None:
    """Print the walk: one line per link with its verdict, then any chain-level problems."""
    if chain is None:
        return
    if chain.get("chain") == CHAIN_NONE:
        print("    chain: this bundle cites no earlier records (no derived_from), so --upstream had nothing to walk.")
        return
    links = chain.get("links") or []
    print(f"    chain walk: {chain.get('chain')}  ({len(links)} link(s); {supplied} earlier record(s) supplied)")
    for e in links:
        print(f"      - {e.get('bundle_sha256')}  depth {e.get('depth')}: {e.get('state')} -- {e.get('detail')}")
    for problem in chain.get("problems") or []:
        print(f"      problem: {problem}")
    print("    the walk checks each cited record's own seal and that the value this bundle says it consumed is")
    print("    that record's result. It does not judge whether the earlier computation was right.")


def _resolve_profile(spec: str):
    """Import the reviewer-named ``pkg.module:attr`` dialect Profile and return it (a class is instantiated
    with no args; a constructed Profile is used as-is). Duck-typed and read attribute-only by the verifier,
    so any object carrying the dialect fields works. This imports the CONSUMER's module, NEVER proof_core --
    the verifier stays stdlib-only. Reads ONLY the command-line ``spec``, never the bundle. Raises ValueError
    with a plain reason on failure, so main() can map it to a usage exit."""
    module_name, attr_path = _spec_loader.split_spec(spec, "--profile", "pkg.module:attr")
    # The current directory is NEVER added to the import path: a sender-planted `acme_profile.py` in an
    # unpacked bundle folder would otherwise pin the sender's key and read as an origin pass. A module comes
    # from the normal import path (PYTHONPATH / installed); a file is named by an absolute path, `/abs/path/file.py:attr`.
    try:
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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # SPEC 4.2 item 8: reading, canonicalizing and printing never depend on PYTHONINTMAXSTRDIGITS
    with safe_terminal_output(enabled="--json" not in args), _int_digits():
        return _main(args)


def _main(args: list[str]) -> int:
    if args[:1] in (["-h"], ["--help"]):
        print(_USAGE)
        return 0
    p = argparse.ArgumentParser(prog="proof-verify", add_help=False,
                                description="Independently verify an evidence bundle (integrity + origin).")
    p.add_argument("bundle")
    p.add_argument("--profile", metavar="pkg.module:attr",
                   help="verify under this dialect Profile (duck-typed; needed for a non-neutral bundle); "
                        "import path only, never the current directory, or /abs/path/file.py:attr")
    p.add_argument("--pubkey", metavar="HEX",
                   help="pin this 64-hex Ed25519 public key as the origin trust root")
    p.add_argument("--json", action="store_true",
                   help="emit the verdict as a JSON object (same exit code) instead of human text")
    p.add_argument("--policy", metavar="FILE",
                   help="a receiver policy JSON file (evidence.receiver-policy.v1); its pins replace the demo pin")
    p.add_argument("--no-policy-discovery", dest="no_policy_discovery", action="store_true",
                   help="do not read PROOF_POLICY (only --policy, else the default policy)")
    p.add_argument("--expect-policy", dest="expect_policy", metavar="sha256:HEX",
                   help="exit 2 with no verdict unless the effective policy's policy_sha256 is this")
    p.add_argument("--allow-self-verify", dest="allow_self_verify", action="store_true",
                   help="accept a verifier/approver sign-off under an originator's key or signer id (SPEC 13.5)")
    p.add_argument("--as-of", dest="as_of", metavar="T",
                   help="the evaluation instant, a UTC timestamp YYYY-MM-DDTHH:MM:SSZ (default: now)")
    p.add_argument("--upstream", action="append", metavar="PATH",
                   help="an earlier bundle (or a folder of them) to walk the derived_from chain through; repeatable")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        print("error: expected a bundle path", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return EXIT_UNREADABLE
    if ns.as_of is not None and not _utc_or_null(ns.as_of):
        # SPEC 13.5: "A malformed value is a usage error with exit 2."
        msg = f"--as-of must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ (SPEC 2.3): {ns.as_of!r}"
        if ns.json:
            print(json.dumps({"error": "usage", "message": msg}, sort_keys=True))
        else:
            print(f"error: {msg}", file=sys.stderr)
        return EXIT_UNREADABLE
    profile = None
    if ns.profile is not None:
        try:
            profile = _resolve_profile(ns.profile)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_UNREADABLE
    bad = _ps.check_expect(ns.expect_policy)
    if bad:
        if ns.json:
            print(json.dumps({"error": "usage", "message": bad}, sort_keys=True))
        else:
            print(f"error: {bad}", file=sys.stderr)
        return EXIT_UNREADABLE
    pins = None
    # which policy (policy_source.py): --policy FILE > --policy preset:NAME > $PROOF_POLICY > the built-in default
    # (no folder is searched). Selection only; the policy found is then read exactly as --policy FILE always was.
    try:
        policy, source = _ps.resolve(ns.policy, no_discovery=ns.no_policy_discovery)
    except PolicyError as exc:
        return _policy_error(exc, ns.json, getattr(exc, "source", None))
    note = _ps.ignored_note(source)
    if note:
        print(note, file=sys.stderr)
    if policy is not None:
        # SPEC 7.12 / 13.4.1 step 3: pins from outside the policy file -- the CLI's built-in demo pin and
        # --pubkey -- are MERGED into it with the demo-wins rule, so a demo-signed bundle reads
        # `integrity-only (demo pin)` under any policy.
        # "the CLI's built-in demo pin" (13.4.1 step 3): every demo key of SPEC section 2 (the Ed25519 and the P-256
        # demo key), as a demo pin, so a demo-signed bundle of either suite reads `integrity-only (demo pin)`.
        pins = [dict(p) for p in BUILTIN_DEMO_PINS]
        if ns.pubkey is not None:
            pins.append({"legacy_raw_key": ns.pubkey, "demo": False})
    if ns.allow_self_verify:
        # SPEC 13.5: "`--allow-self-verify`: sets `allow_self_verify: true` in the effective policy, so
        # `policy_sha256` reflects it". Without --policy: the default policy with that one member set, plus the
        # out-of-policy pins the --policy path merges (the built-in demo pins and --pubkey).
        if policy is None:
            policy = {"schema": "evidence.receiver-policy.v1"}
            pins = [dict(p) for p in BUILTIN_DEMO_PINS]
            if ns.pubkey is not None:
                pins.append({"legacy_raw_key": ns.pubkey, "demo": False})
        if not isinstance(policy, dict):
            return _policy_error(PolicyError("a receiver policy must be a JSON object"), ns.json, source)
        policy = {**policy, "allow_self_verify": True}
    if ns.pubkey is not None and pins is None:
        try:
            pin_key(ns.pubkey)
        except (ValueError, TypeError) as exc:
            print(f"error: --pubkey must be 64 lowercase hex characters: {exc}", file=sys.stderr)
            return EXIT_UNREADABLE
    if ns.expect_policy is not None and policy is not None:
        # checked before the bundle is read too, so not even an `unreadable` result is printed under another policy
        # (the verdict's own policy_sha256 is checked again in verify_path; without a policy file the default
        # policy's digest depends on the pin, so only that later check applies)
        try:
            pin_set, members = effective_policy(policy, pins)
        except PolicyError as exc:
            return _policy_error(exc, ns.json, source)
        refused = _expect_refused(ns.expect_policy, policy_sha256(members, pin_set), source, ns.json)
        if refused is not None:
            return refused
    return verify_path(ns.bundle, profile=profile, as_json=ns.json, upstreams=ns.upstream, policy=policy,
                       pins=pins, as_of=ns.as_of, policy_source=source, expect_policy=ns.expect_policy)


if __name__ == "__main__":
    raise SystemExit(main())
