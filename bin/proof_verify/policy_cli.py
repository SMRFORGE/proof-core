"""``proof-policy`` -- write and read a receiver policy (``evidence.receiver-policy.v1``, SPEC v4 13.4.1).

Four subcommands, all tooling AROUND the verifier (none changes a verdict rule):

- ``proof-policy explain <policy.json> [--json] [--pubkey HEX] [--allow-self-verify] [--expect-policy sha256:HEX]``
  validates the file exactly as
  ``proof-verify --policy`` does (the same loader, the same `PolicyError`, the same normalization), prints the
  ``policy_sha256`` that ``proof-verify --policy FILE`` (with the same flags) reports, and explains in plain language
  what a bundle must show to be accepted under it (SPEC 13.4.3 rows, 13.4.4, 7.13). ``--expect-policy`` refuses
  (exit 2) unless that ``policy_sha256`` is the one given, as ``proof-verify --expect-policy`` does.
- ``proof-policy init --preset NAME [--fill SLOT=VALUE ...] [-o FILE] [--force]`` writes a starter policy from a
  versioned preset shipped in ``proof_verify/presets``; ``init --list`` lists them.
- ``proof-policy add-pin`` / ``proof-policy add-person`` edit an existing policy: pin a non-demo origin key, add a
  roster person, or fill a placeholder pin or person. ``--from-bundle`` takes the key (and, for a person, the
  printed name and signer id of a valid v2 sign-off) from a bundle whose integrity holds, which saves typing them.
  Integrity shows only that the file matches its own seal; it does not show whose key that is (anyone can seal a
  bundle under their own key), so ``--expect-key-id`` checks the taken key against one confirmed with its holder
  through another channel. An edit
  is checked as proof-verify will read it before anything is written; a policy verify would refuse (other than for
  a placeholder the input already held and the edit leaves) is never written. Writes are atomic (temporary file and
  rename) and never overwrite another file.

Placeholders. A preset holds the parts only the receiver can supply (the production key it trusts, the people who
sign off) as **slots**. An object that holds an unfilled slot carries an extra member ``replace_me``. Pin and person
objects are closed (SPEC 7.12, 13.4.1), so a policy with any ``replace_me`` member left is MALFORMED: proof-verify
refuses it (exit 2, no verdict). Second layer: an unfilled key slot holds a placeholder key id whose digest starts with
48 zero hex digits; no key is known to hash to it, so even with the marker deleted by hand it can never match a
signature. ``init`` removes an object's marker only when every slot inside it is filled, refuses a demo key (or a
placeholder key id, or one key in two slots) as a fill value, and ``explain`` refuses (exit 2) any file in which a
marker, a placeholder key id or a ``REPLACE-ME`` value remains.

A policy describes what this receiver requires before it accepts a bundle. It says nothing about whether the
computation or its result is right.

Exit codes: 0 done; 2 usage error, or the policy is malformed / still holds a placeholder (no explanation).
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import re
import sys
import tempfile
from importlib import resources
from typing import Any

from .policy_source import PolicyMismatch, check_expect
from .verify import (
    _DEMO_KEY_IDS,
    _KEY_ID_RE,
    _MAX_BUNDLE_BYTES,
    _PERSON_ID_RE,
    _PUBKEY_HEX_RE,
    _ROLE_NAMES,
    _SIGNER_ID_RE,
    BUILTIN_DEMO_PINS,
    POLICY_SCHEMA,
    PolicyError,
    _canon,
    _int_digits,
    _sha,
    classify_bundle,
    effective_policy,
    is_restricted_text,
    key_id,
    loads,
    policy_sha256,
    safe_terminal_output,
)

EXIT_OK = 0
EXIT_REFUSED = 2
EXPLAIN_KIND = "proof_verify.policy_explain.v1"
PRESET_SCHEMA = "proof_verify.policy_preset.v1"
#: The marker member an object holding an unfilled slot carries. Unknown to SPEC 13.4.1, so it makes the policy
#: malformed wherever it sits (pins and persons are closed objects).
MARKER = "replace_me"
#: A key id whose SHA-256 part starts with 48 zero hex digits is a placeholder (no key is known to hash to it).
_PLACEHOLDER_KID_RE = re.compile(r"[a-z0-9][a-z0-9.+\-]{0,31}:sha256:0{48}[0-9a-f]{16}", re.ASCII)
_PLACEHOLDER_TEXT = "REPLACE-ME"
_ROLE_MEANING = {"verifier": "review", "approver": "approval", "originator": "authorship or responsibility"}

_USAGE = (
    "usage: proof-policy explain <policy.json> [--json] [--pubkey HEX] [--allow-self-verify]\n"
    "                            [--expect-policy sha256:HEX]\n"
    "       proof-policy init --preset NAME [--fill SLOT=VALUE ...] [-o FILE] [--force]\n"
    "       proof-policy init --list\n"
    "       proof-policy add-pin <policy.json> (--key-id ID | --pubkey HEX | --from-bundle BUNDLE [--signer N]\n"
    "                            [--expect-key-id ID]) [--label TEXT] [-o FILE | --in-place]\n"
    "       proof-policy add-person <policy.json> --person-id ID --printed-name NAME --signer-id SID\n"
    "                            --role ROLE[,ROLE] (--key-id ID | --pubkey HEX | --from-bundle BUNDLE --signoff N\n"
    "                            [--expect-key-id ID]) [--replace-placeholder PERSON_ID] [-o FILE | --in-place]\n"
    "  explain  validate a receiver policy exactly as proof-verify --policy does, print its policy_sha256 (the\n"
    "           fingerprint proof-verify reports with the same --pubkey/--allow-self-verify flags) and what a\n"
    "           bundle must show to be accepted under it. A malformed policy exits 2 with verify's message.\n"
    "           --expect-policy sha256:HEX exits 2 (no explanation) unless its policy_sha256 is HEX.\n"
    "  init     write a starter policy from a versioned preset; --fill SLOT=VALUE fills a placeholder slot\n"
    "           (a key slot takes a key id <alg>:sha256:<64 hex> or a 64-hex Ed25519 public key). A policy\n"
    "           with an unfilled slot is refused by proof-verify (exit 2) until every slot is filled.\n"
    "  add-pin  pin a non-demo origin key in an existing policy (or fill its placeholder pin). --from-bundle\n"
    "           takes a seal signer's key from a bundle whose integrity holds (--signer N picks one).\n"
    "           Integrity does not show whose key it is: pass --expect-key-id ID, the key id confirmed with\n"
    "           its holder through another channel, and the edit is refused unless the taken key matches.\n"
    "  add-person  add a roster person (or fill a placeholder person: --replace-placeholder PERSON_ID, which\n"
    "           keeps its person_id and roles unless given). --from-bundle --signoff N takes the key,\n"
    "           printed_name and signer_id from a valid v2 sign-off in a bundle whose integrity holds\n"
    "           (--expect-key-id ID as for add-pin).\n"
    "           Both refuse demo and placeholder keys and duplicates, never write a policy proof-verify would\n"
    "           refuse, write atomically and never overwrite another file (-o FILE must be new; --in-place\n"
    "           rewrites the policy; with neither the edited policy goes to stdout). They print policy_sha256.\n"
    "           (or: python -P -m proof_core policy ...; -P: under -m Python puts the cwd first on the\n"
    "           import path, so a planted proof_verify/ or profile module would win)")


class PlaceholderError(PolicyError):
    """A policy that still holds a placeholder (a `replace_me` marker, a placeholder key id or a REPLACE-ME value)."""

    kind = "placeholder"


# ---- placeholders -----------------------------------------------------------------------------------------------

def find_placeholders(obj: Any, at: str = "") -> list[dict]:
    """Every placeholder left in a parsed policy: ``{"at": <JSON pointer>, "what": marker|key_id|text}``."""
    out: list[dict] = []
    if isinstance(obj, dict):
        if MARKER in obj:
            out.append({"at": at or "/", "what": "marker", "note": obj[MARKER]})
        for k, v in obj.items():
            if k != MARKER:
                out += find_placeholders(v, f"{at}/{_ptr_escape(k)}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += find_placeholders(v, f"{at}/{i}")
    elif isinstance(obj, str):
        if _PLACEHOLDER_KID_RE.fullmatch(obj):
            out.append({"at": at, "what": "key_id", "note": obj})
        elif obj.startswith(_PLACEHOLDER_TEXT):
            out.append({"at": at, "what": "text", "note": obj})
    return out


def _ptr_escape(k: str) -> str:
    return str(k).replace("~", "~0").replace("/", "~1")


def _ptr_parts(ptr: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in ptr.split("/")[1:]]


def _ptr_set(doc: Any, ptr: str, value: Any) -> None:
    parts = _ptr_parts(ptr)
    node = doc
    for p in parts[:-1]:
        node = node[int(p)] if isinstance(node, list) else node[p]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def _ptr_get(doc: Any, ptr: str) -> Any:
    node = doc
    for p in _ptr_parts(ptr):
        node = node[int(p)] if isinstance(node, list) else node[p]
    return node


def _strip_markers(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_markers(v) for k, v in obj.items() if k != MARKER}
    if isinstance(obj, list):
        return [_strip_markers(v) for v in obj]
    return obj


# ---- validation and the fingerprint, exactly as proof-verify --policy -------------------------------------------

def cli_pins(pubkey: str | None = None) -> list[dict]:
    """The out-of-policy pins `proof-verify --policy FILE` merges (SPEC 13.4.1 step 3): its built-in demo pins (both
    demo keys of section 2) and, with ``--pubkey``, that key as a non-demo legacy pin. Same as proof_verify.__main__."""
    pins = [dict(p) for p in BUILTIN_DEMO_PINS]
    if pubkey is not None:
        pins.append({"legacy_raw_key": pubkey, "demo": False})
    return pins


def effective(policy: Any, *, pubkey: str | None = None, allow_self_verify: bool = False
              ) -> tuple[dict[str, bool], dict, str]:
    """(effective pin set, normalized members, policy_sha256) for ``policy`` as `proof-verify --policy` evaluates it
    with the same flags. Raises PolicyError exactly as verify does (same function, same message)."""
    if allow_self_verify:
        if not isinstance(policy, dict):
            raise PolicyError("a receiver policy must be a JSON object")
        policy = {**policy, "allow_self_verify": True}
    pin_set, members = effective_policy(policy, cli_pins(pubkey))
    return pin_set, members, policy_sha256(members, pin_set)


def read_policy(path: str) -> Any:
    """Read a policy file as proof-verify does (hardened loader). Raises PolicyError with verify's message, also for a
    file that parses but is not a JSON object (SPEC v4: a policy MUST be one; `null` is not "no policy")."""
    try:
        with open(path, "rb") as handle:
            policy = loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise PolicyError(f"cannot read policy {path!r}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(policy, dict):
        raise PolicyError("a receiver policy must be a JSON object")
    return policy


# ---- explain ----------------------------------------------------------------------------------------------------

def _fmt_pin(kid: str, demo: bool, label: str | None) -> str:
    return f"{kid}" + (f" ({label!r})" if label else "") + (" [demo]" if demo else "")


def explain(policy: Any, *, pubkey: str | None = None, allow_self_verify: bool = False,
            builtin_kids: frozenset[str] | None = None) -> dict:
    """Explain a parsed receiver policy. Raises PolicyError (malformed, verify's message) or PlaceholderError."""
    placeholders = find_placeholders(policy)
    try:
        pin_set, m, digest = effective(policy, pubkey=pubkey, allow_self_verify=allow_self_verify)
    except PolicyError as exc:
        if placeholders:
            exc.placeholders = placeholders        # the caller adds the placeholder note to verify's message
        raise
    if placeholders:
        raise PlaceholderError(
            "the policy still holds placeholder value(s) at " + ", ".join(p["at"] for p in placeholders)
            + ": a placeholder key id matches no key, so this policy would accept no bundle; replace each one "
            "(proof-policy init --fill SLOT=VALUE)")
    labels = m.get("_labels", {})
    listed = _file_kids(policy) | ({key_id("ed25519", pubkey)} if pubkey else set())
    nondemo = sorted(k for k, demo in pin_set.items() if not demo)
    roster = m["roster"]
    roles = m["require_roles"]
    warnings: list[str] = []
    sections: list[dict] = []

    def sec(topic: str, lines: list[str]) -> None:
        sections.append({"topic": topic, "lines": lines})

    # -- origin (7.12, 7.13; rows 1 and 2)
    lines = []
    if m["min_envelope"] == "v4":
        lines.append("Only v4 bundles are accepted: a v3 bundle is refused (row 2 envelope_below_minimum). This closes "
                     "format downgrade, since a v3 bundle escapes every v4 rule (sign-off roles, the statistical band).")
    else:
        lines.append("v3 and v4 bundles are both read (min_envelope \"v3\"). A producer can mint a v3 bundle and avoid "
                     "every v4 rule (13.4.5); set \"min_envelope\": \"v4\" to close that.")
    lines.append(f"Pinned keys ({len(_file_kids(policy))} from this policy"
                 + (", plus --pubkey" if pubkey else "") + ", plus proof-verify's built-in demo pins):")
    for kid in sorted(k for k in pin_set if k in listed):
        demo = pin_set[kid]
        if demo:
            use = "a demo key or a pin marked demo: it never counts for origin or for any sign-off role (SIG-28)"
        else:
            use = "counts toward origin when it made a verified seal signature"
            if not roster:
                use += "; a valid sign-off under it is a pinned_key sign-off, eligible for any role it claims"
            elif not any(kid in p["keys"] for p in roster):
                use += ("; a sign-off under it is eligible for no role, because the roster decides who signs off "
                        "(rows 12 and 19 still read it)")
        lines.append(f"  - {_fmt_pin(kid, demo, labels.get(kid))}: {use}")
    lines.append("  - the built-in demo pins (both published demo keys): a demo-signed bundle reads "
                 "integrity-only (demo pin) and is refused (row 1)")
    q = m["origin_quorum"]
    v3_read = m["min_envelope"] == "v3"
    lines.append(f"For a v4 bundle, origin holds only when at least {q} distinct non-demo pinned key(s) made a verified "
                 "seal signature, and the required suites and aging below hold (7.13 SIG-31). Without origin a bundle "
                 "is refused (row 1 state_not_accepted).")
    if v3_read:
        lines.append("For a v3 bundle only the pins affect origin (SIG-31a): origin holds when its seal signature "
                     "verifies under a non-demo pin. origin_quorum, require_seal_suites, suites and hashes are not "
                     "applied to it, so a v3 bundle keeps its v3 state under this policy.")
    if not nondemo:
        warnings.append("no non-demo key is pinned: no bundle (v3 or v4) can reach integrity+origin, so this policy "
                        "accepts nothing (row 1)")
    elif q > len(nondemo):
        if v3_read:
            warnings.append(f"origin_quorum is {q} but only {len(nondemo)} non-demo key(s) are pinned: no v4 bundle "
                            "can reach integrity+origin (row 1). A v3 bundle is not held to the quorum (SIG-31a) and "
                            "can still be accepted, since min_envelope is \"v3\"")
        else:
            warnings.append(f"origin_quorum is {q} but only {len(nondemo)} non-demo key(s) are pinned: no bundle can "
                            "reach integrity+origin, so this policy accepts nothing (row 1)")
    if m["require_seal_suites"]:
        lines.append("In a v4 bundle, each of these signature suites must be the suite of at least one counted seal "
                     "signature: " + ", ".join(sorted(m["require_seal_suites"])) + " (7.13 SIG-31 b).")
    for member, what in (("suites", "suite"), ("hashes", "hash")):
        for name, e in sorted(m[member].items()):
            if e.get("trusted_until") is None:
                lines.append(f"{what} {name}: no end date (an entry with trusted_until null is dropped from the "
                             "effective policy).")
            else:
                lines.append(f"{what} {name} is trusted until {e['trusted_until']}: after that instant a v4 "
                             "signature that depends on it counts only if a valid, continuous archive rescues it "
                             "(7.13).")
    sec("origin", lines)

    # -- sign-offs (10.3.8, 13.4.4; rows 3 to 12, 19)
    if m["ignore_unrecognised_signoffs"]:
        lines = [("A bundle is refused when a sign-off is invalid, under any key (row 3), or when a valid sign-off "
                  "under a pinned key records a rejection (row 5)."),
                 ("ignore_unrecognised_signoffs is true (13.4.4 \"Unrecognised sign-offs\"): a valid sign-off under "
                  "an unpinned or demo key is noted (unrecognised_signoffs_ignored) but neither counted nor blocking. "
                  "Its rejection (row 5), self-verification (row 4), failed time check (row 9) or uncited approval "
                  "(rules O and OE, rows 11 and 23) does not reject, and a review under such a key does not satisfy "
                  "rule O. A sign-off under a pinned key keeps its full effect. v4 bundles only.")]
    else:
        lines = [("Under every policy a bundle is refused when a sign-off is invalid (row 3) or a valid sign-off "
                  "records a rejection (row 5), under any key: anyone who can append a sign-off to a bundle can "
                  "block its acceptance this way, also with an approval that cites no review (row 11, under require_order) or a "
                  "self-verification (row 4). Set \"ignore_unrecognised_signoffs\": true to have a sign-off under an "
                  "unpinned or demo key noted but not blocking (13.4.4 \"Unrecognised sign-offs\").")]
    if m["allow_self_verify"]:
        lines.append("allow_self_verify is true: a verifier or approver sign-off made with an originator's key or "
                     "signer id is accepted (row 4 off) and can count for its role.")
    else:
        lines.append("A verifier or approver sign-off that is a self-verification is refused (row 4 self_verified).")
    basis = ["its key is a seal signer's key or an originator sign-off's key"]
    if m["originator_keys"]:
        basis[0] += " or one of originator_keys " + ", ".join(sorted(m["originator_keys"]))
    basis.append("its signer_id equals an originator sign-off's signer_id"
                 + (" or one of originator_signer_ids " + ", ".join(sorted(m["originator_signer_ids"]))
                    if m["originator_signer_ids"] else ""))
    if roster:
        basis.append("the roster person holding its key also holds such a key")
    lines.append("Self-verification means: " + "; or ".join(basis) + " (10.3.8 step 10). The key comparison against "
                 "the seal signers always runs; the signer_id comparison has something to compare only when the "
                 "bundle carries an originator sign-off"
                 + (" or originator_signer_ids is set" if m["originator_signer_ids"] else
                    ", since originator_signer_ids is empty (set it to the originator's signer ids to compare them "
                    "too)") + ". It does not establish that two people are independent.")
    if roles:
        counts = {r: roles.count(r) for r in sorted(set(roles))}
        principal = "roster persons" if roster else "pinned keys"
        lines.append("Required sign-offs (rule R, row 10 role_unsatisfied): "
                     + ", ".join(f"{r} x{n}" for r, n in counts.items())
                     + f", each counted in distinct {principal}.")
        elig = ["a valid v2 sign-off", "with that role and its meaning ("
                + "; ".join(f"{r}: {_ROLE_MEANING[r]}" for r in counts) + ")", "whose time check did not fail"]
        if m["require_full_copy_review"]:
            elig.append("made on the full copy (nothing withheld)")
        if not m["allow_self_verify"] and any(r in ("verifier", "approver") for r in counts):
            elig.append("not a self-verification (verifier, approver)")
        elig.append("under a roster person who holds the role and whose printed_name and signer_id match"
                    if roster else "under a pinned non-demo key")
        lines.append("Eligible means: " + ", ".join(elig) + " (13.4.4). A demo or unpinned key, a rejection, an "
                     "x- meaning and a v1 sign-off of a v3 bundle never count.")
        if not roster:
            lines.append("Without a roster, distinctness is checked by key and signer_id only: one person holding two "
                         "keys is not detected, and one pinned key may sign for every required role (13.4.4).")
        for r, n in counts.items():
            if roster and sum(1 for p in roster if r in p["roles"]) < n:
                warnings.append(f"require_roles needs {n} distinct {r}(s) but the roster has fewer persons holding "
                                f"{r}: no bundle can satisfy rule R, so this policy accepts nothing (row 10)")
            if not roster and len(nondemo) < n:
                warnings.append(f"require_roles needs {n} distinct {r}(s) but fewer non-demo keys are pinned: no "
                                "bundle can satisfy rule R, so this policy accepts nothing (row 10)")
    else:
        lines.append("No sign-off is required (require_roles is empty).")
    if m["require_order"] and m["require_order_eligible"]:
        lines.append("Order (rule O, row 11 order_unsatisfied): every valid approver sign-off must cite, in prior, the "
                     "entry digest of some valid verifier sign-off with meaning review. With no approver sign-off "
                     "this holds.")
        lines.append("Eligible order (rule OE, require_order_eligible, row 23 order_review_not_eligible): the cited "
                     "review must also be eligible for the verifier role, exactly a review rule R counts for "
                     "verifier: a valid verifier sign-off with meaning review, "
                     + ("under a roster person who holds verifier and whose printed_name and signer_id match"
                        if roster else "under a pinned non-demo key")
                     + ", whose time check did not fail"
                     + (", made on the full copy" if m["require_full_copy_review"] else "")
                     + ("" if m["allow_self_verify"] else ", not a self-verification")
                     + ". A review under an unpinned or demo key"
                     + (", or under a pinned key outside the roster," if roster else "")
                     + " does not satisfy it. An approval citing no review fails both rules (rows 11 and 23). "
                     "v4 bundles only: a v1 sign-off of a v3 bundle is checked by neither rule.")
    elif m["require_order"]:
        lines.append("Order (rule O, row 11 order_unsatisfied): every valid approver sign-off must cite, in prior, the "
                     "entry digest of some valid verifier sign-off with meaning review. The cited review need not be "
                     "eligible for a role: it may be under an unpinned key or outside the roster, and need not be the "
                     "review rule R counts (set \"require_order_eligible\": true to require that, rule OE). With no "
                     "approver sign-off this holds.")
    else:
        lines.append("Order is not checked (require_order is false): an approver need not cite a verifier review.")
    if roster:
        lines.append(f"Roster ({len(roster)} person(s)): a valid sign-off under a person's key whose printed_name or "
                     "signer_id differs from the roster, or whose role the person does not hold, is refused "
                     "(rows 6, 7, 8):")
        for p in sorted(roster, key=lambda x: x["person_id"]):
            lines.append(f"  - {p['person_id']}: printed_name {p['printed_name']!r}, signer_id {p['signer_id']!r}, "
                         f"roles {sorted(p['roles'])}, keys {sorted(p['keys'])}")
    if m["require_signoff_timestamps"]:
        derived = "require_signoff_timestamps" not in policy
        lines.append("Every valid sign-off under a pinned key must carry an accepted timestamp token (row 12 "
                     "signoff_timestamp_missing)" + (" -- derived: this policy pins a TSA and does not state "
                                                     "require_signoff_timestamps (13.4.1)" if derived else "") + ".")
        if not m["tsas"]:
            warnings.append("require_signoff_timestamps is true but no TSA is pinned: no token can be accepted, so a "
                            "bundle with any sign-off under a pinned key is refused (row 12)")
    else:
        lines.append("Sign-off timestamps are not required."
                     + (" This policy pins a TSA and states require_signoff_timestamps false, so the verdict carries "
                        "the advisory note signoff_timestamps_not_required." if m["tsas"] else ""))
    if m["tsas"]:
        lines.append(f"A sign-off that carries an accepted token must be signed at most 300 s after the token's time "
                     f"and at most {m['max_attest_lag_s']} s before it (row 9 signoff_time_inconsistent).")
    if m["require_full_copy_review"]:
        lines.append("A sign-off made on a redacted copy counts for no role and is named (row 19 "
                     "partial_copy_review).")
    else:
        lines.append("A sign-off made on a redacted copy still counts (require_full_copy_review is false).")
    lines.append("A holder can delete a sign-off, including a signed rejection, without detection unless rule R "
                 "needs it or a required archive binds it (13.4.4).")
    sec("sign-offs", lines)

    # -- trusted time and archive (10.7, 10.8; rows 13 to 18, 20, 21)
    lines = [("Under every policy a timestamp or archive that is malformed is refused (rows 13, 16). An invalid "
              "timestamp or a broken archive is refused only when it is checked, that is against a TSA this policy "
              "pins (rows 14, 17): a token or stamp from a TSA the policy does not pin is reported not_checked or "
              "unpinned and does not cause a reject.")]
    if m["tsas"]:
        lines.append(f"Pinned TSAs ({len(m['tsas'])}):")
        for t in sorted(m["tsas"], key=lambda x: x["id"]):
            lines.append(f"  - {t['id']}: spki_sha256 {t['spki_sha256']}, trusted {t['trusted_from']} to "
                         f"{t['trusted_until'] or 'no end'}, distrusted_after {t['distrusted_after'] or 'none'}, "
                         f"policy_oids {t['policy_oids'] or 'any'}")
    else:
        lines.append("No TSA is pinned, so no timestamp token can be accepted.")
    if m["min_seal_tsas"]:
        lines.append(f"The seal must carry accepted tokens from at least {m['min_seal_tsas']} distinct pinned TSA(s), "
                     "counted by TSA key identity (row 15 seal_tsas_insufficient).")
        if len(m["tsas"]) < m["min_seal_tsas"]:
            warnings.append(f"min_seal_tsas is {m['min_seal_tsas']} but only {len(m['tsas'])} TSA(s) are pinned: "
                            "this policy accepts nothing (row 15)")
    else:
        lines.append("No seal timestamp is required (min_seal_tsas is 0). To require one, pin the TSAs you trust "
                     "in \"tsas\" and set \"min_seal_tsas\" to how many distinct ones the seal needs.")
    if m["allow_ess_v1"]:
        lines.append("allow_ess_v1 is true: tokens whose certificate binding uses ESS v1 (SHA-1) are accepted.")
    if m["require_archive"]:
        n = m["min_archive_tsas"]
        lines.append("An archive is required (require_archive). It is met only if all of these hold (13.4.3 "
                     "\"What require_archive requires\"):")
        lines.append("  1. the archive verifies (valid) (row 18 archive_required);")
        lines.append(f"  2. every stamp of its verified prefix carries accepted tokens from at least {n} distinct "
                     "pinned TSA(s), counted by TSA key identity (row 18 archive_required);")
        lines.append("  3. it is continuous now: as_of is within the end of the last stamp of its verified prefix "
                     "(row 20 archive_not_continuous);")
        oe = m["require_order"] and m["require_order_eligible"]
        lines.append("  4. every sign-off the policy relies on (every sign-off eligible for a role in "
                     "require_roles" + (", and, under rule OE, every eligible verifier review an approval cites"
                                        if oe else "") + ") is covered by the archive; missing coverage information "
                     "fails closed (row 21 archive_not_covering_signoffs)"
                     + ("." if roles or oe else ". This policy requires no role, so it relies on no sign-off."))
        if len(m["tsas"]) < n:
            warnings.append(f"require_archive needs stamps from {n} distinct pinned TSA(s) but {len(m['tsas'])} "
                            "are pinned: this policy accepts nothing (row 18)")
    else:
        lines.append("No archive is required (require_archive is false). To require one, set \"require_archive\": "
                     "true and pin the TSAs whose stamps you trust in \"tsas\" (\"min_archive_tsas\": how many "
                     "distinct TSAs each stamp needs, default 1).")
        if roles and m["tsas"]:
            lines.append("SPEC 13.4.5: a receiver that sets require_roles and pins a TSA SHOULD also set "
                         "require_archive.")
    sec("trusted time and archive", lines)

    # -- the statistical band (rows 22 and 24)
    lines = [("A v4 bundle whose sealed statistical band (reproduce_tolerance of kind \"stat\") breaks a rule of "
              "13.4.3 \"The statistical band\" is refused (row 22 reproduce_tolerance_unusable), under every policy."),
             ("A bundle with no statistical band, or one whose band cannot be checked (withheld or committed), is not "
              "refused by row 22.")]
    if m["require_reproduce_tolerance"]:
        lines.append("A declared reproduction is required (require_reproduce_tolerance, row 24 "
                     "reproduce_tolerance_undeclared): a v4 bundle whose integrity holds must declare how it "
                     "reproduces in its sealed result core, either exactly {\"kind\": \"exact\"} (a deterministic "
                     "result, reproduce compares exactly; the producer sets Result.reproduce_tolerance to it) or a "
                     "sound statistical band (kind \"stat\"). A bundle with no reproduce_tolerance, any other "
                     "object, or a band that cannot be checked (withheld or committed) is refused; an unusable band is "
                     "row 22 alone. A v3 bundle is never checked by this row. A producer seals with "
                     "`reproduce_tolerance=exact_tolerance()` for a deterministic result, or a stat band "
                     "(`stat_tolerance(...)`) for a stochastic one; nothing declares exact automatically.")
    else:
        lines.append("A declared reproduction is not required: a bundle with no reproduce_tolerance passes (set "
                     "\"require_reproduce_tolerance\": true to require {\"kind\": \"exact\"} or a sound band, "
                     "row 24).")
        lines.append("A v4 band whose quantity or sigma is a committed item cannot be checked (reproduce_tolerance "
                     "not_checked), so this policy accepts it unchecked; the verdict carries the advisory note "
                     "tolerance_committed_not_checked (13.4.3 \"The statistical band\"). Set "
                     "\"require_reproduce_tolerance\": true to reject such a band (row 24).")
    if m["min_envelope"] == "v3":
        lines.append("A v3 bundle is never checked by this row, and this policy accepts v3 bundles.")
    sec("statistical band", lines)

    # SPEC 13.4.4 "Unrecognised sign-offs" (spec 1.2): a roster person's key that is also pinned demo: true reads
    # demo_key (10.3.8 step 12 tests demo first), so under ignore_unrecognised_signoffs that person's sign-offs,
    # rejections included, are ignored. Not a refusal: explain only says so.
    if m["ignore_unrecognised_signoffs"]:
        for p in sorted(roster, key=lambda x: x["person_id"]):
            demo_kids = sorted(k for k in p["keys"] if pin_set.get(k) is True)
            if demo_kids:
                warnings.append(f"roster person {p['person_id']} holds key(s) {', '.join(demo_kids)} that are also "
                                "pinned demo: true, so their sign-offs read demo_key (10.3.8 step 12): under "
                                "ignore_unrecognised_signoffs they are ignored, a signed rejection included; remove "
                                "the demo pin or the key")
    # SPEC 13.4.1 "v4 bundles only" (spec 1.2): the 1.1 opt-in members constrain v4 bundles alone (13.4.6), so a
    # receiver that sets one and still reads v3 bundles can be bypassed by a producer who mints v3. Not a refusal:
    # the policy is well-formed and the decision is unchanged; explain only says so.
    v4_only = [k for k in ("require_order_eligible", "require_reproduce_tolerance") if m[k] is True]
    if v4_only and m["min_envelope"] != "v4":
        warnings.append(", ".join(v4_only) + (" is" if len(v4_only) == 1 else " are") + " true but min_envelope is "
                        "\"v3\": " + ("this member constrains" if len(v4_only) == 1 else "these members constrain")
                        + " v4 bundles only (13.4.1 \"v4 bundles only\"), so a producer who mints a v3 bundle "
                        "escapes " + ("it" if len(v4_only) == 1 else "them") + "; set \"min_envelope\": \"v4\" "
                        "to close that")
    sec("scope", [("This describes what this receiver requires before it accepts a bundle. An accept means these "
                   "checks passed; it says nothing about whether the computation or its result is right.")])
    members = {k: v for k, v in m.items() if k != "_labels"}
    return {
        "kind": EXPLAIN_KIND,
        "policy_sha256": digest,
        "accepts_nothing": bool(warnings and any("accepts nothing" in w for w in warnings)),
        "warnings": warnings,
        "members": members,
        "pins": [{"key_id": k, "demo": pin_set[k], **({"label": labels[k]} if k in labels else {})}
                 for k in sorted(pin_set)],
        "sections": sections,
    }


def _file_kids(policy: dict) -> set[str]:
    out = set()
    for p in policy.get("pins", []) if isinstance(policy, dict) else []:
        if isinstance(p, dict):
            if isinstance(p.get("key_id"), str):
                out.add(p["key_id"])
            elif isinstance(p.get("legacy_raw_key"), str):
                out.add(key_id("ed25519", p["legacy_raw_key"]))
    return out


def render_text(rep: dict, path: str) -> str:
    out = [f"receiver policy: {path}", f"policy_sha256: {rep['policy_sha256']}",
           "  (what proof-verify --policy reports for this file with the same flags)"]
    for w in rep["warnings"]:
        out.append(f"WARNING: {w}")
    for s in rep["sections"]:
        out.append("")
        out.append(s["topic"].upper())
        out += [ln if ln.startswith("  ") else f"- {ln}" for ln in s["lines"]]
    return "\n".join(out)


def _refuse(exc: PolicyError, as_json: bool) -> int:
    """The same output as proof-verify's malformed-policy path (SPEC 13.4.1: exit 2, no verdict), plus a note
    naming any placeholder left."""
    kind = getattr(exc, "kind", "policy")
    ph = getattr(exc, "placeholders", None)
    if as_json:
        out = {"error": kind, "message": str(exc)}
        if ph:
            out["placeholders"] = ph
        print(json.dumps(out, sort_keys=True))
    else:
        print(f"error: policy refused: {exc}", file=sys.stderr)
        if ph:
            print("note: the policy still holds placeholder(s) at " + ", ".join(p["at"] for p in ph)
                  + "; fill them (proof-policy init --fill SLOT=VALUE) or replace each value and delete its "
                  f"{MARKER!r} member", file=sys.stderr)
    return EXIT_REFUSED


def _explain_main(ns) -> int:
    if ns.pubkey is not None and not _PUBKEY_HEX_RE.fullmatch(ns.pubkey):
        print("error: --pubkey must be 64 lowercase hex characters", file=sys.stderr)
        return EXIT_REFUSED
    bad = check_expect(ns.expect_policy)
    if bad:
        print(f"error: {bad}", file=sys.stderr)
        return EXIT_REFUSED
    try:
        policy = read_policy(ns.policy)
        rep = explain(policy, pubkey=ns.pubkey, allow_self_verify=ns.allow_self_verify)
        if ns.expect_policy is not None and rep["policy_sha256"] != ns.expect_policy:
            # the same refusal proof-verify --expect-policy gives: this is not the policy the receiver meant
            raise PolicyMismatch(f"--expect-policy {ns.expect_policy}: the policy {ns.policy} has policy_sha256 "
                                 f"{rep['policy_sha256']}; it is not the policy expected")
    except PolicyError as exc:
        return _refuse(exc, ns.json)
    if ns.json:
        print(json.dumps(rep, sort_keys=True))
    else:
        print(render_text(rep, ns.policy))
    return EXIT_OK


# ---- presets and init -------------------------------------------------------------------------------------------

def preset_names() -> list[str]:
    return sorted(p.name[:-5] for p in resources.files(__package__).joinpath("presets").iterdir()
                  if p.name.endswith(".json"))


def load_preset(name: str) -> dict:
    if name not in preset_names():
        raise KeyError(f"unknown preset {name!r}; available: {', '.join(preset_names())}")
    text = resources.files(__package__).joinpath("presets", f"{name}.json").read_text(encoding="utf-8")
    preset = loads(text)
    if preset.get("schema") != PRESET_SCHEMA or preset.get("preset") != name:
        raise ValueError(f"preset file {name}.json is not a {PRESET_SCHEMA} preset named {name!r}")
    # the recorded digests are part of the preset's version: a change to its policy that does not re-record them
    # (and bump `version`) is refused here and fails the test suite
    for member, fn in (("template_sha256", template_digest), ("template_policy_sha256", template_policy_sha256)):
        if preset.get(member) != fn(preset):
            raise ValueError(f"preset {name!r}: recorded {member} {preset.get(member)!r} does not match its policy "
                             f"({fn(preset)}); re-record it and bump the preset version")
    return preset


def template_digest(preset: dict) -> str:
    """The digest of the preset's policy object as shipped (canon_1), placeholders included."""
    return _sha(_canon(preset["policy"]))


def template_policy_sha256(preset: dict) -> str:
    """The policy_sha256 proof-verify reports for the preset's policy with every `replace_me` marker deleted and
    every slot left at its placeholder value: a fixed fingerprint of the preset's shape (a filled policy has its own)."""
    return effective(_strip_markers(preset["policy"]))[2]


def _fill_value(slot: dict, raw: str) -> str:
    kind = slot["kind"]
    if kind == "key_id":
        kid = key_id("ed25519", raw) if _PUBKEY_HEX_RE.fullmatch(raw) else raw
        if not _KEY_ID_RE.fullmatch(kid):
            raise PolicyError(f"--fill {slot['name']}: not a key id <alg>:sha256:<64 lowercase hex> or a 64-hex "
                              f"Ed25519 public key: {raw!r}")
        if kid in _DEMO_KEY_IDS:
            raise PolicyError(f"--fill {slot['name']}: {kid} is a published demo key: anyone can sign with it, so it "
                              "can never stand for a production key or a person (SIG-28); init refuses it")
        if _PLACEHOLDER_KID_RE.fullmatch(kid):
            raise PolicyError(f"--fill {slot['name']}: {kid} is a placeholder key id, not a real key")
        return kid
    if kind == "signer_id":
        if not _SIGNER_ID_RE.fullmatch(raw):
            raise PolicyError(f"--fill {slot['name']}: a signer_id must match [!-~]{{1,256}}: {raw!r}")
    elif kind == "printed_name":
        if not is_restricted_text(raw, 1, 256):
            raise PolicyError(f"--fill {slot['name']}: a printed_name must be restricted text of 1 to 256 code points")
    else:
        raise PolicyError(f"preset slot {slot['name']!r} has an unknown kind {kind!r}")
    if raw.startswith(_PLACEHOLDER_TEXT):
        raise PolicyError(f"--fill {slot['name']}: {raw!r} is a placeholder value")
    return raw


def build_from_preset(preset: dict, fills: dict[str, str]) -> tuple[dict, list[str]]:
    """Apply ``fills`` (slot name -> value) to the preset's policy. Returns (policy, unfilled slot names). A marker is
    removed only when every slot inside its object is filled. Raises PolicyError for a bad fill."""
    slots = {s["name"]: s for s in preset.get("slots", [])}
    unknown = sorted(set(fills) - set(slots))
    if unknown:
        raise PolicyError(f"--fill names unknown slot(s) {unknown}; preset {preset['preset']!r} has "
                          f"{sorted(slots) or 'no slots'}")
    policy = copy.deepcopy(preset["policy"])
    used: dict[str, str] = {}
    for name, raw in fills.items():
        value = _fill_value(slots[name], raw)
        if slots[name]["kind"] == "key_id":
            if value in used:
                raise PolicyError(f"--fill {name}: key {value} already fills slot {used[value]!r}; one key fills one "
                                  "slot (the originator and each person need their own key)")
            used[value] = name
        _ptr_set(policy, slots[name]["at"], value)
    unfilled = sorted(n for n in slots if n not in fills)
    for ptr in sorted({s["marker"] for s in slots.values()}):
        if not any(slots[n]["marker"] == ptr for n in unfilled):
            obj = _ptr_get(policy, ptr)
            obj.pop(MARKER, None)
    return policy, unfilled


def _init_main(ns) -> int:
    if ns.list:
        for name in preset_names():
            p = load_preset(name)
            print(f"{name} (version {p['version']}): {p['description']}")
            for s in p.get("slots", []):
                print(f"    slot {s['name']} ({s['kind']}): {s['means']}")
        return EXIT_OK
    if not ns.preset:
        print("error: init needs --preset NAME (or --list)", file=sys.stderr)
        return EXIT_REFUSED
    try:
        preset = load_preset(ns.preset)
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return EXIT_REFUSED
    fills: dict[str, str] = {}
    for item in ns.fill or []:
        name, sep, value = item.partition("=")
        if not sep or not name:
            print(f"error: --fill must be SLOT=VALUE (got {item!r})", file=sys.stderr)
            return EXIT_REFUSED
        if name in fills:
            print(f"error: --fill {name} given twice", file=sys.stderr)
            return EXIT_REFUSED
        fills[name] = value
    try:
        policy, unfilled = build_from_preset(preset, fills)
        digest = None
        if not unfilled:
            # the policy as proof-verify reads it: any breach is refused here, before a file is written
            digest = explain(loads(json.dumps(policy)))["policy_sha256"]
    except PolicyError as exc:
        print(f"error: init refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    text = json.dumps(policy, indent=2, sort_keys=False) + "\n"
    if ns.output and ns.output != "-":
        if os.path.exists(ns.output) and not ns.force:
            print(f"error: {ns.output} exists; pass --force to overwrite", file=sys.stderr)
            return EXIT_REFUSED
        try:
            with open(ns.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"error: cannot write {ns.output!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        where = ns.output
    else:
        sys.stdout.write(text)
        where = "stdout"
    head = f"wrote preset {preset['preset']} version {preset['version']} to {where}"
    if unfilled:
        print(f"{head}: {len(unfilled)} slot(s) still to fill: {', '.join(unfilled)}. proof-verify refuses this "
              f"policy (exit 2) until each is filled: re-run init with --fill SLOT=VALUE, or replace each value and "
              f"delete its {MARKER!r} member. See: proof-policy init --list", file=sys.stderr)
    else:
        print(f"{head}; policy_sha256 {digest}. Run proof-policy explain on it to read what it requires.",
              file=sys.stderr)
    return EXIT_OK


# ---- edit an existing policy: add-pin and add-person ------------------------------------------------------------

class EditError(PolicyError):
    """An edit add-pin / add-person refuses (nothing is written)."""

    kind = "edit"


def _refuse_special_key(flag: str, kid: str) -> None:
    if kid in _DEMO_KEY_IDS:
        raise EditError(f"{flag}: {kid} is a published demo key: anyone can sign with it, so it can never stand for a "
                        "production key or a person (SIG-28); refused")
    if _PLACEHOLDER_KID_RE.fullmatch(kid):
        raise EditError(f"{flag}: {kid} is a placeholder key id, not a real key")


def _edit_key(flag: str, raw: str) -> str:
    """A key given on the command line (a key id, or with --pubkey a 64-hex Ed25519 public key) -> its key id.
    Refuses a demo key and a placeholder key id, as init does."""
    if flag == "--pubkey":
        if not _PUBKEY_HEX_RE.fullmatch(raw):
            raise EditError("--pubkey must be 64 lowercase hex characters (an Ed25519 public key)")
        kid = key_id("ed25519", raw)
    else:
        kid = raw
        if not _KEY_ID_RE.fullmatch(kid):
            raise EditError(f"{flag}: not a key id <alg>:sha256:<64 lowercase hex>: {raw!r}")
    _refuse_special_key(flag, kid)
    return kid


def _edit_text(flag: str, raw: Any, kind: str) -> str:
    ok = {"signer_id": lambda v: isinstance(v, str) and _SIGNER_ID_RE.fullmatch(v) is not None,
          "person_id": lambda v: isinstance(v, str) and _PERSON_ID_RE.fullmatch(v) is not None,
          "text": lambda v: is_restricted_text(v, 1, 256)}[kind]
    if not ok(raw):
        need = {"signer_id": "a signer_id must match [!-~]{1,256}",
                "person_id": "a person_id must match [a-z0-9][a-z0-9.-]{0,63}",
                "text": "must be restricted text of 1 to 256 code points (SPEC 2.2)"}[kind]
        raise EditError(f"{flag}: {need}: {raw!r}")
    if raw.startswith(_PLACEHOLDER_TEXT):
        raise EditError(f"{flag}: {raw!r} is a placeholder value")
    return raw


def read_bundle_checked(path: str) -> dict:
    """Read a bundle's BYTES and verify them as proof-verify does (`classify_bundle`: the hardened loader, no
    policy). Returns the verdict report. Raises EditError unless integrity holds. Integrity shows only that the file
    matches its own seal (it was not changed after sealing); it does NOT show whose key sealed or signed it: anyone
    can seal a changed bundle under their own key. Taking a key from a bundle saves typing it; it is not
    authentication. The caller confirms the key id with its holder (``--expect-key-id``)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(_MAX_BUNDLE_BYTES + 1)      # one byte over the cap is enough for the loader to refuse
    except OSError as exc:
        raise EditError(f"cannot read bundle {path!r}: {type(exc).__name__}: {exc}") from exc
    try:
        rep = classify_bundle(data)
    except (ValueError, TypeError, RecursionError, MemoryError) as exc:
        raise EditError(f"cannot verify bundle {path!r}: {type(exc).__name__}: {exc}") from exc
    if not rep.get("integrity_ok"):
        why = "; ".join(rep.get("integrity_problems") or []) or str(rep.get("state"))
        raise EditError(f"bundle {path!r} fails integrity (state {rep.get('state')!r}): {why}. A key is never taken "
                        "from a bundle that does not match its own seal")
    return rep


def _verified(s: dict) -> bool:
    return bool(s.get("checked") and s.get("valid"))


def bundle_signer(rep: dict, path: str, index: int | None) -> tuple[str, list[str]]:
    """The seal signer to pin, from a verified report: (key id, the signer listing). ``index`` picks one of the
    listed signers; without it the single verified non-demo signer is taken, and more than one is ambiguous."""
    signers = rep.get("signers") or []
    listing = []
    for i, s in enumerate(signers):
        what = "verified" if _verified(s) else ("not checked" if not s.get("checked") else "invalid")
        listing.append(f"  [{i}] {s.get('key_id')} ({s.get('alg')}): {what}"
                       + (" [demo key: never pinned]" if s.get("key_id") in _DEMO_KEY_IDS else ""))
    shown = (":\n" + "\n".join(listing)) if listing else ""
    if index is not None:
        if not 0 <= index < len(signers):
            raise EditError(f"--signer {index}: bundle {path!r} has {len(signers)} seal signer(s){shown}")
        chosen = signers[index]
        if not _verified(chosen):
            raise EditError(f"--signer {index}: that seal signature was not verified, so its key is not pinned{shown}")
    else:
        cands = [s for s in signers if _verified(s) and s.get("key_id") not in _DEMO_KEY_IDS]
        if len(cands) != 1:
            raise EditError(f"bundle {path!r} has {len(cands)} verified non-demo seal signer(s): "
                            + ("pick one with --signer N" if cands else "none can be pinned") + shown)
        chosen = cands[0]
    _refuse_special_key("--from-bundle", chosen["key_id"])
    return chosen["key_id"], listing


def bundle_signoff(rep: dict, path: str, index: int) -> dict:
    """Sign-off entry ``index`` of a verified report (SPEC 10.3.8 output). Refused unless it is a valid v2 entry,
    not a self-verification, under a non-demo key, with a usable printed_name and signer_id."""
    entries = (rep.get("signoffs") or {}).get("entries") or []
    if not entries:
        raise EditError(f"bundle {path!r} has no v2 sign-off entry (a v3 bundle's v1 attestations are not read)")
    if not 0 <= index < len(entries):
        raise EditError(f"--signoff {index}: bundle {path!r} has {len(entries)} sign-off entr"
                        f"{'y' if len(entries) == 1 else 'ies'} (0 to {len(entries) - 1})")
    x = entries[index]
    if x.get("state") != "valid":
        why = "; ".join(x.get("problems") or []) or str(x.get("state"))
        raise EditError(f"--signoff {index}: the entry is {x.get('state')} ({why}); a person is taken only from a "
                        "valid sign-off")
    if x.get("self_verify"):
        raise EditError(f"--signoff {index}: the entry is a self-verification (its key or signer_id is the "
                        "originator's, SPEC 10.3.8 step 10); refused")
    if not isinstance(x.get("key_id"), str):
        raise EditError(f"--signoff {index}: the entry has no readable key")
    _refuse_special_key("--from-bundle", x["key_id"])
    _edit_text("--from-bundle (the sign-off's printed_name)", x.get("printed_name"), "text")
    _edit_text("--from-bundle (the sign-off's signer_id)", x.get("signer_id"), "signer_id")
    return x


def _slots_left(policy: Any) -> set[str]:
    """The objects (`/pins/N`, `/roster/N`, or a member) that still hold a placeholder."""
    return {"/".join(p["at"].split("/")[:3]) for p in find_placeholders(policy)}


def _placeholder_index(policy: dict, member: str) -> list[int]:
    items = policy.get(member, [])
    return [i for i, o in enumerate(items if isinstance(items, list) else []) if find_placeholders(o)]


def load_for_edit(path: str) -> dict:
    """Read a policy to edit. It must be one proof-verify accepts as well-formed, or one verify refuses only for the
    placeholders it still holds (with its markers deleted it validates). Raises PolicyError with verify's message."""
    policy = read_policy(path)
    effective(_strip_markers(policy) if find_placeholders(policy) else policy)
    return policy


def _pin_kids(policy: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, p in enumerate(policy.get("pins", [])):
        if isinstance(p.get("key_id"), str):
            out[p["key_id"]] = i
        elif isinstance(p.get("legacy_raw_key"), str):
            out[key_id("ed25519", p["legacy_raw_key"])] = i
    return out


def _held_kids(policy: dict, skip: int | None = None) -> dict[str, str]:
    return {k: p["person_id"] for i, p in enumerate(policy.get("roster", [])) if i != skip for k in p["keys"]}


def _need_fill(policy: dict, what: str) -> None:
    left = find_placeholders(policy)
    if left:
        raise EditError("the policy still holds placeholder(s) at " + ", ".join(p["at"] for p in left)
                        + f" and this edit fills none; {what}")


def add_pin(policy: dict, kid: str, label: str | None = None) -> tuple[dict, str]:
    """Pin ``kid`` as a non-demo key: fill the first placeholder pin, or (with none left) append a pin. Returns (the
    new policy, what was done). Refuses a demo or placeholder key, a key already pinned or held by a roster person,
    and an edit of a policy whose placeholders it would not fill."""
    _refuse_special_key("add-pin", kid)
    pinned = _pin_kids(policy)
    if kid in pinned:
        raise EditError(f"{kid} is already pinned (pins[{pinned[kid]}]); a key is pinned once (SPEC 7.12)")
    held = _held_kids(policy)
    if kid in held:
        raise EditError(f"{kid} is held by roster person {held[kid]!r}: one key fills one slot (the originator and "
                        "each person need their own key)")
    new = copy.deepcopy(policy)
    slots = _placeholder_index(new, "pins")
    if slots:
        i = slots[0]
        old = new["pins"][i]
        lab = label if label is not None else old.get("label")
        new["pins"][i] = {"key_id": kid, "demo": False, **({"label": lab} if lab is not None else {})}
        return new, f"filled placeholder pins[{i}] with {kid}"
    _need_fill(new, "fill a placeholder person first (add-person --replace-placeholder PERSON_ID)")
    new.setdefault("pins", []).append({"key_id": kid, "demo": False, **({"label": label} if label else {})})
    return new, f"pinned {kid} as pins[{len(new['pins']) - 1}]"


def add_person(policy: dict, *, kid: str, printed_name: str, signer_id: str, person_id: str | None = None,
               roles: list[str] | None = None, replace: str | None = None) -> tuple[dict, str]:
    """Add a roster person holding ``kid``, or fill the placeholder person whose person_id is ``replace`` (its
    person_id and roles are kept unless given). Applies verify's roster rules (SPEC 13.4.1) with plain messages."""
    _refuse_special_key("add-person", kid)
    roster = policy.get("roster", [])
    skip = None
    if replace is not None:
        slots = _placeholder_index(policy, "roster")
        match = [i for i in slots if roster[i].get("person_id") == replace]
        if not match:
            raise EditError(f"--replace-placeholder {replace}: no placeholder person has that person_id; placeholder "
                            f"persons: {[roster[i].get('person_id') for i in slots] or 'none'}")
        skip = match[0]
        person_id = person_id or roster[skip]["person_id"]
        roles = roles or list(roster[skip]["roles"])
    else:
        _need_fill(policy, "fill one with --replace-placeholder PERSON_ID (or add-pin for a placeholder pin)")
    if not person_id or not roles:
        raise EditError("add-person needs --person-id and --role (both default to the placeholder's only with "
                        "--replace-placeholder)")
    if any(r not in _ROLE_NAMES for r in roles) or len(set(roles)) != len(roles):
        raise EditError(f"--role: 1 to 3 unique role names of {list(_ROLE_NAMES)}, comma separated (got {roles})")
    for i, p in enumerate(roster):
        if i == skip:
            continue
        if p["person_id"] == person_id:
            raise EditError(f"person_id {person_id!r} is already in the roster (roster[{i}]); person ids are unique "
                            "(SPEC 13.4.1)")
        if p["signer_id"] == signer_id:
            raise EditError(f"signer_id {signer_id!r} is already roster person {p['person_id']!r}'s; signer ids are "
                            "unique (SPEC 13.4.1)")
    held = _held_kids(policy, skip)
    if kid in held:
        raise EditError(f"{kid} is already held by roster person {held[kid]!r}: a key is held by one person only "
                        "(SPEC 13.4.1)")
    pinned = _pin_kids(policy)
    if kid in pinned:
        raise EditError(f"{kid} is pinned as a seal key (pins[{pinned[kid]}]): one key fills one slot (the "
                        "originator and each person need their own key)")
    person = {"person_id": person_id, "printed_name": printed_name, "signer_id": signer_id, "keys": [kid],
              "roles": list(roles)}
    new = copy.deepcopy(policy)
    if skip is not None:
        new["roster"][skip] = person
        return new, f"filled placeholder roster[{skip}] with person {person_id!r} (key {kid})"
    new.setdefault("roster", []).append(person)
    return new, f"added roster[{len(new['roster']) - 1}] person {person_id!r} (key {kid})"


def check_edited(before: dict, new: dict) -> tuple[str | None, list[dict]]:
    """Check an edited policy as proof-verify will read it (re-read through the hardened loader). Returns
    (policy_sha256 when no placeholder is left, else None; the placeholders left). Raises PolicyError with verify's
    message for anything verify would refuse beyond a placeholder the input already held, and EditError for an edit
    that leaves a placeholder without filling one."""
    reread = loads(json.dumps(new))
    left, had = _slots_left(reread), _slots_left(before)
    if left and not (left < had):
        raise EditError("the edit leaves placeholder(s) without filling one; refused")
    if left:
        effective(_strip_markers(reread))
        return None, find_placeholders(reread)
    return explain(reread)["policy_sha256"], []


def write_atomic(path: str, text: str) -> None:
    """Write ``text`` to ``path`` through a temporary file in the same directory and a rename (`os.replace`), so a
    reader never sees a half-written policy and a failed write leaves the old file as it was. Raises OSError."""
    fd, tmp = tempfile.mkstemp(prefix=".proof-policy-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _edit_target(ns) -> tuple[bool, str | None]:
    """(ok, the file to write or None for stdout). Never overwrites except the policy itself with --in-place."""
    if ns.in_place and ns.output:
        print("error: give -o FILE or --in-place, not both", file=sys.stderr)
        return False, None
    if ns.in_place:
        return True, ns.policy
    if not ns.output or ns.output == "-":
        return True, None
    if os.path.abspath(ns.output) == os.path.abspath(ns.policy):
        print("error: -o names the policy being edited; use --in-place to rewrite it", file=sys.stderr)
        return False, None
    if os.path.lexists(ns.output):
        print(f"error: {ns.output} exists; -o writes a new file (use --in-place to rewrite the policy itself)",
              file=sys.stderr)
        return False, None
    return True, ns.output


def _edit_write(cmd: str, target: str | None, new: dict, done: str, digest: str | None, left: list[dict]) -> int:
    text = json.dumps(new, indent=2, sort_keys=False) + "\n"
    if target is None:
        sys.stdout.write(text)
    else:
        try:
            write_atomic(target, text)
        except OSError as exc:
            print(f"error: cannot write {target!r}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return EXIT_REFUSED
    where = target or "stdout"
    if digest is not None:
        print(f"{cmd}: {done}; wrote {where}; policy_sha256 {digest}", file=sys.stderr)
    else:
        print(f"{cmd}: {done}; wrote {where}; still to fill: " + ", ".join(p["at"] for p in left)
              + ". proof-verify refuses this policy (exit 2) until each placeholder is filled", file=sys.stderr)
    return EXIT_OK


def _one_key_source(ns, cmd: str) -> bool:
    if sum(x is not None for x in (ns.key_id, ns.pubkey, ns.from_bundle)) != 1:
        print(f"error: {cmd} needs exactly one of --key-id, --pubkey, --from-bundle", file=sys.stderr)
        return False
    return True


_CONFIRM = ("integrity shows only that the file matches its own seal, not whose key this is (anyone can seal a "
            "bundle under their own key): confirm this key id with its holder through another channel before "
            "trusting it")


def _taken_key(ns, kid: str, what: str) -> None:
    """Show the key taken from a bundle and, with --expect-key-id, refuse unless it is that key."""
    if ns.expect_key_id is not None and kid != ns.expect_key_id:
        raise EditError(f"--expect-key-id: the {what} key is {kid}, not the expected {ns.expect_key_id}; refused")
    print(f"KEY TAKEN FROM BUNDLE: {kid}", file=sys.stderr)
    if ns.expect_key_id is not None:
        print("  it matches --expect-key-id", file=sys.stderr)
    else:
        print(f"  {_CONFIRM}; or pass --expect-key-id {kid} once confirmed", file=sys.stderr)


_MEANING = {"verifier": "review", "approver": "approval"}


def role_warnings(policy: dict, new: dict, signoff: dict | None = None, defaulted: bool = False) -> list[str]:
    """Warnings (never refusals) about an edited roster: one person newly holding both verifier and approver where
    require_roles needs both (rule R counts distinct persons per role, so that person alone satisfies both), and a
    sign-off whose role or meaning differs from the placeholder slot it filled with the slot's default roles."""
    out = []
    both = {"verifier", "approver"}
    if both <= set(new.get("require_roles") or []):
        old = {p["person_id"]: set(p["roles"]) for p in policy.get("roster", [])}
        for p in new.get("roster", []):
            if both <= set(p["roles"]) and not both <= old.get(p["person_id"], set()):
                out.append(f"roster person {p['person_id']!r} holds both verifier and approver while require_roles "
                           "needs both: rule R counts distinct persons per role, so this one person can satisfy the "
                           "two-person rule alone")
    if signoff is not None and defaulted:
        person = next((p for p in new.get("roster", []) if signoff["key_id"] in p["keys"]), None)
        role, meaning = signoff.get("role"), signoff.get("meaning")
        if person and (role not in person["roles"] or _MEANING.get(role, meaning) != meaning):
            out.append(f"the sign-off taken is role {role!r} with meaning {meaning!r}, but the slot it filled gives "
                       f"roles {person['roles']}: check that this is the right person for the slot")
    return out


def _add_pin_main(ns) -> int:
    ok, target = _edit_target(ns)
    if not (ok and _one_key_source(ns, "add-pin")):
        return EXIT_REFUSED
    if (ns.signer is not None or ns.expect_key_id is not None) and ns.from_bundle is None:
        print("error: --signer N and --expect-key-id go with --from-bundle", file=sys.stderr)
        return EXIT_REFUSED
    try:
        policy = load_for_edit(ns.policy)
        label = _edit_text("--label", ns.label, "text") if ns.label is not None else None
        if ns.from_bundle is not None:
            kid, listing = bundle_signer(read_bundle_checked(ns.from_bundle), ns.from_bundle, ns.signer)
            print(f"bundle {ns.from_bundle}: matches its own seal (integrity holds); seal signers:\n"
                  + "\n".join(listing), file=sys.stderr)
            _taken_key(ns, kid, "seal signer's")
        else:
            kid = _edit_key("--pubkey", ns.pubkey) if ns.pubkey is not None else _edit_key("--key-id", ns.key_id)
        new, done = add_pin(policy, kid, label)
        digest, left = check_edited(policy, new)
    except PolicyError as exc:
        print(f"error: add-pin refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    return _edit_write("add-pin", target, new, done, digest, left)


def _add_person_main(ns) -> int:
    ok, target = _edit_target(ns)
    if not (ok and _one_key_source(ns, "add-person")):
        return EXIT_REFUSED
    if (ns.signoff is None) != (ns.from_bundle is None):
        print("error: --from-bundle BUNDLE and --signoff N go together", file=sys.stderr)
        return EXIT_REFUSED
    if ns.expect_key_id is not None and ns.from_bundle is None:
        print("error: --expect-key-id goes with --from-bundle", file=sys.stderr)
        return EXIT_REFUSED
    roles = [r.strip() for r in ns.role.split(",")] if ns.role else None
    x = None
    try:
        policy = load_for_edit(ns.policy)
        name, sid = ns.printed_name, ns.signer_id
        if ns.from_bundle is not None:
            x = bundle_signoff(read_bundle_checked(ns.from_bundle), ns.from_bundle, ns.signoff)
            for flag, given, taken in (("--printed-name", name, x["printed_name"]), ("--signer-id", sid, x["signer_id"])):
                if given is not None and given != taken:
                    raise EditError(f"{flag} {given!r} differs from the sign-off's {taken!r}: verify would refuse "
                                    "that sign-off under this roster (rows 6, 7)")
            kid, name, sid = x["key_id"], x["printed_name"], x["signer_id"]
            print(f"bundle {ns.from_bundle}: matches its own seal (integrity holds); taken from valid sign-off "
                  f"{ns.signoff} (role {x['role']}, meaning {x['meaning']}): printed_name {name!r}, signer_id "
                  f"{sid!r}", file=sys.stderr)
            _taken_key(ns, kid, "sign-off's")
            if roles and x["role"] not in roles:
                print(f"note: that sign-off's role {x['role']!r} is not among --role {','.join(roles)}",
                      file=sys.stderr)
        else:
            kid = _edit_key("--pubkey", ns.pubkey) if ns.pubkey is not None else _edit_key("--key-id", ns.key_id)
            if name is None or sid is None:
                raise EditError("add-person needs --printed-name and --signer-id (or --from-bundle with --signoff N)")
        name = _edit_text("--printed-name", name, "text")
        sid = _edit_text("--signer-id", sid, "signer_id")
        pid = _edit_text("--person-id", ns.person_id, "person_id") if ns.person_id is not None else None
        new, done = add_person(policy, kid=kid, printed_name=name, signer_id=sid, person_id=pid, roles=roles,
                               replace=ns.replace_placeholder)
        digest, left = check_edited(policy, new)
    except PolicyError as exc:
        print(f"error: add-person refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    for w in role_warnings(policy, new, x, defaulted=roles is None):
        print(f"WARNING: {w}", file=sys.stderr)
    return _edit_write("add-person", target, new, done, digest, left)


# ---- entry point ------------------------------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="proof-policy", add_help=False)
    sub = p.add_subparsers(dest="cmd")
    e = sub.add_parser("explain", add_help=False)
    e.add_argument("policy")
    e.add_argument("--json", action="store_true")
    e.add_argument("--pubkey", metavar="HEX")
    e.add_argument("--allow-self-verify", dest="allow_self_verify", action="store_true")
    e.add_argument("--expect-policy", dest="expect_policy", metavar="sha256:HEX")
    i = sub.add_parser("init", add_help=False)
    i.add_argument("--preset", metavar="NAME")
    i.add_argument("--fill", action="append", metavar="SLOT=VALUE")
    i.add_argument("-o", "--output", metavar="FILE")
    i.add_argument("--force", action="store_true")
    i.add_argument("--list", action="store_true")
    for name in ("add-pin", "add-person"):
        a = sub.add_parser(name, add_help=False)
        a.add_argument("policy")
        a.add_argument("--key-id", dest="key_id", metavar="ID")
        a.add_argument("--pubkey", metavar="HEX")
        a.add_argument("--from-bundle", dest="from_bundle", metavar="BUNDLE")
        a.add_argument("-o", "--output", metavar="FILE")
        a.add_argument("--in-place", dest="in_place", action="store_true")
        a.add_argument("--expect-key-id", dest="expect_key_id", metavar="ID")
        if name == "add-pin":
            a.add_argument("--signer", type=int, metavar="N")
            a.add_argument("--label", metavar="TEXT")
        else:
            a.add_argument("--signoff", type=int, metavar="N")
            a.add_argument("--person-id", dest="person_id", metavar="ID")
            a.add_argument("--printed-name", dest="printed_name", metavar="NAME")
            a.add_argument("--signer-id", dest="signer_id", metavar="SID")
            a.add_argument("--role", metavar="ROLE[,ROLE]")
            a.add_argument("--replace-placeholder", dest="replace_placeholder", metavar="PERSON_ID")
    return p


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(_USAGE, file=sys.stderr)
        return EXIT_REFUSED
    if args[0] in ("-h", "--help") or args[1:2] in (["-h"], ["--help"]):
        print(_USAGE)
        return EXIT_OK
    try:
        ns = _parser().parse_args(args)
    except SystemExit:
        print(_USAGE, file=sys.stderr)
        return EXIT_REFUSED
    with safe_terminal_output(enabled="--json" not in args), _int_digits():
        if ns.cmd == "explain":
            return _explain_main(ns)
        if ns.cmd == "init":
            return _init_main(ns)
        if ns.cmd == "add-pin":
            return _add_pin_main(ns)
        if ns.cmd == "add-person":
            return _add_person_main(ns)
    print(_USAGE, file=sys.stderr)
    return EXIT_REFUSED


__all__ = ["POLICY_SCHEMA", "EditError", "PlaceholderError", "add_person", "add_pin", "build_from_preset",
           "check_edited", "effective", "explain", "find_placeholders", "load_for_edit", "load_preset", "main",
           "preset_names", "read_bundle_checked", "role_warnings", "template_digest", "template_policy_sha256", "write_atomic"]

if __name__ == "__main__":
    # `python -m` without -P: say the cwd could shadow this tool (stderr only; see _spec_loader)
    from ._spec_loader import warn_if_cwd_on_path
    warn_if_cwd_on_path()
    raise SystemExit(main())
