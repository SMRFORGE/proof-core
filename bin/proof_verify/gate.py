"""The ONE gate: what ``proof-verify`` decides about a bundle, as a value every other tool reuses.

``verify`` is the single source of truth for three questions about a received bundle:

1. is it unaltered (integrity),
2. who signed it, judged under the RECEIVER's pins (origin), and
3. does the receiver's policy accept it (valid sign-offs, ``attestations_ok``, and the 13.5 decision).

``gate(bundle_bytes, policy, pins, as_of)`` answers all three in one `Decision`, whose ``exit_code`` is exactly the
single-bundle exit code ``proof-verify`` returns for the same bytes and trust inputs (0 / 1 / 3 / 4 / 6; the chain walk
of ``--upstream`` is ``proof-verify``'s alone). ``proof-reproduce``, ``certify_bundle`` / ``seal_certification`` and
the Adapter consume this Decision instead of reading ``integrity_ok`` / ``origin_ok`` themselves, so none of them can
give a looser pass than verify: a bundle verify rejects (a signed rejection, a forged sign-off, an aged suite under the
receiver's policy, a policy the receiver did not expect) is rejected by every one of them.

``trust_inputs`` / ``resolve_trust`` turn the command-line trust arguments (``--policy``, ``PROOF_POLICY``,
``--no-policy-discovery``, ``--pubkey``, ``--allow-self-verify``) into the ``(policy, pins)`` pair exactly as
``proof-verify`` does, so a CLI that takes the same flags evaluates under the same effective policy and reports the same
``policy_sha256``. Selection only: no verdict rule lives here; the decision is ``classify_bundle``'s.

Standard library only, like the rest of proof_verify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import policy_source as _ps
from .verify import (
    BUILTIN_DEMO_PINS,
    STATE_UNSUPPORTED_ALG,
    STATE_UNSUPPORTED_CANON,
    UNSEALED_DECISION_MEMBERS,  # noqa: F401 -- re-exported: the one definition lives in verify.py
    PolicyError,
    _canon,
    _int_digits,
    _sha,
    _verdict_pins,
    classify_bundle,
    effective_policy,
    evaluated_signoffs_sha256,
    parse_bundle,
    pin_key,
    policy_sha256,
)


def pins_sha256(rep: dict) -> str | None:
    """sha256 of canon_1 of the effective pin set the verdict was made under ({key_id: demo}), or None."""
    pins = _verdict_pins(rep)
    return None if pins is None else _sha(_canon({k: pins[k] for k in sorted(pins)}))

#: The single-bundle exit codes of ``proof-verify`` (see proof_verify/__main__.py for the full contract).
EXIT_VERIFIED = 0
EXIT_FAIL = 1
EXIT_UNREADABLE = 2
EXIT_INTEGRITY_ONLY = 3
EXIT_UNSUPPORTED_CANON = 4
EXIT_UNSUPPORTED_ALG = 6


def decision_rejects(rep: dict) -> list[str]:
    """SPEC v4 draft 13.5: the decision reasons other than `state_not_accepted`; any of them turns exit 0 or 3 into 1."""
    decision = rep.get("decision") or {}
    return [r for r in decision.get("reasons", []) if r != "state_not_accepted"]


def decision_exit_code(rep: dict) -> int:
    """The single-bundle exit code of ``proof-verify`` for a ``classify_bundle`` report: 4 / 6 for an unsupported canon
    or suite; 1 for an integrity failure; else 0 (integrity + origin) or 3 (integrity only); then a present-but-invalid
    sign-off (``attestations_ok`` false) or a rejecting decision reason turns it into 1."""
    if rep.get("state") == STATE_UNSUPPORTED_CANON:
        return EXIT_UNSUPPORTED_CANON
    if rep.get("state") == STATE_UNSUPPORTED_ALG:
        return EXIT_UNSUPPORTED_ALG
    if not rep.get("integrity_ok"):
        return EXIT_FAIL
    code = EXIT_VERIFIED if rep.get("origin_ok") else EXIT_INTEGRITY_ONLY
    if not rep.get("attestations_ok", True) or decision_rejects(rep):
        return EXIT_FAIL
    return code


@dataclass(frozen=True)
class Decision:
    """The gate's verdict on one bundle under one set of trust inputs.

    ``exit_code`` is ``proof-verify``'s single-bundle exit code for the same bytes and trust inputs. ``passed`` is True
    only for exit 0: intact, signed under a non-demo pin of the receiver, every sign-off valid, and accepted by the
    receiver's policy. ``rejected`` is True when verify fails the bundle closed (exit 1, 4 or 6); an integrity-only
    bundle (exit 3) is neither passed nor rejected."""

    exit_code: int
    state: str | None
    integrity_ok: bool
    origin_ok: bool
    attestations_ok: bool
    #: the decision reasons that reject the bundle (every reason other than `state_not_accepted`)
    reasons: list[str]
    problems: list[str]
    policy_sha256: str | None
    policy_source: dict | None = None
    #: the evaluation instant, the effective pin set's digest, and the digest of the unsealed decision members
    #: (sign-offs, time tokens, archive) the decision read: what a sealed record of this decision must name
    as_of: str | None = None
    pins_sha256: str | None = None
    evaluated_signoffs_sha256: str | None = None
    #: the full ``classify_bundle`` report the decision was read from
    report: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def passed(self) -> bool:
        return self.exit_code == EXIT_VERIFIED

    @property
    def rejected(self) -> bool:
        return self.exit_code not in (EXIT_VERIFIED, EXIT_INTEGRITY_ONLY)

    def summary(self) -> dict:
        """The JSON-ready view of the decision (no report): what a reproduce / certify verdict embeds as ``gate``."""
        out = {"exit_code": self.exit_code, "passed": self.passed, "state": self.state,
               "integrity_ok": self.integrity_ok, "origin_ok": self.origin_ok,
               "attestations_ok": self.attestations_ok, "reasons": list(self.reasons),
               "policy_sha256": self.policy_sha256, "as_of": self.as_of, "pins_sha256": self.pins_sha256,
               "evaluated_signoffs_sha256": self.evaluated_signoffs_sha256}
        if self.policy_source is not None:
            out["policy_source"] = self.policy_source
        return out

    def why_not(self) -> str | None:
        """None when the gate passed, else one plain sentence naming why it did not."""
        if self.passed:
            return None
        if self.exit_code == EXIT_UNSUPPORTED_CANON:
            return "the bundle is sealed under a canon this verifier does not support"
        if self.exit_code == EXIT_UNSUPPORTED_ALG:
            return "the bundle is signed with a suite this verifier does not implement"
        if not self.integrity_ok:
            return "integrity does not hold"
        if not self.attestations_ok:
            return "a human sign-off on the bundle does not verify"
        if self.reasons:
            return f"the receiver decision rejects the bundle ({', '.join(self.reasons)})"
        if self.report.get("pinned_key_is_demo") and self.report.get("key_matches_pin"):
            return "origin is not established: the matching pin is the public demo key"
        return "origin is not established under the receiver's pins and policy"


def gate(bundle_bytes: bytes | str, policy: Any = None, pins: Any = None, as_of: str | None = None, *,
         profile=None, policy_source: dict | None = None, expect_policy: str | None = None) -> Decision:
    """Verify ``bundle_bytes`` under the receiver's trust inputs and return the `Decision` ``proof-verify`` makes.

    ``policy`` / ``pins`` / ``as_of`` / ``profile`` are handed to ``classify_bundle`` unchanged (``policy=None`` and
    ``pins=None`` is the single-pin path under the module pin, as ``proof-verify`` with no policy). A malformed policy
    raises PolicyError, before any verdict (``proof-verify`` exits 2). ``expect_policy`` (``sha256:<64 hex>``) raises
    ``policy_source.PolicyMismatch`` unless the verdict's ``policy_sha256`` is that value (``--expect-policy``).
    ``policy_source`` is only recorded on the Decision.

    A ``policy`` given with ``pins=None`` gets proof-verify's out-of-policy pins merged in (every built-in demo pin, as
    a demo pin: ``trust_inputs(policy)``), exactly as ``proof-verify --policy FILE`` evaluates it, so the decision AND
    its ``policy_sha256`` / pins digest are the CLI's for the same policy. Pass ``pins`` explicitly to choose them.

    A ``profile`` that pins an origin key (``pinned_pubkey`` / ``pinned_keys``) together with a ``policy`` that does not
    pin the same key (same demo flag) raises ``policy_source.PolicyUsageError`` (proof-verify: exit 2): under a policy
    the profile's pin would be silently ignored. Pin the key in the policy, or pass it in ``pins``."""
    if policy is not None and pins is None:
        policy, pins = trust_inputs(policy)
    if profile is not None and policy is not None:
        # a profile's origin pin (pinned_pubkey / pinned_keys) is not a trust root under a receiver policy: refuse
        # rather than drop it silently, exactly as proof-verify refuses --profile with such a policy (exit 2)
        from .__main__ import _profile_pin_conflict
        conflict = _profile_pin_conflict(profile, type(profile).__name__, policy, pins,
                                         policy_source or {"kind": "flag", "path": "policy="}, False)
        if conflict is not None:
            raise _ps.PolicyUsageError(conflict)
    rep = classify_bundle(bundle_bytes, profile=profile, policy=policy, pins=pins, as_of=as_of)
    actual = rep.get("policy_sha256")
    if expect_policy is not None and actual != expect_policy:
        source = policy_source or {"kind": "default"}
        raise _ps.PolicyMismatch(f"--expect-policy {expect_policy}: the effective policy ({_ps.describe(source)}) "
                                 f"has policy_sha256 {actual}; no verdict is given under a policy other than the one "
                                 "expected")
    try:
        with _int_digits():                     # the same digit limit classify_bundle reads under (SPEC 4.2 item 8)
            parsed = parse_bundle(bundle_bytes)
    except (ValueError, TypeError, RecursionError, MemoryError):
        parsed = None
    return Decision(
        as_of=rep.get("as_of"), pins_sha256=pins_sha256(rep), evaluated_signoffs_sha256=evaluated_signoffs_sha256(parsed),
        exit_code=decision_exit_code(rep), state=rep.get("state"), integrity_ok=bool(rep.get("integrity_ok")),
        origin_ok=bool(rep.get("origin_ok")), attestations_ok=bool(rep.get("attestations_ok", True)),
        reasons=decision_rejects(rep), problems=list(rep.get("problems") or []), policy_sha256=actual,
        policy_source=policy_source, report=rep)


def trust_inputs(policy: Any, pubkey: str | None = None, *, allow_self_verify: bool = False) -> tuple[Any, Any]:
    """``(policy, pins)`` as ``proof-verify`` builds them from a resolved policy object (None = the built-in default),
    ``--pubkey`` and ``--allow-self-verify`` (SPEC 7.12 / 13.4.1 step 3, 13.5):

    * under a policy, the out-of-policy pins -- every built-in demo pin, as a demo pin, and ``--pubkey`` as a
      non-demo pin -- are merged into it;
    * ``--allow-self-verify`` without a policy evaluates under the default policy with that member set, plus the same
      out-of-policy pins;
    * with neither, ``pins`` is None: the single-pin path, where ``--pubkey`` is the module pin (``apply_single_pin``).

    Raises PolicyError when ``--allow-self-verify`` is combined with a policy that is not a JSON object."""
    pins = None
    if policy is not None:
        pins = [dict(p) for p in BUILTIN_DEMO_PINS]
        if pubkey is not None:
            pins.append({"legacy_raw_key": pubkey, "demo": False})
    if allow_self_verify:
        if policy is None:
            policy = {"schema": "evidence.receiver-policy.v1"}
            pins = [dict(p) for p in BUILTIN_DEMO_PINS]
            if pubkey is not None:
                pins.append({"legacy_raw_key": pubkey, "demo": False})
        if not isinstance(policy, dict):
            raise PolicyError("a receiver policy must be a JSON object")
        policy = {**policy, "allow_self_verify": True}
    return policy, pins


def apply_single_pin(pubkey: str | None, pins: Any) -> None:
    """On the single-pin path (``pins`` None), pin ``--pubkey`` as the module's origin trust root, as ``proof-verify``
    does. Raises ValueError / TypeError for a pubkey that is not 64 lowercase hex."""
    if pubkey is not None and pins is None:
        pin_key(pubkey)


@dataclass(frozen=True)
class Trust:
    """The receiver's resolved trust inputs: what ``gate`` is called with."""

    policy: Any
    pins: Any
    source: dict
    expect_policy: str | None = None
    as_of: str | None = None


def resolve_trust(*, policy_arg: str | None = None, pubkey: str | None = None, no_discovery: bool = False,
                  allow_self_verify: bool = False, expect_policy: str | None = None,
                  as_of: str | None = None) -> Trust:
    """Resolve the command-line trust arguments exactly as ``proof-verify`` does: the policy from ``--policy FILE`` /
    ``preset:NAME`` / ``PROOF_POLICY`` / the built-in default (``policy_source.resolve``), then ``trust_inputs``.
    Does not touch the module pin (see ``apply_single_pin``). Raises PolicyError (exit 2, no verdict) for a policy
    that cannot be read, is malformed, or does not match ``expect_policy`` when that can be told before a bundle is
    read (a policy is in effect), and for a malformed ``expect_policy`` value."""
    bad = _ps.check_expect(expect_policy)
    if bad:
        raise _ps.PolicyUsageError(bad)
    policy, source = _ps.resolve(policy_arg, no_discovery=no_discovery)
    policy, pins = trust_inputs(policy, pubkey, allow_self_verify=allow_self_verify)
    if expect_policy is not None and policy is not None:
        pin_set, members = effective_policy(policy, pins)       # a malformed policy raises PolicyError here
        actual = policy_sha256(members, pin_set)
        if actual != expect_policy:
            raise _ps.PolicyMismatch(f"--expect-policy {expect_policy}: the effective policy "
                                     f"({_ps.describe(source)}) has policy_sha256 {actual}; no verdict is given "
                                     "under a policy other than the one expected")
    return Trust(policy=policy, pins=pins, source=source, expect_policy=expect_policy, as_of=as_of)
