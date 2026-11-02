"""Human sign-off: a countersignature on a sealed decision.

The bundle `signature` is the PRODUCER's seal -- it proves the record came from the producing system and was
not edited. It does not say a *named person* approved the decision. In many settings (a credit adjudication, a
model-risk validation, a supervisory approval, deploying an AI agent whose conduct the deployer answers for) the
accountable human must sign to own the call.

An attestation is that sign-off: the approver signs over the sealed bundle digest TOGETHER WITH their role,
name and timestamp, so none of those can be changed without breaking the sign-off, and it is appended to the
bundle's `attestations` list WITHOUT touching the decision seal. The independent verifier (proof_verify) checks
each attestation's signature; whether a signing key really belongs to the named person is an identity question
(a pinned approver registry / hardware-key attestation / SSO binding), the same way the producer's origin is a
property of the pinned key -- stated honestly, not asserted by a label.

    bundle = produce(...)                      # system seals the decision
    bundle = attest_bundle(bundle, "adjudicator", "A. Officer", officer_sk)   # the human signs off
    verify_bundle(bundle)                       # decision seal unchanged; proof_verify also reports the sign-off
"""
from __future__ import annotations

import copy
import datetime
import hashlib

from . import signing
from .envelope import canon

ATTESTATION_SCHEMA = "evidence.attestation.v1"
#: the message label an approver signs under; bound INTO the signed bytes (mirrors the producer signature's
#: S2 `message`), so it names what was signed and cannot be swapped or the schema relabelled after the fact.
ATTESTATION_MESSAGE = "attests:v1"


def _attestation_message(bundle_sha256: str, role: str, name: str, timestamp: str) -> bytes:
    """The exact bytes an approver signs: the sealed decision digest bound to the attestation SCHEMA and
    message label AND to WHO signed off, as WHAT, and WHEN. Canonical JSON (sorted keys) so the independent
    verifier re-derives identical bytes. Binding the schema, label, role, name and timestamp into the signed
    message is what stops any of them being swapped after the fact (a sign-off cannot be lifted onto a
    different schema, relabelled, or re-attributed)."""
    return canon({"attests": bundle_sha256, "schema": ATTESTATION_SCHEMA, "message": ATTESTATION_MESSAGE,
                  "role": role, "name": name, "timestamp": timestamp})


def make_attestation(bundle_sha256: str, role: str, name: str, sk: bytes, *, timestamp: str | None = None) -> dict:
    """Build a single sign-off over `bundle_sha256` under the approver's private key `sk`."""
    ts = timestamp or datetime.datetime.now(datetime.UTC).isoformat()
    pk = signing.publickey(sk)
    sig = signing.sign(_attestation_message(bundle_sha256, role, name, ts), sk, pk)
    return {
        "schema": ATTESTATION_SCHEMA,
        "role": role,
        "name": name,
        "public_key": pk.hex(),
        "timestamp": ts,
        "message": ATTESTATION_MESSAGE,   # bound into the signed bytes (with schema, role, name, timestamp)
        "signature": sig.hex(),
    }


def attest_bundle(bundle: dict, role: str, name: str, sk: bytes, *, timestamp: str | None = None) -> dict:
    """Return a COPY of `bundle` with a human approver's sign-off appended to `attestations`.

    The approver signs the sealed bundle digest together with their role, name and timestamp. The decision
    seal (the producer `signature`) is left untouched, so the sign-off is additive: several approvers can
    countersign the same sealed decision (maker-checker), and `verify_bundle`'s integrity+origin verdict over
    the decision is unchanged. Raises if the bundle carries no `bundle_sha256` to sign."""
    digest = bundle.get("bundle_sha256")
    if not isinstance(digest, str) or not digest:
        raise ValueError("cannot attest a bundle with no bundle_sha256 (seal it first)")
    b = copy.deepcopy(bundle)
    b.setdefault("attestations", []).append(make_attestation(digest, role, name, sk, timestamp=timestamp))
    return b


# --- sign-offs v2 (SPEC 10.3.2 to 10.3.9), for evidence.envelope.v4 bundles ---------------------------------------
# An entry states a role, a meaning code and a statement, a printed name, a signer id, a claimed signing time, which
# copy the signer viewed and which earlier entries it follows, all signed with the seal the bundle carries. What a
# valid entry shows is narrow (10.3.9): the holder of the key signed this text over this seal. It does not show who
# the person is, and `signed_at` is the signer's own claim; only an accepted, pinned timestamp token (a later
# release) bounds when the signature existed.

ATTESTATION_V2_SCHEMA = "evidence.attestation.v2"
ATTESTATION_V2_MESSAGE = "attests:v2"
#: SPEC 10.3.3: the role names (domain-neutral) and the meaning codes. An extension meaning matches
#: `x-[a-z0-9][a-z0-9-]{0,30}`; it never satisfies a required role and never acts as a rejection (13.4.4).
SIGNOFF_ROLES = ("originator", "verifier", "approver")
SIGNOFF_MEANINGS = ("authorship", "review", "approval", "responsibility", "rejection")
_SIGNED_MEMBERS = ("alg", "attests", "meaning", "message", "printed_name", "prior", "public_key", "reviewed_copy",
                   "role", "schema", "signed_at", "signer_id", "statement")


def reviewed_copy(withheld_sections=(), withheld_item_paths=()) -> dict:
    """SPEC 10.3.6: the `reviewed_copy` record of the copy a signer viewed: the sorted withheld sections (from
    inputs and result), the number of withheld items, and `digest(canon_1(P))` with P the withheld item paths in
    code point order. ``reviewed_copy()`` is the full copy."""
    paths = sorted(withheld_item_paths)
    return {"withheld_sections": sorted(set(withheld_sections)), "withheld_items_count": len(paths),
            "withheld_items_sha256": "sha256:" + hashlib.sha256(canon(paths)).hexdigest()}


def signoff_signed_bytes(entry: dict, seal: str) -> bytes:
    """SPEC 10.3.7: M = canon_1(O), the 13 signed members of the entry with `attests` set to ``seal``."""
    o = {k: entry[k] for k in _SIGNED_MEMBERS}
    o["attests"] = seal
    return canon(o)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_signoff(bundle: dict, signer, *, role: str, meaning: str, statement: str, printed_name: str,
                 signer_id: str, signed_at: str | None = None, reviewed: dict | None = None,
                 prior=(), allow_self_verify: bool = False) -> dict:
    """Build one `evidence.attestation.v2` entry over ``bundle``'s seal, signed by ``signer``.

    ``signer`` is the external-signer hook (duck-typed, like `use_signer`): ``alg`` (default ``"ed25519"``),
    ``public_key() -> bytes`` and ``sign(msg) -> bytes``. A hardware or remote key signs through it; the kernel never
    sees the private key. For a suite this kernel does not implement, the signer must also provide
    ``verify(msg, sig)``, so the mint can check its own output.

    ``signed_at`` defaults to now (UTC, whole seconds): it is the time the signer STATES, never a checked time.
    ``reviewed`` is a `reviewed_copy(...)` record (default: the full copy); ``prior`` the entry digests this entry
    follows (they must be entries already in the bundle). The entry is checked with the independent verifier before
    it is returned (SPEC 14: a producer emits only what the reference verifier accepts), and a `verifier` or
    `approver` entry under an originator's key or signer id is refused unless ``allow_self_verify`` (SPEC 13.4.5:
    the default receiver policy rejects it). Raises ValueError."""
    from proof_verify import verify as _v
    if not isinstance(bundle, dict) or bundle.get("schema") != "evidence.envelope.v4":
        raise ValueError("sign-offs v2 apply to evidence.envelope.v4 bundles only (SPEC 10.3); a v3 bundle keeps "
                         "evidence.attestation.v1 (attest_bundle)")
    seal = bundle.get("bundle_sha256")
    if not isinstance(seal, str) or not seal.startswith("sha256:"):
        raise ValueError("cannot sign off a bundle with no bundle_sha256 (seal it first)")
    signing.signer_key_problems(signer, where="signer")
    alg = signing.signer_alg(signer)
    entry = {"schema": ATTESTATION_V2_SCHEMA, "message": ATTESTATION_V2_MESSAGE, "attests": seal, "role": role,
             "meaning": meaning, "statement": statement, "printed_name": printed_name, "signer_id": signer_id,
             "signed_at": signed_at if signed_at is not None else _utc_now(),
             "reviewed_copy": reviewed if reviewed is not None else reviewed_copy(),
             "prior": sorted(set(prior)), "alg": alg, "public_key": bytes(signer.public_key()).hex()}
    problems = _v._att2_shape_problems({**entry, "signature": "00" * 64}, seal)
    problems = [p for p in problems if not p.startswith("entry.signature")]
    if problems:
        raise ValueError(f"refusing to mint a sign-off: {problems[0]}")
    msg = signoff_signed_bytes(entry, seal)
    sig = signing._encode_sig(alg, signer.sign(msg))
    ok = signing.verify_suite(alg, bytes(signer.public_key()), msg, sig)
    if ok is None:
        own = getattr(signer, "verify", None)
        if own is None:
            raise ValueError(f"refusing to mint a sign-off: a {alg!r} signer must provide verify(msg, sig) so the "
                             "mint can check its own signature")
        ok = own(msg, sig) is True
    if not ok:
        raise ValueError(f"refusing to mint a sign-off: the {alg!r} signature does not verify over the signed object")
    entry["signature"] = sig.hex()
    trial = copy.deepcopy(bundle)
    trial.setdefault("attestations", []).append(entry)
    rep = _v.check_signoffs_v2(trial, _v._sha(_v._canon(bundle["sha256sums"])), {}, dict(_v._POLICY_DEFAULTS),
                               _v.utc_now())
    mine = rep["entries"][-1]
    if mine["state"] == "invalid":
        raise ValueError(f"refusing to mint a sign-off the verifier rejects: {mine['problems'][:2]}")
    if mine["self_verify"] and not allow_self_verify:
        raise ValueError("refusing to mint a self-verification: this verifier/approver sign-off uses an originator's "
                         "key or signer id (the default receiver policy rejects it; pass allow_self_verify=True to "
                         "mint it anyway)")
    return entry


def add_signoff(bundle: dict, signer, **fields) -> dict:
    """Return a COPY of the v4 ``bundle`` with one sign-off v2 entry (`make_signoff`) appended to `attestations`. The
    seal and the seal signatures are untouched: sign-offs sit outside the seal (SPEC 10.3)."""
    entry = make_signoff(bundle, signer, **fields)
    b = copy.deepcopy(bundle)
    b.setdefault("attestations", []).append(entry)
    return b


def signoff_digest(entry: dict) -> str:
    """SPEC 10.3.7 "Entry digest": `digest(canon_1(entry minus "timestamps"))`, the value a later entry's `prior`
    cites."""
    return "sha256:" + hashlib.sha256(canon({k: v for k, v in entry.items() if k != "timestamps"})).hexdigest()
