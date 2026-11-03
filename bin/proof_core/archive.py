"""Producer side of the archive (SPEC v4 10.8): the imprints a producer asks a TSA to stamp for an archive, and
attaching the tokens it gets back as the first stamp or as a timestamp renewal.

proof-core never talks to a TSA: the caller sends the imprint to the time-stamping authority of its choice and passes
the DER tokens back, as for seal tokens (`proof_core.timestamps`). The two producer obligations of 10.8.9 are enforced
here:

- "A producer MUST NOT add, remove or reorder seal tokens after creating an archive (AR-7)": `add_archive` freezes
  the seal tokens into the archived object, and `proof_core.timestamps.add_seal_timestamps` refuses a bundle that
  already has an archive (start a new archive instead: drop the old block, add the tokens, archive again).
- "A producer renewing an archive MUST append the new stamp at a time within the previous stamp's end (AR-13) as the
  receiver's policy will see it": `renew_archive` verifies the renewed bundle under the receiver policy it is given
  and refuses the stamp unless the archive stays `valid` with the new stamp inside its verified prefix.
"""
from __future__ import annotations

import base64
import copy
import hashlib

from .envelope import canon

ARCHIVE_SCHEMA = "evidence.archive.v1"
ARCHIVE_OBJECT_SCHEMA = "evidence.archive.object.v1"
ARCHIVE_RENEWAL_SCHEMA = "evidence.archive.renewal.v1"
_MAX_STAMP_TOKENS = 4
_MAX_STAMPS = 64
_MAX_DIGESTS = 256


def _parse(der: bytes):
    from proof_verify import tsp
    return tsp.parse_token(bytes(der))


def _token_id_of_text(token: str) -> str:
    from proof_verify import tsp
    return tsp.parse_token_text(token).token_id


def entry_digest(entry: dict) -> str:
    """SPEC 10.8.3 AR-8: the entry digest of a sign-off, `entry_sha256` of 10.3.7 (the entry without `timestamps`)."""
    return "sha256:" + hashlib.sha256(canon({k: v for k, v in entry.items() if k != "timestamps"})).hexdigest()


def archive_object(bundle: dict, attestations=()) -> bytes:
    """SPEC 10.8.3: AO = canon_1({schema, bundle_sha256, signatures: [every E signature hex], timestamps: [token_id of
    each seal token], attestations}). ``attestations`` are the entry digests the archive lists (sorted here)."""
    if not isinstance(bundle.get("signature"), dict) or "signature" not in bundle["signature"]:
        raise ValueError("the bundle has no seal signature yet: archive only a finished record (SPEC 10.8.9)")
    sigs = [bundle["signature"]["signature"]] + [b["signature"] for b in bundle.get("signatures", [])]
    ids = [_token_id_of_text(e["token"]) for e in bundle.get("timestamps", [])]
    return canon({"schema": ARCHIVE_OBJECT_SCHEMA, "bundle_sha256": bundle["bundle_sha256"], "signatures": sigs,
                  "timestamps": ids, "attestations": sorted(set(attestations))})


def archive_imprint(bundle: dict, attestations=()) -> bytes:
    """The 32-byte imprint of chain 0 stamp 0 (AR-9): SHA-256(AO). Send it to the TSA."""
    return hashlib.sha256(archive_object(bundle, attestations)).digest()


def renewal_imprint(bundle: dict) -> bytes:
    """The imprint of the next stamp of chain 0 (AR-10), over every token of the last stamp: its token_id and its
    signature digest (10.8.2), so the renewal commits to the previous stamp's signatures."""
    from proof_verify import tsp
    stamps = bundle["archive"]["chains"][0]["stamps"]
    previous = []
    for text in stamps[-1]["tokens"]:
        t = tsp.parse_token_text(text)
        previous.append({"token_id": t.token_id, "sig": tsp.signature_digest(t)})
    return hashlib.sha256(canon({"schema": ARCHIVE_RENEWAL_SCHEMA, "previous": previous})).digest()


def _stamp(tokens: list[bytes], want: bytes, what: str) -> dict:
    if not 1 <= len(tokens) <= _MAX_STAMP_TOKENS:
        raise ValueError(f"a stamp holds 1 to {_MAX_STAMP_TOKENS} tokens (SPEC 10.8.1 AR-4)")
    out = []
    for i, der in enumerate(tokens):
        try:
            got = _parse(der).imprint
        except Exception as exc:          # the verifier's Malformed, or a non-bytes value
            raise ValueError(f"token {i} is not a well-formed RFC 3161 token: {exc}") from exc
        if got != want:
            raise ValueError(f"token {i} does not carry the {what} imprint of this bundle")
        out.append(base64.b64encode(bytes(der)).decode("ascii"))
    return {"format": "rfc3161", "tokens": out}


def add_archive(bundle: dict, tokens: list[bytes], attestations=()) -> dict:
    """Return a COPY of the v4 ``bundle`` with a new `archive`: chain 0 holds one stamp of ``tokens`` (DER RFC 3161
    tokens over `archive_imprint(bundle, attestations)`, normally from different TSAs). ``attestations`` are the entry
    digests of the sign-offs the archive covers; each must be present in `attestations`. Raises ValueError."""
    if "archive" in bundle:
        raise ValueError("the bundle already has an archive: renew it (renew_archive) or drop it to start a new one")
    if len(set(attestations)) > _MAX_DIGESTS:
        raise ValueError(f"an archive lists at most {_MAX_DIGESTS} sign-offs (SPEC 10.8.1 AR-2)")
    present = {entry_digest(e) for e in bundle.get("attestations", []) if isinstance(e, dict)}
    missing = sorted(set(attestations) - present)
    if missing:
        raise ValueError(f"the archive would list sign-off(s) not present in the bundle: {missing} (SPEC 10.8.3 AR-8)")
    stamp = _stamp(list(tokens), archive_imprint(bundle, attestations), "archived-object (AR-9)")
    b = copy.deepcopy(bundle)
    b["archive"] = {"schema": ARCHIVE_SCHEMA, "object": {"attestations": sorted(set(attestations))},
                    "chains": [{"hash": "sha256", "stamps": [stamp]}]}
    return b


def renew_archive(data: bytes | str, tokens: list[bytes], *, policy: dict, as_of: str) -> dict:
    """Return a COPY of ``bundle`` with ``tokens`` appended to chain 0 as a timestamp renewal (AR-10). SPEC 10.8.9:
    the new stamp must be "at a time within the previous stamp's end (AR-13) as the receiver's policy will see it", so
    the renewed bundle is verified under the receiver ``policy`` at ``as_of``; unless its archive is `valid` and the
    new stamp is accepted inside the verified prefix with no continuity problem, ValueError is raised (renew earlier,
    or under a TSA the policy still trusts). ``data`` is the bundle's bytes or text (SPEC 4); a parsed object raises
    TypeError, and unreadable bytes raise ValueError."""
    from proof_verify import classify_bundle

    from .envelope import bundle_bytes, received_bundle
    _, bundle = received_bundle(data, "renew_archive")
    if not isinstance(bundle, dict):
        raise ValueError("renew_archive: the bundle is unreadable (SPEC 4)")  # noqa: TRY004 -- unreadable bytes, not a type
    stamps = bundle.get("archive", {}).get("chains", [{}])[0].get("stamps")
    if not isinstance(stamps, list) or not stamps:
        raise ValueError("the bundle has no archive to renew: create one with add_archive")
    if len(stamps) >= _MAX_STAMPS:
        raise ValueError(f"chain 0 already holds {_MAX_STAMPS} stamps (SPEC 10.8.1 AR-4)")
    stamp = _stamp(list(tokens), renewal_imprint(bundle), "timestamp-renewal (AR-10)")
    b = copy.deepcopy(bundle)
    b["archive"]["chains"][0]["stamps"].append(stamp)
    rep = classify_bundle(bundle_bytes(b), policy=policy, as_of=as_of)   # the renewed bundle this producer made
    a = rep["archive"]
    last = a["chains"][0]["stamps"][-1] if a["chains"] else None
    if a["state"] != "valid" or last is None or last["class"] != "accepted" or last["problems"]:
        why = "; ".join(a["problems"] + (last["problems"] if last else [])) or f"the new stamp is {last and last['class']}"
        raise ValueError(f"the renewal is not within the previous stamp's end under this policy (SPEC 10.8.9, AR-13): "
                         f"archive {a['state']}: {why}")
    want = policy.get("min_archive_tsas", 1) if isinstance(policy, dict) else 1
    have = _stamp_distinct_tsas(stamp, renewal_imprint(bundle), policy)
    if have < want:
        raise ValueError(f"the renewal stamp has accepted tokens from {have} distinct TSA(s), fewer than the "
                         f"receiver's min_archive_tsas {want}; every stamp needs them (SPEC 10.8.9, 7.13; distinct "
                         "TSAs are distinct TSA keys, 10.7.7)")
    return b


def _stamp_distinct_tsas(stamp: dict, imprint: bytes, policy: dict) -> int:
    """The number of distinct TSA key identities (SPEC 10.7.7) among the accepted tokens of ``stamp`` under the
    receiver ``policy`` -- the count 10.8.6 `min_tsas` takes, so one key pinned twice is one TSA."""
    from proof_verify import tsp as _tsp
    from proof_verify.verify import effective_policy
    members = effective_policy(policy)[1]
    pins = [{**p, "_cert": _tsp.pin_cert(p)} for p in sorted(members.get("tsas") or [], key=lambda p: p["id"])]
    reps = [_tsp.classify_token({"format": "rfc3161", "token": t}, j, imprint, pins,
                                allow_ess_v1=bool(members.get("allow_ess_v1")), aged=None)
            for j, t in enumerate(stamp["tokens"])]
    return _tsp.distinct_tsas([r for r in reps if r["class"] == "accepted"])
