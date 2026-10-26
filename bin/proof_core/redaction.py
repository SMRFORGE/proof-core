"""Verifiable redaction of evidence bundles (disclosure-safe derivatives).

A reviewer, auditor or regulatory docket usually needs two versions of the same evidence: the full
one, and a shareable one with proprietary or export-controlled parts withheld (a plant data snapshot,
a vendor model's inputs, a proprietary design spec). Normally the public copy has no verifiable
relationship to the signed original -- "trust me, this is a redaction of the real thing."

Because the bundle's signature covers only the SEALED DIGEST-LIST (see envelope.build_bundle),
this module produces a redaction whose relationship to the original is provable: it removes a
section's *contents* but keeps that section's *digest* in `sha256sums`, so

  * the withheld value stays pinned by its SHA-256,
  * the seal (`bundle_sha256`) is unchanged, and
  * the ORIGINAL Ed25519 signature still verifies over the redacted copy.

The derivative is therefore provably a redaction of the signed original: nothing changed
except that named sections' contents were withheld, each still bound by digest. `verify_bundle`
(proof_verify) accepts it and refuses an UNDECLARED strip -- a value missing without a matching
redaction entry is a failure, not a pass.

Only whole-section, hash-only withholding is offered (`inputs`, `result`, `provenance`).
The headline case is withholding `inputs` -- a proprietary data snapshot, model configuration or
design spec -- while the computed evidence in `result` stays public and verifiable.
"""
from __future__ import annotations

import copy

#: Sections whose contents may be withheld. Each is a top-level entry of the sealed digest-list.
WITHHOLDABLE = ("inputs", "result", "provenance")

#: Sections that also carry a readable top-level copy in the bundle (removed when withheld).
_TOP_LEVEL_COPY = {"result": "result", "provenance": "reproducibility"}

REDACTION_SCHEMA = "evidence.envelope.redaction.v1"


def redact_bundle(bundle: dict, *, withhold, profile=None) -> dict:
    """Return a disclosure-safe redacted copy of `bundle` with each named section's contents
    withheld. The seal and the original signature are untouched, so the result still verifies.

    ADR-049 (one strict dialect): the redaction record is always PROSE-FREE -- the CLOSED machine key set
    {schema, withheld, parent_bundle_sha256} only. There is no free-text `reason`/`caveats`: an unsigned
    sentence riding on a still-verifying bundle is exactly what prose-free removes; the basis for a
    withholding lives in the producer's own docket/affidavit, never in the bundle.

    Args:
        bundle: a signed evidence bundle (evidence.envelope.v2).
        withhold: section names to withhold (subset of WITHHOLDABLE).
        profile: optional dialect profile; supplies the dialect's own ``redaction_schema`` tag. None/default
            uses the neutral literal.

    Raises:
        ValueError: if a requested section is not withholdable or not present in the bundle.
    """
    names = sorted({str(w) for w in withhold})
    sums = bundle.get("sha256sums", {})
    for name in names:
        if name not in WITHHOLDABLE:
            raise ValueError(f"cannot withhold {name!r}; withholdable sections: {WITHHOLDABLE}")
        if name not in sums:
            raise ValueError(f"section {name!r} is not present in this bundle")

    out = copy.deepcopy(bundle)
    for name in names:
        out["manifest"][name].pop("value", None)          # drop contents, keep the pinned digest
        top = _TOP_LEVEL_COPY.get(name)
        if top and top in out:
            del out[top]                                   # and its readable top-level copy
    # Composable redaction: a second pass must UNION with what a prior pass already withheld, not
    # replace it. Overwriting `withheld` would drop the earlier declaration while its value stays
    # gone from the manifest, producing a derivative the verifier rejects
    # (`value is missing but not declared redacted`).
    prior = {str(w) for w in (bundle.get("redaction") or {}).get("withheld", [])}
    all_withheld = sorted(prior | set(names))
    out["redaction"] = {
        # a dialect brands its own redaction-record schema (its production verifier may require it);
        # None/default -> the neutral literal, so the neutral record is byte-identical.
        "schema": getattr(profile, "redaction_schema", None) or REDACTION_SCHEMA,
        "withheld": all_withheld,
        # the seal is unchanged, so this equals the redacted copy's own bundle_sha256; recorded
        # for traceability back to the exact signed original
        "parent_bundle_sha256": bundle["bundle_sha256"],
    }
    return out
