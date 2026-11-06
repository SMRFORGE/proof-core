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

LEAK BOUNDARY (producer's responsibility, not the verifier's): withholding removes a section's
CONTENTS and keeps its DIGEST pinned. It does NOT guarantee the withheld value appears nowhere else
in the bundle. If the producer echoes a withheld `inputs` value into a public section (the readable
`provenance`/`reproducibility`, or the `result` map), it is still readable in the clear even though
`inputs` is "withheld". The verifier catches only one specific echo (a withheld input re-stated in the
result core's `provenance.inputs`); it cannot scan for every possible echo. The withholder MUST ensure
the withheld content is not reproduced in any retained public section. The format's promise is "the
digest stays pinned", never "this content appears nowhere else".
"""
from __future__ import annotations

import copy

#: Sections whose contents may be withheld. Each is a top-level entry of the sealed digest-list.
WITHHOLDABLE = ("inputs", "result", "provenance")

#: Sections that also carry a readable top-level copy in the bundle (removed when withheld).
_TOP_LEVEL_COPY = {"result": "result", "provenance": "reproducibility"}

REDACTION_SCHEMA = "evidence.envelope.redaction.v1"
#: SPEC evidence.envelope.v4 draft 10.4: the record of a canon-3 (v4) bundle.
REDACTION_SCHEMA_V2 = "evidence.envelope.redaction.v2"
#: v4 sections that may be withheld whole (6.6.6 P5: "In v4, `provenance` MUST NOT be withheld as a section").
WITHHOLDABLE_V4 = ("inputs", "result")


def _is_v4(bundle: dict) -> bool:
    sums = bundle.get("sha256sums")
    return isinstance(sums, dict) and sums.get("canon_version") == 3


def _redact_v4(bundle: dict, sections: list[str], items: list[str], profile) -> dict:
    """See `_redact_v4_impl`. A malformed bundle raises ValueError (never KeyError/TypeError)."""
    try:
        return _redact_v4_impl(bundle, sections, items, profile)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError(f"cannot redact a malformed v4 bundle ({type(exc).__name__}: {exc})") from None


def _redact_v4_impl(bundle: dict, sections: list[str], items: list[str], profile) -> dict:
    """SPEC v4 draft 10.4: withhold whole sections (inputs, result) and/or committed items by path, keeping the seal.
    R7: "the sorted union of the old and new `withheld_sections`; the sorted union of the old and new
    `withheld_items`, minus every path under a section that is now wholly withheld"."""
    from .committed import item_at, set_item, withheld_form
    for name in sections:
        if name not in WITHHOLDABLE_V4:
            raise ValueError(f"cannot withhold {name!r} in a v4 bundle; withholdable sections: {WITHHOLDABLE_V4}")
    out = copy.deepcopy(bundle)
    for path in items:
        set_item(out, path, withheld_form(item_at(out, path)))     # raises on a path that names no item
    for name in sections:
        out["manifest"][name].pop("value", None)
        top = _TOP_LEVEL_COPY.get(name)
        if top and top in out:
            del out[top]
    prior = bundle.get("redaction") if isinstance(bundle.get("redaction"), dict) else {}
    all_sections = sorted(set(prior.get("withheld_sections", [])) | set(sections))
    all_items = sorted(p for p in set(prior.get("withheld_items", [])) | set(items)
                       if p.split("/")[1] not in all_sections)
    if not all_sections and not all_items:
        out.pop("redaction", None)
        return out
    out["redaction"] = {"schema": getattr(profile, "redaction_schema_v2", None) or REDACTION_SCHEMA_V2,
                        "parent_bundle_sha256": bundle["bundle_sha256"],
                        "withheld_sections": all_sections, "withheld_items": all_items}
    return out


def redact_bundle(bundle: dict, *, withhold=(), withhold_items=(), profile=None, _allow_result_withheld=False) -> dict:
    """Return a disclosure-safe redacted copy of `bundle` with each named section's contents
    withheld. The seal and the original signature are untouched, so the result still verifies.

    ADR-049 (one strict dialect): the redaction record is always PROSE-FREE -- the CLOSED machine key set
    {schema, withheld, parent_bundle_sha256} only. There is no free-text `reason`/`caveats`: an unsigned
    sentence riding on a still-verifying bundle is exactly what prose-free removes; the basis for a
    withholding lives in the producer's own docket/affidavit, never in the bundle.

    Args:
        bundle: a signed evidence bundle (evidence.envelope.v3).
        withhold: section names to withhold (subset of WITHHOLDABLE). In a v4 (canon 3) bundle, withholding
            ``"result"`` keeps the seal but makes the statistical band uncheckable, so every receiver decision
            rejects the copy (SPEC v4 13.4.3 row 22, spec 1.3, fail closed). It is refused unless
            ``_allow_result_withheld`` is true; keep part of a v4 result back with committed items and
            ``withhold_items`` instead.
        _allow_result_withheld: produce a v4 copy with its result section withheld anyway (one every receiver
            rejects; for test vectors and demonstrations).
        profile: optional dialect profile; supplies the dialect's own ``redaction_schema`` tag. None/default
            uses the neutral literal.

        withhold_items: v4 (canon 3) only -- item paths (``"/" + section + JSON pointer``) of disclosed committed
            items to rewrite into withheld form (SPEC v4 draft 6.6, 10.4). A v4 bundle gets a redaction record v2.

    Raises:
        ValueError: if a requested section is not withholdable or not present in the bundle, or an item path
            names no committed item.
    """
    names = sorted({str(w) for w in withhold})
    if _is_v4(bundle) and "result" in names and not _allow_result_withheld:
        raise ValueError("withholding the result section of a v4 bundle makes every receiver reject the copy "
                         "(SPEC v4 13.4.3 row 22, spec 1.3: its band cannot be checked); seal the parts to keep back "
                         "as committed items and withhold those with withhold_items, or pass "
                         "_allow_result_withheld=True (private: test vectors only) for a copy that is meant to be rejected")
    if _is_v4(bundle):
        return _redact_v4(bundle, names, sorted({str(p) for p in withhold_items}), profile)
    if withhold_items:
        raise ValueError("withhold_items needs a canon-3 (evidence.envelope.v4) bundle; a v3 bundle has no items")
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
