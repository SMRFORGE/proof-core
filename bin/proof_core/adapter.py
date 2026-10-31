"""proof_core.adapter -- the generic integration base for sealing a result and re-deriving it.

A thin, domain-agnostic convenience over the kernel verbs for the single most common integration shape:

  1. pin the INPUTS that reproduce a result (the re-run recipe),
  2. SEAL the result's content hash into a bundle,
  3. VERIFY the bundle offline, and
  4. REPRODUCE it by recomputing from the sealed inputs via a caller-supplied runner and comparing digests.

It imports no domain or vendor code. A producer integrates in a few lines by constructing one ``Adapter`` and
calling ``seal`` / ``verify`` / ``reproduce``; a vendor connector is the same plus a wrapper that knows the
tool's result shape. This is the free, self-serve integration path -- the paid work is the maintained,
vendor-specific wrapper around it, never this base.

``outcome`` is whatever computed value is the point of the result (a metric dict, an eval scored-view, a solver
output). ``view`` optionally transforms it before hashing, so the sealed outcome is the reproducible subset
(e.g. scores without timestamps). The transform is applied identically on seal and on reproduce, so what is
sealed is exactly what is re-derived.
"""
from __future__ import annotations

import json

from .contract import Case, Fidelity, Result, Verdict
from .envelope import build_bundle, canon, sha
from .signing import use_signer


def _digest(outcome, view):
    """Content hash of the (optionally view-transformed) outcome -- the canonical sealed value."""
    return sha(canon(view(outcome) if view is not None else outcome))


class Adapter:
    """Seal / verify / reproduce for one capability. Construct once, reuse per result.

    ``capability`` is the result's capability string; ``engine`` / ``engine_version`` identify the producing
    engine; ``caveat`` is the honest-scope line appended to every result's caveats; ``view`` optionally
    transforms the outcome before hashing; ``outcome_key`` is the outputs key the sealed digest is written to
    (e.g. ``"metrics_sha256"``), which ``reproduce`` reads back.
    """

    def __init__(self, *, capability, engine, engine_version, caveat="", view=None,
                 outcome_key="result_sha256"):
        self.capability = capability
        self.engine = engine
        self.engine_version = engine_version
        self.caveat = caveat
        self.view = view
        self.outcome_key = outcome_key

    def digest(self, outcome):
        """Content hash of ``outcome`` under this adapter's ``view`` -- the value sealed and compared."""
        return _digest(outcome, self.view)

    def seal(self, *, inputs, outcome, verdict, data_label, outputs=None, extra_outputs=None,
             fidelity=Fidelity.SCREENING, caveats=(), provenance=None, signer=None):
        """Seal ``outcome`` into a signed bundle, pinning ``inputs`` as the re-run recipe.

        ``inputs`` is the recipe a reviewer re-runs; ``outcome`` is the computed value, pinned by content hash
        (its digest also lands in outputs under ``outcome_key`` and is the ``data_library`` digest under
        ``data_label``); ``extra_outputs`` are extra result fields (e.g. an aggregate) folded into outputs.
        Returns ``(bundle, bundle_bytes)``. Demo key by default (integrity-only); pass ``signer`` for a
        production key.
        """
        if signer is not None:
            use_signer(signer)
        d = self.digest(outcome)
        out = dict(outputs or {})
        out[self.outcome_key] = d
        if extra_outputs:
            out.update(extra_outputs)
        cavs = tuple(caveats) + ((self.caveat,) if self.caveat else ())
        case = Case(capability=self.capability, inputs=inputs)
        result = Result(capability=self.capability, fidelity=fidelity, verdict=verdict,
                        outputs=out, caveats=cavs, provenance=provenance or {})
        bundle = build_bundle(case, result, engine=self.engine, engine_version=self.engine_version,
                              data_library=(data_label, d))
        return bundle, json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode()

    def verify(self, bundle_or_bytes):
        """Independent offline check. Returns a verdict dict, never raises on bad input: malformed JSON yields
        ``{"integrity_ok": False, "state": "fail", ...}`` rather than a traceback. Imports no producer code."""
        from proof_verify.verify import classify_bundle
        try:
            bundle = _load(bundle_or_bytes)
        except (ValueError, TypeError, RecursionError, MemoryError) as exc:
            return {"integrity_ok": False, "state": "fail",
                    "error": f"not a valid bundle ({exc.__class__.__name__})"}
        return classify_bundle(bundle)

    def sealed_inputs(self, bundle):
        """The sealed re-run recipe (the ``inputs`` passed to ``seal``)."""
        return bundle["manifest"]["inputs"]["value"]["inputs"]

    def sealed_outcome_sha(self, bundle):
        """The sealed outcome digest (under ``outcome_key``), or ``None`` if this bundle carries no result for
        this adapter's capability/outcome_key (a foreign or incompatible bundle). Never raises on a structurally
        valid bundle."""
        try:
            return bundle["manifest"]["result"]["value"]["result"].get(self.capability, {}).get(self.outcome_key)
        except (KeyError, TypeError, AttributeError):
            return None

    def reproduce(self, bundle, run, *, verify_first=True):
        """Re-derive the sealed outcome and confirm it matches.

        ``run(inputs) -> outcome`` recomputes the outcome from the sealed inputs; the digest of the result is
        compared to the sealed digest. By default the bundle's integrity is checked FIRST (``verify_first``),
        and a bundle that fails verification is not re-derived -- so a tampered recipe can never read as
        reproduced. A foreign/incompatible bundle (valid, but carrying no result for this capability) returns
        ``reproduced=False`` with an ``error`` rather than raising. Returns ``{"reproduced": bool,
        "expected_sha", "got_sha"}`` (plus ``"error"`` when it refuses). Pass ``verify_first=False`` only when
        the caller has already verified.

        ``bundle`` may be the bundle's bytes/str (preferred for a file from someone else: it is parsed ONCE with
        the verifier's hardened loader, which refuses duplicate keys, so the recipe that is re-run is the one
        that was verified) or a dict. A dict must come from ``proof_verify.verify.loads``: a plain ``json.loads``
        silently keeps the LAST of two duplicate keys, and that cannot be detected after parsing.
        """
        if not isinstance(bundle, dict):
            try:
                bundle = _load(bundle)
            except (ValueError, TypeError, RecursionError, MemoryError) as exc:
                return {"reproduced": False, "expected_sha": None, "got_sha": None,
                        "error": f"not a valid bundle ({exc.__class__.__name__})"}
        if verify_first and not self.verify(bundle).get("integrity_ok", False):
            return {"reproduced": False, "expected_sha": None, "got_sha": None,
                    "error": "bundle failed integrity verification; not re-deriving"}
        expected = self.sealed_outcome_sha(bundle)
        if expected is None:
            return {"reproduced": False, "expected_sha": None, "got_sha": None,
                    "error": f"no {self.outcome_key!r} under capability {self.capability!r} "
                             "(foreign or incompatible bundle)"}
        got = self.digest(run(self.sealed_inputs(bundle)))
        return {"reproduced": got == expected, "expected_sha": expected, "got_sha": got}


def _load(bundle_or_bytes):
    """A dict passes through; bytes/str are parsed with the verifier's own hardened loader (duplicate keys, NaN,
    depth, size, digit limit), never a plain json.loads, so the text a person reads is the text that is checked."""
    if isinstance(bundle_or_bytes, dict):
        return bundle_or_bytes
    from proof_verify.verify import loads
    text = bundle_or_bytes.decode("utf-8") if isinstance(bundle_or_bytes, (bytes, bytearray)) else bundle_or_bytes
    return loads(text)


__all__ = ["Adapter", "Fidelity", "Verdict"]
