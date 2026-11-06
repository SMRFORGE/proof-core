"""proof_core.adapter -- the generic integration base for sealing a result and re-deriving it.

A thin, domain-agnostic convenience over the kernel verbs for the single most common integration shape:

  1. pin the INPUTS that reproduce a result (the re-run recipe),
  2. SEAL the result's content hash into a bundle,
  3. VERIFY the bundle offline, and
  4. REPRODUCE it by recomputing from the sealed inputs via a caller-supplied runner. ``reproduce`` delegates to the
     kernel's ``reproduce_bundle`` (the same comparison and the same verify step ``proof-reproduce`` uses): when the
     runner returns a ``Rerun`` the WHOLE sealed result is re-derived -- the outcome digest, every other sealed
     output (``outputs`` / ``extra_outputs``) and the claim fields (verdict, fidelity, caveats) -- and ``reproduced``
     follows ``proof-reproduce``'s exit-0 rule. A runner that returns only the outcome re-derives only its digest:
     that is ``outcome_reproduced``, never ``reproduced``, and the report lists what was not checked.

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
from dataclasses import dataclass, field
from typing import Any

from .contract import Case, Fidelity, Result, Verdict
from .envelope import build_bundle, canon, sha
from .signing import use_signer


@dataclass(frozen=True)
class Rerun:
    """What a FULL re-run hands back to ``Adapter.reproduce``: the outcome and every sealed claim ``seal`` took.

    Mirrors ``Adapter.seal``'s arguments, so the re-run re-derives the whole sealed result, not only the outcome
    digest: ``outputs`` / ``extra_outputs`` (e.g. an aggregate computed from the outcome), the ``verdict``, the
    ``fidelity`` tier and the ``caveats`` (the adapter's own caveat is appended, as on seal).

    ``data_library`` is the data environment the re-run says it used, ``(label, "sha256:<hex>")``; it is compared to
    the sealed pin. It is the CALLER'S DECLARATION and is NOT checked: proof-core cannot see what the re-run read, so
    a receiver must trust whoever ran the re-run for it. For an ``Adapter.seal`` bundle the sealed pin is
    ``(data_label, <the outcome digest>)``, so declaring it (the label plus the recomputed outcome digest) adds
    nothing beyond the outcome check itself; it only says that the caller vouches for the environment. Left out, the
    re-run's environment is not captured: the report says ``environment_unverifiable`` and the result is never
    ``reproduced`` (the sealed pin is never echoed back as if the re-run had confirmed it)."""

    outcome: Any
    verdict: Verdict
    outputs: dict | None = None
    extra_outputs: dict | None = None
    fidelity: Fidelity = Fidelity.SCREENING
    caveats: tuple = ()
    provenance: dict = field(default_factory=dict)
    data_library: tuple | None = None


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
             fidelity=Fidelity.SCREENING, caveats=(), provenance=None, signer=None, canon_version=3):
        """Seal ``outcome`` into a signed bundle, pinning ``inputs`` as the re-run recipe.

        ``inputs`` is the recipe a reviewer re-runs; ``outcome`` is the computed value, pinned by content hash
        (its digest also lands in outputs under ``outcome_key`` and is the ``data_library`` digest under
        ``data_label``); ``extra_outputs`` are extra result fields (e.g. an aggregate) folded into outputs.
        Returns ``(bundle, bundle_bytes)``. Demo key by default (integrity-only); pass ``signer`` for a
        production key. ``canon_version`` selects the envelope, as ``build_bundle``: 3 (the default) mints
        ``evidence.envelope.v4``, 1 the frozen ``evidence.envelope.v3``.
        """
        if signer is not None:
            use_signer(signer)
        result, d = self._result(outcome, verdict=verdict, outputs=outputs, extra_outputs=extra_outputs,
                                 fidelity=fidelity, caveats=caveats, provenance=provenance)
        case = Case(capability=self.capability, inputs=inputs)
        bundle = build_bundle(case, result, engine=self.engine, engine_version=self.engine_version,
                              data_library=(data_label, d), canon_version=canon_version)
        return bundle, json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode()

    def verify(self, bundle_or_bytes):
        """Independent offline check. Returns a verdict dict, never raises on bad input: malformed JSON yields
        ``{"integrity_ok": False, "state": "fail", ...}`` rather than a traceback. Imports no producer code."""
        from proof_verify.verify import classify_bundle
        if not isinstance(bundle_or_bytes, (bytes, bytearray, str)):
            # SPEC 4 / 17.3.2: a verdict is given on bytes or text only; a parsed object cannot show the duplicate
            # keys of the bytes it came from. Still a verdict, never an exception.
            return {"integrity_ok": False, "state": "fail",
                    "error": "verify takes the bundle's bytes or text (SPEC 4), not a parsed "
                             f"{type(bundle_or_bytes).__name__}"}
        try:
            return classify_bundle(bundle_or_bytes)   # the verifier parses the bytes itself (SPEC 4)
        except (TypeError, RecursionError, MemoryError) as exc:
            return {"integrity_ok": False, "state": "fail",
                    "error": f"not a valid bundle ({exc.__class__.__name__})"}

    def sealed_inputs(self, bundle):
        """The sealed re-run recipe (the ``inputs`` passed to ``seal``), as the VALUES the engine computes on: every
        disclosed committed item is unwrapped to its plain value, as ``reproduce_bundle`` does (salts and marks are
        not inputs). Raises ValueError ("N items withheld; reproduce not possible here", SPEC v4 draft 10.6) when
        it holds a withheld committed item."""
        from .committed import disclosed_values, refuse_withheld_items
        inputs = bundle["manifest"]["inputs"]["value"]["inputs"]
        sums = bundle.get("sha256sums") if isinstance(bundle, dict) else None
        if not (isinstance(sums, dict) and sums.get("canon_version") == 3):
            return inputs                   # under canon 1 and 2 a `$committed` object is plain data (6.6.1)
        refuse_withheld_items(inputs, "sealed inputs")
        return disclosed_values(inputs)

    def sealed_outcome_sha(self, bundle):
        """The sealed outcome digest (under ``outcome_key``), or ``None`` if this bundle carries no result for
        this adapter's capability/outcome_key (a foreign or incompatible bundle). Never raises on a structurally
        valid bundle."""
        try:
            return bundle["manifest"]["result"]["value"]["result"].get(self.capability, {}).get(self.outcome_key)
        except (KeyError, TypeError, AttributeError):
            return None

    def _result(self, outcome, *, verdict, outputs=None, extra_outputs=None, fidelity=Fidelity.SCREENING,
                 caveats=(), provenance=None):
        """(the Result ``seal`` mints for these arguments, the outcome digest): ONE place, for seal and re-run."""
        d = self.digest(outcome)
        out = dict(outputs or {})
        out[self.outcome_key] = d
        if extra_outputs:
            out.update(extra_outputs)
        cavs = tuple(caveats) + ((self.caveat,) if self.caveat else ())
        return Result(capability=self.capability, fidelity=fidelity, verdict=verdict, outputs=out, caveats=cavs,
                      provenance=provenance or {}), d

    def reproduce(self, bundle, run, *, verify_first=True, policy=None, pins=None, as_of=None):
        """Re-derive the sealed result and confirm it matches, through the kernel's ``reproduce_bundle``.

        ``run(inputs)`` recomputes from the sealed inputs and returns either

        * a ``Rerun`` (the outcome AND the verdict, outputs / extra_outputs, fidelity, caveats ``seal`` took, and the
          data environment it actually used): the fresh result is minted exactly as ``seal`` mints it and compared to
          the WHOLE sealed result core (every output, the claim fields) by ``reproduce_bundle``. ``reproduced`` is
          the kernel's verdict, ``proof-reproduce``'s exit-0 rule: the result and claim re-derive
          (``outputs_reproduced``) AND the bundle passes the one gate under the receiver's trust inputs
          (``verified``) AND the re-run used the sealed inputs AND the environment is declared and matches.
          ``shortfalls`` names what failed (``gate_not_passed``, ``inputs_not_identical``, ``environment_mismatch``,
          ``environment_unverifiable``); ``not_checked`` lists sealed caveats the re-run did not produce; or
        * the outcome alone (the older form): only its digest is re-derived. ``outcome_reproduced`` says whether it
          matched; ``reproduced`` and ``outputs_reproduced`` are False, and ``not_checked`` lists the sealed outputs
          and claim fields that were taken on trust.

        Trust inputs: ``policy`` / ``pins`` / ``as_of`` reach the gate exactly as ``proof-verify``'s. With neither
        ``policy`` nor ``pins`` they are resolved as ``proof-verify`` resolves them with no flags
        (``proof_verify.gate.resolve_trust``: ``$PROOF_POLICY`` if set, else the built-in default), so a bundle
        verify rejects under the receiver's policy is never reproduced here. A policy that cannot be read is a
        refusal (``error``), never a pass. A set ``$PROOF_POLICY`` overrides ``proof_verify.pin_key()``, exactly as
        ``proof-verify`` without ``--pubkey``: the policy's pins (plus the built-in demo pins) are the trust roots, so
        a key set with ``pin_key`` counts only if the policy pins it.

        The bundle's integrity is always checked before anything is re-run, and a bundle that fails is not
        re-derived. Every report, refusals included, carries the same keys (``error`` is None unless refused).

        ``bundle`` should be the bundle's bytes/str (parsed ONCE with the verifier's hardened loader). A dict cannot
        be verified (SPEC 4), so it is refused, unless ``verify_first=False``: then it is re-serialized for the
        kernel, which checks its integrity anyway. A dict must come from ``proof_verify.verify.loads``.
        """
        from proof_verify.gate import resolve_trust
        from proof_verify.verify import PolicyError

        from .certify import ReproduceError, reproduce_bundle
        from .envelope import bundle_bytes

        def report(error=None, expected=None, **fields):
            out = {"reproduced": False, "outcome_reproduced": False, "outputs_reproduced": False,
                   "expected_sha": expected, "got_sha": None, "verified": False, "integrity_ok": None,
                   "origin_ok": None, "inputs_identical": None, "environment_mismatch": {},
                   "environment_unverifiable": None, "claim_drift": {}, "reproduce_detail": None, "shortfalls": [],
                   "not_checked": [], "gate": None, "error": error}
            out.update(fields)
            return out

        if policy is None and pins is None:
            try:
                trust = resolve_trust()                 # PROOF_POLICY discovery, exactly as proof-verify with no flags
            except PolicyError as exc:
                return report(f"receiver policy refused: {exc}")
            policy, pins = trust.policy, trust.pins
        raw = bundle
        if not isinstance(bundle, dict):
            try:
                bundle = _load(bundle)
            except (ValueError, TypeError, RecursionError, MemoryError) as exc:
                return report(f"not a valid bundle ({exc.__class__.__name__})")
        elif verify_first:
            # the verdict is on the bytes as received (SPEC 4); a dict cannot be verified, so it is refused here
            return report("bundle failed integrity verification; not re-deriving (a parsed dict cannot be "
                          "verified: pass the bundle's bytes)")
        else:
            raw = bundle_bytes(bundle)
        expected = self.sealed_outcome_sha(bundle)
        if expected is None:
            return report(f"no {self.outcome_key!r} under capability {self.capability!r} "
                          "(foreign or incompatible bundle)")
        runner = _AdapterRunner(self, run, bundle)
        try:
            rep = reproduce_bundle(raw, runner, policy=policy, pins=pins, as_of=as_of)
        except ReproduceError as exc:                   # SPEC v4 draft 10.6 and the other named gaps: never a re-run
            return report(str(exc), expected)
        except PolicyError as exc:
            return report(f"receiver policy refused: {exc}", expected)
        verify_part = {"verified": rep.get("verified") is True, "integrity_ok": rep.get("integrity_ok"),
                       "origin_ok": rep.get("origin_ok"), "gate": rep.get("gate")}
        if rep.get("unverified"):
            return report("bundle failed integrity verification; not re-deriving", expected, **verify_part)
        got = runner.got_sha
        out = report(None, expected, **verify_part, got_sha=got, outcome_reproduced=got == expected,
                     inputs_identical=rep.get("inputs_identical"),
                     environment_mismatch=rep.get("environment_mismatch") or {},
                     environment_unverifiable=rep.get("environment_unverifiable"),
                     claim_drift=rep.get("claim_drift") or {}, reproduce_detail=rep.get("reproduce_detail"),
                     shortfalls=list(rep.get("shortfalls") or []))
        sealed_core = bundle["manifest"]["result"]["value"]
        if not runner.full:
            sealed_out = _sealed_outputs(bundle, self.capability)
            # only the outcome digest was re-derived; everything else in the sealed result was taken on trust
            out["not_checked"] = ([f"result.outputs.{k}" for k in sorted(sealed_out) if k != self.outcome_key]
                                  + ["result.verdict", "result.fidelity", "result.caveats"])
            return out
        # the kernel's verdict, one rule with proof-reproduce and certify
        out["outputs_reproduced"] = rep.get("result_rederived") is True
        out["reproduced"] = rep.get("reproduced") is True
        # a sealed caveat the re-run does not declare only narrows the claim, so the comparison allows it -- but
        # nothing re-derived it: say so
        fresh_cavs = set(runner.fresh_caveats)
        out["not_checked"] = [f"result.caveats: {c}" for c in (sealed_core.get("caveats") or [])
                              if isinstance(c, str) and c not in fresh_cavs]
        return out


class _AdapterRunner:
    """The ``ReproduceRunner`` ``Adapter.reproduce`` hands the kernel: it calls the caller's ``run(inputs)`` and mints
    the fresh bundle exactly as ``Adapter.seal`` would. A ``Rerun`` re-derives the whole result; a bare outcome
    re-derives only its digest, so the other sealed outputs and the claim fields are copied from the sealed bundle and
    the comparison is outputs-only (``outputs_only``, as ``proof-reproduce --command``)."""

    def __init__(self, adapter, run, bundle):
        self.adapter, self._run, self._bundle = adapter, run, bundle
        self.outputs_only = False
        self.full = False
        self.got_sha = None
        self.fresh_caveats: tuple = ()

    def can_run(self, capability):
        return capability == self.adapter.capability

    def run(self, capability, inputs):
        from .certify import subject_canon
        a = self.adapter
        r = self._run(inputs)
        core = self._bundle["manifest"]["result"]["value"]
        if isinstance(r, Rerun):
            self.full = True
            # the environment is the one the re-run DECLARES; undeclared, it is marked not captured (the kernel then
            # reports environment_unverifiable), never copied from the sealed bundle
            prov = dict(r.provenance or {})
            if r.data_library is None:
                prov["environment_captured"] = False
            result, d = a._result(r.outcome, verdict=r.verdict, outputs=r.outputs, extra_outputs=r.extra_outputs,
                                  fidelity=r.fidelity, caveats=r.caveats, provenance=prov)
            self.fresh_caveats = tuple(result.caveats)
            data_library = r.data_library
        else:
            # the outcome alone: re-derive its digest; copy every other sealed output and the claim from the bundle
            self.outputs_only = True
            d = a.digest(r)
            out = dict(_sealed_outputs(self._bundle, a.capability))
            out[a.outcome_key] = d
            result = Result(capability=a.capability, fidelity=Fidelity(core["fidelity"]),
                            verdict=Verdict(core["verdict"]), outputs=out, caveats=tuple(core.get("caveats") or ()),
                            provenance={"environment_captured": False})
            data_library = None
        self.got_sha = d
        return build_bundle(Case(capability=a.capability, inputs=inputs), result, engine=a.engine,
                            engine_version=a.engine_version, data_library=data_library,
                            canon_version=subject_canon(self._bundle)[0])


def _sealed_outputs(bundle, capability) -> dict:
    try:
        out = bundle["manifest"]["result"]["value"]["result"].get(capability, {})
    except (KeyError, TypeError, AttributeError):
        return {}
    return out if isinstance(out, dict) else {}


def _load(bundle_or_bytes):
    """A dict passes through; bytes/str are parsed with the verifier's own hardened loader (duplicate keys, NaN,
    depth, size, digit limit), never a plain json.loads, so the text a person reads is the text that is checked."""
    if isinstance(bundle_or_bytes, dict):
        return bundle_or_bytes
    from proof_verify.verify import loads
    text = bundle_or_bytes.decode("utf-8") if isinstance(bundle_or_bytes, (bytes, bytearray)) else bundle_or_bytes
    return loads(text)


__all__ = ["Adapter", "Fidelity", "Rerun", "Verdict"]
