"""``@sealed`` -- turn a pure Python function into a one-call sealer AND its own reproduce runner.

Writing a ReproduceRunner by hand is two methods of boilerplate (``can_run`` / ``run``) that just re-run
the producer. For a pure function -- deterministic in its inputs, returning a dict of outputs -- that
boilerplate is mechanical, so ``@sealed`` derives it:

    from proof_core import sealed

    @sealed(capability="arith:add", engine="demo-adapter", engine_version="1.0.0")
    def add(inputs):
        return {"total": inputs["a"] + inputs["b"]}

    bundle = add({"a": 2, "b": 3})          # CALL -> a sealed, signed evidence bundle

The decorated object is BOTH the sealer (call it with the inputs dict to get a bundle) AND a
``proof_core.contract.ReproduceRunner`` (it carries ``can_run`` / ``run``), so

    proof-reproduce bundle.json --runner your.module:add

needs no hand-written adapter -- the reviewer still NAMES the runner on the command line (the security
line is unchanged; the decorator only removes the boilerplate). ``reproduce_bundle(bundle_bytes(bundle), add)`` works
the same way in code.

SCOPE: ``@sealed`` is for a DETERMINISTIC pure function -- a single ``inputs`` dict in, a dict of outputs
out, same inputs -> same outputs, compared on an EXACT result-core match. The inputs are deep-copied
before the call, so the sealed case is exactly what the caller supplied and a function that mutates its
argument cannot change the sealed inputs or the caller's dict. A STOCHASTIC producer is OUT OF SCOPE: it
must record the ``rng_seed`` it actually drew (so a re-run compares within a committed statistical band),
which this decorator has no way to capture -- seal those with ``build_bundle`` directly, setting
``Result.provenance['rng_seed']`` and a ``stat`` ``reproduce_tolerance`` (see
``examples/eval_result.py``)."""
from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from .certify import ReproduceError
from .contract import Case, Fidelity, Result, Verdict
from .envelope import build_bundle


class SealedFunction:
    """A pure function wrapped so calling it SEALS (inputs + output -> signed bundle) and so it doubles as
    its own ReproduceRunner. Constructed by the ``sealed`` decorator; not usually built directly."""

    def __init__(self, fn: Callable[[dict], dict], *, capability: str, engine: str, engine_version: str,
                 fidelity: Fidelity, verdict: Verdict, caveats: tuple[str, ...],
                 data_library: tuple[str, str] | None, profile=None, canon_version: int = 3):
        self._fn = fn
        #: the envelope it mints: 3 = evidence.envelope.v4 (the default, as build_bundle), 1 = the v3 envelope
        self.canon_version = canon_version
        self.capability = capability
        self.engine = engine
        self.engine_version = engine_version
        self.fidelity = fidelity
        self.verdict = verdict
        self.caveats = tuple(caveats)
        self.data_library = data_library
        # the on-disk DIALECT this function seals (and re-derives) under. None -> the neutral dialect, so a
        # @sealed function is byte-identical to today unless a branded consumer passes its own Profile.
        self.profile = profile
        # look like the wrapped function to introspection, without functools.update_wrapper surprises.
        self.__name__ = getattr(fn, "__name__", "sealed")
        self.__qualname__ = getattr(fn, "__qualname__", self.__name__)
        self.__doc__ = fn.__doc__
        self.__wrapped__ = fn

    def seal(self, inputs: dict) -> dict:
        """Run the wrapped function on ``inputs`` and return a sealed, signed evidence bundle.

        ``inputs`` is deep-copied first, so the caller's dict is never mutated and the sealed case is
        exactly what was supplied -- a function that mutates its argument cannot inject keys into the
        sealed ``inputs`` section (the function runs against its own private copy)."""
        supplied = copy.deepcopy(inputs)
        outputs = self._fn(copy.deepcopy(supplied))
        if not isinstance(outputs, dict):
            raise TypeError(
                f"@sealed function {self.__name__!r} must return a dict of outputs, got "
                f"{type(outputs).__name__}")
        case = Case(capability=self.capability, inputs=supplied)
        result = Result(capability=self.capability, fidelity=self.fidelity, verdict=self.verdict,
                        outputs=outputs, caveats=self.caveats)
        return build_bundle(case, result, engine=self.engine, engine_version=self.engine_version,
                            data_library=self.data_library, profile=self.profile,
                            canon_version=self.canon_version)

    def __call__(self, inputs: dict) -> dict:
        return self.seal(inputs)

    # --- ReproduceRunner (derived automatically; the reviewer still names it on the CLI) ---
    def can_run(self, capability: str) -> bool:
        return capability == self.capability

    def run(self, capability: str, inputs: dict) -> dict:
        if capability != self.capability:
            raise ReproduceError(
                f"@sealed function {self.__name__!r} seals {self.capability!r}, not {capability!r}")
        return self.seal(inputs)


def sealed(*, capability: str, engine: str, engine_version: str,
           fidelity: Fidelity = Fidelity.SCREENING, verdict: Verdict = Verdict.PASS,
           caveats: tuple[str, ...] = (),
           data_library: tuple[str, str] | None = None,
           profile=None, canon_version: int = 3) -> Callable[[Callable[[dict], Any]], SealedFunction]:
    """Decorator: wrap a pure, DETERMINISTIC ``inputs -> outputs`` function as a ``SealedFunction`` (see the
    module docstring). ``capability``, ``engine`` and ``engine_version`` are required; the rest default to a
    screening/pass leaf with no caveats. Reproduction is an EXACT result-core match; a stochastic producer
    (which must record its ``rng_seed``) is out of scope -- seal it with ``build_bundle`` directly.

    ``profile`` (optional) is the on-disk DIALECT this function seals and re-derives under; a branded
    consumer passes its own ``proof_core.profile.Profile``. ``None`` is the neutral dialect, byte-unchanged.

    ``canon_version`` selects the envelope, as ``build_bundle``: 3 (the default) mints ``evidence.envelope.v4``;
    1 mints the frozen ``evidence.envelope.v3``."""
    def deco(fn: Callable[[dict], Any]) -> SealedFunction:
        return SealedFunction(fn, capability=capability, engine=engine, engine_version=engine_version,
                              fidelity=fidelity, verdict=verdict, caveats=tuple(caveats),
                              data_library=data_library, profile=profile, canon_version=canon_version)
    return deco
