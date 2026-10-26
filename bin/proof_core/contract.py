"""The one contract everything hangs off: a `Case` (inputs) and the `Result` (outputs) a producer seals,
plus the `ReproduceRunner` seam a consumer injects so the domain-agnostic core can re-derive without
importing any domain engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Fidelity(str, Enum):
    SCREENING = "screening"
    REFERENCE = "reference"


class Verdict(str, Enum):
    PASS = "pass"
    ADVISORY = "advisory"
    FAIL = "fail"


@dataclass(frozen=True)
class Case:
    """The input to any capability. Its (capability, inputs) pair is its deterministic identity."""
    capability: str
    inputs: dict[str, Any]


@dataclass(frozen=True)
class Result:
    """The output. `fidelity` and `verdict` are REQUIRED and stamped by construction --
    honesty is structural (ADR-036: fidelity is never dropped, verdict drives exit code)."""
    capability: str
    fidelity: Fidelity
    verdict: Verdict
    outputs: dict[str, Any]
    caveats: tuple[str, ...] = ()
    # run-scoped reproducibility facts (e.g. a data-snapshot or reference-library digest), OS-INDEPENDENT
    # so they can be folded into the signed manifest without making the bundle hash platform-dependent.
    provenance: dict[str, Any] = field(default_factory=dict)
    # How a reviewer's re-run is compared. None -> exact result-core match (the default for a
    # deterministic producer). A stochastic producer (a sampling-based simulation, a sampled model)
    # declares a tolerance here so `reproduce` accepts a re-run that agrees within statistical
    # uncertainty rather than bit-for-bit; it rides in the SIGNED core, so the tolerance a reviewer is
    # held to is part of the record.
    reproduce_tolerance: dict[str, Any] | None = None


@runtime_checkable
class ReproduceRunner(Protocol):
    """The consumer-injected bridge that lets `certify.reproduce_bundle` re-derive a bundle WITHOUT the
    domain-agnostic core importing any domain engine. This is the reproduce-harness seam: a domain adapter
    (an analytics pipeline's scorer, a modeling engine's capability registry, an AI-output replayer, ...)
    implements it. `can_run` says
    whether the named capability is available to re-execute in this process; `run` re-executes it on the
    bundle's own sealed inputs and returns the freshly minted bundle dict for the core to compare against
    the sealed one. The core never knows what the capability computes -- only that it re-derives (or not)."""
    def can_run(self, capability: str) -> bool: ...
    def run(self, capability: str, inputs: dict[str, Any]) -> dict[str, Any]: ...
