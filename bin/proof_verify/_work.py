"""SPEC 10.7.4 TT-15, the work budget: a count of public-key operations over one whole verification.

"A verifier MUST count public-key operations over one whole verification: each seal signature verify, each
attestation signature verify, each token signature verify, and any operation a product layer adds (for example the
proof-mcp server signatures). Operations 1 to 2,048 are performed; the operation that would make the count 2,049
MUST NOT be performed, and from then on the verifier MUST stop performing public-key operations."

One `WorkBudget` is the count of one verification. `classify_bundle(..., work_budget=b)` charges the kernel's own
operations to ``b``; a product layer then passes the same ``b`` to `verify_signature(..., work_budget=b)` for each of
its own operations, so the 2,048 limit covers both. An operation is charged after the suite-row shape gates pass and
before any arithmetic runs; a refused one is not performed. Standard library only.
"""
from __future__ import annotations

import contextvars

#: TT-15: operations 1 to 2,048 are performed.
WORK_BUDGET_LIMIT = 2048


class WorkBudgetExceeded(Exception):
    """TT-15: the public-key operation that would make the count 2,049 was refused, and was not performed. Raised by
    `verify_signature(..., work_budget=...)` so that a product layer cannot mistake a refusal for a bad signature."""


class WorkBudget:
    """The count of public-key operations of one verification (TT-15).

    ``used`` is the number of operations performed so far, at most `WORK_BUDGET_LIMIT`. ``exhausted`` is True once an
    operation has been refused; from then on every operation is refused (TT-15: "from then on the verifier MUST stop
    performing public-key operations")."""

    __slots__ = ("exhausted", "used")
    limit = WORK_BUDGET_LIMIT

    def __init__(self) -> None:
        self.used = 0
        self.exhausted = False

    def charge(self) -> bool:
        """Count one operation before it runs. True: perform it. False: it would make the count exceed the limit, so
        it is not performed, and the budget is exhausted."""
        if self.exhausted or self.used >= WORK_BUDGET_LIMIT:
            self.exhausted = True
            return False
        self.used += 1
        return True

    def __repr__(self) -> str:
        return f"WorkBudget(used={self.used}, exhausted={self.exhausted})"


#: The budget of the verification in progress (set by `classify_bundle`), or None outside one: an operation run outside
#: any verification (a bare `verify_signature` call with no budget) is not counted.
CURRENT: contextvars.ContextVar[WorkBudget | None] = contextvars.ContextVar("proof_verify_work_budget", default=None)

#: The problem text of a refused operation (TT-15).
REFUSED = ("not performed: the work budget of 2,048 public-key operations for this verification is exhausted "
           "(SPEC 10.7.4 TT-15)")


def charge() -> bool:
    """Charge one operation to the budget in progress. True when there is none (nothing is counted)."""
    b = CURRENT.get()
    return True if b is None else b.charge()
