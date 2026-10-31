# proof-core plugin

A Claude Code plugin shipping an Agent Skill that seals a computed result into a tamper-evident, independently re-runnable evidence bundle, then verifies or reproduces one. It wraps the open-source [proof-core](https://gitlab.com/proof-core/proof-core) kernel (MIT), **vendored into this plugin** (`bin/`) at version 0.19.0, so it runs with no install.

It is **local-only**: pure Python 3.11+ standard library, no third-party dependencies, **no network calls, and no account**. Everything happens on the machine running the agent.

## What it does

Three verbs, all run from the vendored copy via `python -m proof_core`:

- **seal** a result (its inputs + outputs) into a signed, canonical JSON bundle.
- **verify** a bundle offline (hashes recompute; signature checks) — a standalone second implementation (`proof_verify`) that imports no producer code.
- **reproduce** a bundle by re-running the work on its sealed inputs and confirming the result re-derives.

## Honest boundary

A seal proves the record is **unaltered** and that it **re-derives** from its sealed inputs. It does **not** prove the result is correct, nor that the agent actually ran what it claims. Catching that needs independent reproduction by a party the producer does not control. The public build pins a **demo** key, so verify returns "integrity-only" (exit 3) — that is the normal result and is **not** a production origin pass.

## Install (self-serve, any git host)

```
claude plugin marketplace add https://gitlab.com/proof-core/skill
claude plugin install proof-core@proof-core-marketplace
```

proof-core is not on PyPI by design; this plugin carries the source so nothing is fetched at runtime.

## Re-vendoring

The `bin/` tree is a verbatim copy of proof-core's `proof_core/` and `proof_verify/` packages and is never edited here. See [VENDORED.md](VENDORED.md).
