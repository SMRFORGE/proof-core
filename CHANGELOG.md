# Changelog

All notable changes to the proof-core Claude Code plugin. Versions follow [Semantic Versioning](https://semver.org/).
Each release re-vendors a proof-core release into `bin/` verbatim; the vendored code's own changes are listed in
[proof-core's CHANGELOG](https://gitlab.com/proof-core/proof-core/-/blob/main/CHANGELOG.md).

## [0.8.2] - 2026-11-07

### Changed

- SKILL.md and README: the `reproduce` exit-0 wording no longer reads as if a production key alone is enough.
  Exit 0 needs `--runner`, the verify gate passing (a real pinned production key), the sealed inputs and a
  pinned, matching data environment. A `--command` re-run never exits 0: it re-derives the outputs but not the
  sealed claims, so it exits 3 at best under a production key and 7 under the demo key. The README flow diagram,
  the reproduce bullet and the Limits section, and the SKILL.md exit table say so. No code or vendored-kernel
  change; the vendored proof-core is still v0.29.0.

## [0.8.1] - 2026-11-07

### Other changes

- The plugin icon (`.claude-plugin/icon.png`) is now the current proof-core mark, the same one proof-core.com
  uses (white blades around a blue hexagon on navy). No code or vendored-kernel change; the vendored proof-core
  is still v0.29.0.

## [0.8.0] - 2026-11-05

Re-vendors proof-core **v0.29.0** (tag `v0.29.0`, commit `3f21ff1e55d06b2f07339f395ec8ccb9fce0707e`; was v0.28.0,
`be8fa50`). proof-core 0.29.0 is a fail-closed release: `reproduce` decides acceptance through the same gate as
`verify`, `reproduced` is strict, and the Python API mints v4 by default.

### Breaking

- **`reproduce` exit 0 needs the verify gate to pass.** Exit 0 (`reproduced`) now needs three things: verify
  would exit 0 under the receiver's trust inputs (a real pinned production key, never the public demo key), the
  re-run used the sealed inputs, and the sealed data environment is pinned and matches. `reproduce` takes verify's
  trust inputs (`--pubkey`, `--policy`, `$PROOF_POLICY`, `--no-policy-discovery`, `--expect-policy`,
  `--allow-self-verify`, `--as-of`).
- **New `reproduce` exit 7 (`state: partial`).** The numbers re-derive, but the gate did not pass, other inputs
  were used, or the environment differs or was never pinned (`shortfalls`). **Under the public demo key a
  matching `--runner` re-run now exits 7, not 0**, and a matching `--command` re-run exits 7, not 3. Exit 7 is
  never a pass.
- **Other `reproduce` exit changes.** A bundle verify rejects with its integrity intact (a signed rejection, an
  invalid sign-off) now exits 1 instead of 0 / 3. An unsupported canon or signature suite now exits 4 / 6 instead
  of 1. A malformed, unreadable or unexpected receiver policy exits 2.
- **`reproduced` is strict in the Python API too.** `reproduce_bundle` / `certify_bundle` report `reproduced` by
  the exit-0 rule; the raw "numbers matched" comparison is `result_rederived`. `Adapter.reproduce` with a run that
  returns only the outcome gives `reproduced: False, outcome_reproduced: True`. A full reproduction returns
  `proof_core.Rerun(outcome, verdict, ..., data_library=(label, digest))`; without `data_library` the result is
  `environment_unverifiable` and never `reproduced`.
- **The Python API mints v4 by default.** `build_bundle`, `Adapter.seal` and `@sealed` mint `evidence.envelope.v4`;
  pass `canon_version=1` for v3. `attest_bundle` raises on a v4 bundle (use `add_signoff`). The `seal` CLI already
  minted v4 by default (since 0.7.0); `--envelope v3` is unchanged.
- **The vendored verifier fails closed on more inputs.** A withheld v4 result, an archive that does not bind its
  sign-offs' time tokens (under `require_archive`), a stale reproduction record in an `--upstream` chain walk, and
  the other cases in proof-core 0.29.0's Breaking list now reject. Verify's exit codes are unchanged.

### Changed

- `bin/proof_core` and `bin/proof_verify` are re-vendored verbatim from proof-core v0.29.0 (adds
  `bin/proof_verify/gate.py`). VENDORED.md, `plugin.json`, `marketplace.json`, SKILL.md (`wraps:`) and README
  record 0.29.0.
- SKILL.md: the `reproduce` section documents the trust inputs, the full exit-code table (0, 1, 2, 3, 4, 6, 7),
  that a demo-key re-run whose numbers match is exit 7 ("partial", never "reproduced"), and how the Python API
  reports `outcome_reproduced` versus `reproduced` and mints v4.
- README: the flow diagram and Limits section show exit 7; the family table lists proof-core v0.29.0 and plugin
  v0.8.0.

### Added (tests)

- `tools/check_behaviour.py`, run by the blocking `smoke` CI job against the vendored `bin/` with no install. It
  checks five things. The `seal` CLI mints v4 by default and v3 with `--envelope v3`. `reproduce --command` under
  the demo key exits 7 (`partial`, `reproduced: false`, `gate_not_passed`) when the numbers match, and 1 when they
  drift. `build_bundle` / `Adapter.seal` mint v4 by default and v3 with `canon_version=1`. `attest_bundle` refuses
  v4. `Adapter.reproduce` gives `outcome_reproduced` (never `reproduced`) for a bare outcome, and
  `environment_unverifiable` for a `Rerun` with no `data_library`. Run against the v0.28.0 vendored copy, it fails,
  as it should.

## [0.7.0] - 2026-11-04

Re-vendored proof-core v0.28.0; `seal` mints v4 by default (`--envelope v3|v4`).
