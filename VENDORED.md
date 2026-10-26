# Vendored source

`bin/proof_core/` and `bin/proof_verify/` are a **verbatim copy** of the two
packages from the open proof-core repository. They are NEVER edited in this
plugin — fixes go upstream, then re-vendor.

- **Upstream:** https://gitlab.com/proof-core/proof-core (MIT)
- **Version:** 0.16.0
- **main commit:** 67ea93c
- **Vendored:** 2026-10-26

## Why vendored

proof-core is intentionally not on PyPI (air-gap-native distribution), and
Claude plugins may not run a package install at load time. Carrying the source
keeps the plugin self-contained: it imports from `bin/` via
`PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin"` and needs no install and no network.

## Re-vendor procedure

```
# from a proof-core checkout at the target version:
rm -rf bin/proof_core bin/proof_verify
cp -r <proof-core>/proof_core  bin/proof_core
cp -r <proof-core>/proof_verify bin/proof_verify
find bin -name __pycache__ -type d -prune -exec rm -rf {} + ; find bin -name '*.pyc' -delete
# then bump the Version/commit/date above and the version note in README/plugin.json.
```

The vendored packages are pure Python standard library (no third-party runtime
dependencies), so no lockfile or wheel is needed.
