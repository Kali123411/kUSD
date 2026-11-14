# Vendored KCC-20 reference — provenance

- Source: https://github.com/argent-lang/kcc20-reference, license ISC (`publish = false` reference crate).
- Files: `kcc20.ag` (the reference KCC20 actor: KCC-2 owner schemes 0x00–0x04, borrow
  schemes 0x00–0x03, witness-blob transfer ABI) and `fixtures/kcc20/conformance.json`
  (machine-readable conformance vectors: state record/encoding, dispatch, transfer
  argument encoding, owner/borrow witness layouts, hash-chain vectors, borrowed-receive
  cases).
- Copied: 2026-11-11.
- sha256:
  - `kcc20.ag` `f6131d97368461e74b02507d5ef2d7af57c76226cf945ebbbe9735f0953414e9`
  - `conformance.json` `9b424c96ea0e0093cacfd98e3013fd5cbf93dd149cb27696acf288510133010b`
- Compiler compatibility: the source repo pins argent rev `9a9f4b10…` which is an
  ancestor of our pinned checkout (`0cf5b30`, previously `dc7637e`); the vendored contract compiles clean
  under our `argentc` (verified 2026-11-11).
- Role in this repo: `kcc20.ag` is the SEMANTIC SOURCE for kusd.ag's transfer rework
  (Phase 4 Task 2) — kUSD does not build or execute this file in production; the
  conformance suite (`harness/tests/kcc20_conformance.rs`) drives `conformance.json`
  against kUSD's own compiled contract.
