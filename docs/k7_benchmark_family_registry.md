# K7 benchmark family registry and split lock

K7-08a materializes the 24 family IDs preregistered by K7-00 without amending the frozen research contract. The committed registry is a public catalog, not benchmark result evidence.

## Locked invariants

- The split unit is `spec_family`; row-random split is rejected.
- Train, development, and held-out each contain exactly eight families.
- Noticer, generic, and negative each contain exactly eight families.
- Family IDs, split membership, and within-split order must exactly match `k7_research.yaml`.
- Catalog seed `42001` and split seed `42004` must match K7-00.
- Every generated variant inherits its family split. A caller-provided different split is reported as leakage.

Input row order is irrelevant because `split_ordinal` reconstructs the frozen split lists and registry rows are canonicalized by family ID before hashing. The resulting catalog and split hashes must equal the corresponding K7-00 public manifest hashes.

## Public boundary

The public family manifest contains only contract and registry hashes, aggregate counts, split policy, and `private_field_count: 0`. It does not contain family rows, variants, private histories, biosignals, stable identifiers, or result labels.

Generated manifests belong under `artifacts/` and are not committed. The writer is idempotent and refuses to overwrite a conflicting existing file.

```powershell
$env:PYTHONPATH = "src"
python tools/build_k7_benchmark_registry.py build `
  --registry configs/quotient_forge/benchmark_family_registry_v1.yaml `
  --contract configs/quotient_forge/k7_research.yaml `
  --output artifacts/k7/benchmark-family-manifest.json
```

This registry prevents split drift and variant leakage. It does not establish benchmark difficulty, expected status correctness, automatic discovery, or deployment privacy; those remain later K7-08 stages.
