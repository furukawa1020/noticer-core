# Generated artifacts

Generated experiment outputs are intentionally excluded from version control.

K3 writes to `artifacts/k3_token_v2/`. See
`docs/k3_reproducibility.md` for the file contract and reproduction commands.

Experiment outputs and datasets are not committed. Regenerate the smoke artifact with:

```bash
python -m noticer_core.cli attack identity --config configs/attacks/identity_smoke.yaml
```
