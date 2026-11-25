# Bounded synthetic recovery table

This artifact generates the recovery/cost table, not all paper figures.
It reads no participant data and opens no network connections.

From the repository root on POSIX:

```sh
PYTHONPATH=src python tools/run_popets_recovery_matrix.py artifacts/popets-recovery-example
```

On PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python tools/run_popets_recovery_matrix.py artifacts/popets-recovery-example
```

Container recipe from the repository root (use a fresh output directory):

```sh
docker build -f replication/popets_recovery/Dockerfile -t popets-recovery . &&
docker run --rm -v "$PWD/artifacts/recovery-container:/output" popets-recovery
```

The host used to develop this version had the Docker CLI but no available
daemon. The native Python command was executed; the Docker recipe was not.
Pin and record the resolved base image digest before packaging the artifact.

Outputs: recovery-matrix.json and recovery-matrix.csv. Exact enumeration
produces 64 admitted-action/readiness cases per mechanism and 64 obligations
across them. The runner refuses to replace a prior result.
These files do not certify the implementation or a real protocol.

To render the two observer scopes separately:

```sh
python tools/plot_popets_recovery_matrix.py \
  artifacts/popets-recovery-example/recovery-matrix.json \
  artifacts/popets-recovery-example/recovery-cost.svg
```
