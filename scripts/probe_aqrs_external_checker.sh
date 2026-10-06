#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/formal/aqrs/external_checker_lock.json"
WORK="${RUNNER_TEMP:-$(mktemp -d)}/aqrs-external-checker"
RESULT="$WORK/result"
rm -rf "$WORK"
mkdir -p "$RESULT"

mapfile -t pins < <(python - "$LOCK" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value["exporter"]["repository"])
print(value["exporter"]["revision"])
print(value["checker"]["repository"])
print(value["checker"]["revision"])
PY
)
exporter_repo="${pins[0]}"
exporter_revision="${pins[1]}"
checker_repo="${pins[2]}"
checker_revision="${pins[3]}"

checkout_pinned() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  git init -q "$destination"
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch -q --depth 1 origin "$revision"
  git -C "$destination" checkout -q --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
}

checkout_pinned "$exporter_repo" "$exporter_revision" "$WORK/lean4export"
checkout_pinned "$checker_repo" "$checker_revision" "$WORK/nanoda"
cp "$ROOT/formal/aqrs/lean-toolchain" "$WORK/lean4export/lean-toolchain"

(
  cd "$WORK/lean4export"
  lake build lean4export
)
(
  cd "$WORK/nanoda"
  cargo build --release --locked
)

exporter="$WORK/lean4export/.lake/build/bin/lean4export"
(
  cd "$ROOT/formal/aqrs"
  lake build
  lake env "$exporter" Aqrs > "$RESULT/aqrs.ndjson"
)
python "$ROOT/scripts/run_pinned_external_checker.py" \
  --lock "$LOCK" \
  --checker-checkout "$WORK/nanoda" \
  --export "$RESULT/aqrs.ndjson" \
  --artifact "$RESULT/aqrs-valid.json"

(
  cd "$ROOT/tests/fixtures/aqrs_external_checker_bad"
  lake build
  lake env "$exporter" Bad > "$RESULT/aqrs-bad-axiom.ndjson"
)
if python "$ROOT/scripts/run_pinned_external_checker.py" \
  --lock "$LOCK" \
  --checker-checkout "$WORK/nanoda" \
  --export "$RESULT/aqrs-bad-axiom.ndjson" \
  --artifact "$RESULT/unexpected-bad-axiom-accept.json"; then
  echo "external checker accepted the forbidden-axiom fixture" >&2
  exit 1
fi

printf '{"not":"complete"}\n' > "$RESULT/malformed.ndjson"
if python "$ROOT/scripts/run_pinned_external_checker.py" \
  --lock "$LOCK" \
  --checker-checkout "$WORK/nanoda" \
  --export "$RESULT/malformed.ndjson" \
  --artifact "$RESULT/unexpected-malformed-accept.json"; then
  echo "external checker accepted malformed NDJSON" >&2
  exit 1
fi

python - "$LOCK" "$RESULT/aqrs-valid.json" "$RESULT/probe-summary.json" <<'PY'
import hashlib
import json
import sys

lock_path, valid_path, output_path = sys.argv[1:]
lock = json.load(open(lock_path, encoding="utf-8"))
valid = json.load(open(valid_path, encoding="utf-8"))
summary = {
    "schema_version": "noticer.aqrs.external_checker_probe.v1",
    "status": "PASS",
    "lean_toolchain": lock["lean_toolchain"],
    "exporter_revision": lock["exporter"]["revision"],
    "checker_revision": lock["checker"]["revision"],
    "valid_export_sha256": valid["export_sha256"],
    "valid_export": "ACCEPTED",
    "forbidden_axiom_fixture": "REJECTED",
    "malformed_export": "REJECTED",
    "verification_scope": "SOFTWARE_COMPATIBILITY_PROBE",
}
payload = json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
summary["summary_digest"] = hashlib.sha256(payload.encode()).hexdigest()
open(output_path, "w", encoding="utf-8").write(
    json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
)
print(json.dumps(summary, indent=2, sort_keys=True))
PY

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### AQRS external checker compatibility probe"
    echo '```json'
    cat "$RESULT/probe-summary.json"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi
