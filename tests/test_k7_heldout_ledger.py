from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from noticer_core.evaluation.heldout_ledger import (
    BINDING_FIELDS,
    NAMESPACE_FIELDS,
    POLICY_FIELDS,
    PRECOMMIT_FIELDS,
    RECEIPT_FIELDS,
    RESULT_FIELDS,
    HeldOutLedgerError,
    LedgerState,
    append_receipt,
    load_precommit,
    load_receipts,
    open_held_out,
    receipt_sha256,
    seal_precommit,
    serialize_receipt,
    validate_receipt_chain,
)

ROOT = Path(__file__).resolve().parents[1]
PRECOMMIT = ROOT / "configs" / "quotient_forge" / "heldout_precommit_v1.yaml"
PRECOMMIT_SCHEMA = ROOT / "schemas" / "k7_heldout_precommit_v1.schema.json"
RECEIPT_SCHEMA = ROOT / "schemas" / "k7_heldout_receipt_v1.schema.json"
PUBLIC_RESULT = b'{"schema":"noticer.k7.discovery-result.v1","summary":{"cases":8}}\n'


def test_precommit_binds_frozen_corpus_split_bounds_and_backend() -> None:
    precommit = load_precommit(PRECOMMIT, repository_root=ROOT)
    assert precommit.revision == 1
    assert len(precommit.held_out_families) == 8
    assert len(precommit.backend_components) == 5
    assert precommit.artifact_namespaces.development != precommit.artifact_namespaces.held_out
    assert precommit.policies.append_only is True
    assert precommit.policies.bounds_mutable_after_precommit is False


def test_runtime_and_json_schemas_share_exact_allowlists() -> None:
    precommit = json.loads(PRECOMMIT_SCHEMA.read_text(encoding="utf-8"))
    receipt = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
    assert set(precommit["properties"]) == PRECOMMIT_FIELDS
    assert set(precommit["properties"]["bindings"]["properties"]) == BINDING_FIELDS
    assert set(precommit["properties"]["artifact_namespaces"]["properties"]) == NAMESPACE_FIELDS
    assert set(precommit["properties"]["policies"]["properties"]) == POLICY_FIELDS
    assert set(receipt["properties"]) == RECEIPT_FIELDS
    result = receipt["properties"]["result"]["oneOf"][1]
    assert set(result["properties"]) == RESULT_FIELDS


def test_stale_binding_and_postcommit_bound_change_are_rejected(tmp_path: Path) -> None:
    document = yaml.safe_load(PRECOMMIT.read_text(encoding="utf-8"))
    stale = deepcopy(document)
    stale["bindings"]["backend_sha256"] = "0" * 64
    stale_path = tmp_path / "stale.yaml"
    stale_path.write_text(yaml.safe_dump(stale, sort_keys=False), encoding="utf-8")
    with pytest.raises(HeldOutLedgerError, match="binding is stale"):
        load_precommit(stale_path, repository_root=ROOT)

    retuned = deepcopy(document)
    retuned["policies"]["bounds_mutable_after_precommit"] = True
    retuned_path = tmp_path / "retuned.yaml"
    retuned_path.write_text(yaml.safe_dump(retuned, sort_keys=False), encoding="utf-8")
    with pytest.raises(HeldOutLedgerError, match="policies differ"):
        load_precommit(retuned_path, repository_root=ROOT)


def test_receipts_form_one_irreversible_append_only_chain(tmp_path: Path) -> None:
    precommit = load_precommit(PRECOMMIT, repository_root=ROOT)
    sealed = seal_precommit(precommit)
    opened = open_held_out(
        precommit,
        sealed,
        PUBLIC_RESULT,
        result_format="noticer.k7.discovery-result.v1",
    )
    assert sealed.from_state is LedgerState.PRECOMMITTED
    assert sealed.to_state is LedgerState.SEALED
    assert opened.from_state is LedgerState.SEALED
    assert opened.to_state is LedgerState.OPENED
    assert opened.previous_receipt_sha256 == receipt_sha256(sealed)
    assert opened.result is not None
    assert opened.result.sha256 not in serialize_receipt(sealed).decode("ascii")

    ledger = tmp_path / "opening.jsonl"
    append_receipt(ledger, precommit, sealed)
    append_receipt(ledger, precommit, sealed)
    append_receipt(ledger, precommit, opened)
    assert load_receipts(ledger, precommit=precommit) == (sealed, opened)
    original = ledger.read_bytes()

    with pytest.raises(HeldOutLedgerError, match="conflicting receipt"):
        stale_seal = replace(
            sealed,
            bindings=replace(sealed.bindings, corpus_sha256="0" * 64),
        )
        append_receipt(ledger, precommit, stale_seal)
    with pytest.raises(HeldOutLedgerError, match="conflicting receipt"):
        append_receipt(ledger, precommit, replace(opened, result=None))
    assert ledger.read_bytes() == original


def test_reseal_revert_and_stale_receipts_fail_closed() -> None:
    precommit = load_precommit(PRECOMMIT, repository_root=ROOT)
    sealed = seal_precommit(precommit)
    opened = open_held_out(
        precommit,
        sealed,
        PUBLIC_RESULT,
        result_format="noticer.k7.discovery-result.v1",
    )
    with pytest.raises(HeldOutLedgerError, match="at most one opening"):
        validate_receipt_chain(precommit, (sealed, opened, sealed))
    stale = replace(opened, ledger_revision=2)
    with pytest.raises(HeldOutLedgerError, match="revision is stale"):
        validate_receipt_chain(precommit, (sealed, stale))


def test_receipt_excludes_host_identity_paths_and_private_payload() -> None:
    precommit = load_precommit(PRECOMMIT, repository_root=ROOT)
    sealed = seal_precommit(precommit)
    private_result = b'{"participant_id":"p01","score":1}\n'
    with pytest.raises(HeldOutLedgerError, match="forbidden field"):
        open_held_out(
            precommit,
            sealed,
            private_result,
            result_format="noticer.k7.discovery-result.v1",
        )
    opened = open_held_out(
        precommit,
        sealed,
        PUBLIC_RESULT,
        result_format="noticer.k7.discovery-result.v1",
    )
    payload = serialize_receipt(opened).decode("ascii").lower()
    assert "c:\\" not in payload
    assert "/home/" not in payload
    assert "username" not in payload
    assert "participant_id" not in payload
    assert PUBLIC_RESULT.decode("ascii").strip() not in payload
