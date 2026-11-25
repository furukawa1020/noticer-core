"""Check that every declared public input sees an explicit evaluation outcome."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from noticer_core.recovery_input_contract import TapeClass, classify_two_slot_tape


@dataclass(frozen=True, slots=True)
class PublicCoverage:
    eligible: tuple[str, ...]
    outside: tuple[str, ...]
    missing_eligible: tuple[str, ...]


def separate_tape_coverage(
    declared: Mapping[str, tuple[bool, ...]], evaluated: Sequence[str]
) -> PublicCoverage:
    if not declared or "" in declared or len(set(evaluated)) != len(evaluated):
        raise ValueError("named public tapes and distinct evaluation entries are required")
    if not set(evaluated) <= declared.keys():
        raise ValueError("evaluated tape is not declared")
    eligible, outside = [], []
    for name, tape in sorted(declared.items()):
        if classify_two_slot_tape(tape).classification is TapeClass.OUT_OF_SCOPE:
            outside.append(name)
        else:
            eligible.append(name)
    return PublicCoverage(
        tuple(eligible), tuple(outside), tuple(name for name in eligible if name not in evaluated)
    )
