"""Enumerate legal unit-action moves from the current public observation."""

from itertools import combinations

Move = tuple[str, ...]


def legal_moves(pending: Move, eligible: Move, capacity: int) -> tuple[Move, ...]:
    """Include explicit wait and never choose ineligible or completed actions."""
    available = tuple(sorted(set(pending).intersection(eligible)))
    return tuple(
        move
        for count in range(min(capacity, len(available)), -1, -1)
        for move in combinations(available, count)
    )


def remaining_after(pending: Move, sent: Move) -> Move:
    """Subtract the sent subset, preserving canonical action order."""
    return tuple(action for action in pending if action not in sent)
