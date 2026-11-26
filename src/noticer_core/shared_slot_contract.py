"""Finite public scheduling inputs; no biosignals or private readiness."""

from dataclasses import dataclass

MAX_SLOTS = 64
MAX_ACTIONS = 48
MAX_TOTAL_CAPACITY = 128


@dataclass(frozen=True)
class SharedAction:
    """A unit action and the public slots in which its receiver can accept it."""

    name: str
    deadline: int
    slots: tuple[int, ...]


@dataclass(frozen=True)
class SharedSlotCase:
    """One public tape; capacity is shared by all actions at each slot."""

    capacities: tuple[int, ...]
    actions: tuple[SharedAction, ...]

    def __post_init__(self) -> None:
        if type(self.capacities) is not tuple or not 0 < len(self.capacities) <= MAX_SLOTS:
            raise ValueError("invalid slot horizon")
        if any(type(cap) is not int or cap < 0 for cap in self.capacities):
            raise ValueError("capacities must be nonnegative integers")
        if sum(self.capacities) > MAX_TOTAL_CAPACITY:
            raise ValueError("total capacity exceeds model bound")
        if type(self.actions) is not tuple or len(self.actions) > MAX_ACTIONS:
            raise ValueError("invalid action count")
        names: set[str] = set()
        for action in self.actions:
            if type(action) is not SharedAction:
                raise ValueError("invalid action")
            name = action.name
            if (
                type(name) is not str
                or not 1 <= len(name) <= 64
                or not name.isascii()
                or not all(char.isalnum() or char in "_-" for char in name)
                or name in names
            ):
                raise ValueError("invalid or duplicate action name")
            names.add(name)
            if type(action.deadline) is not int or not 0 <= action.deadline < len(self.capacities):
                raise ValueError("deadline out of horizon")
            if type(action.slots) is not tuple or any(
                type(slot) is not int or not 0 <= slot <= action.deadline
                for slot in action.slots
            ):
                raise ValueError("invalid eligible slot")
            if action.slots != tuple(sorted(set(action.slots))):
                raise ValueError("eligible slots must be sorted and unique")
