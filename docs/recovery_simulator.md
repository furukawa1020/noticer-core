# Deterministic Recovery Simulator

The simulator generates a bounded seeded sequence of crash/restart, key rotation, backlog, and ceremony progression events. Restart preserves the sealed phase, rotation starts a new ceremony epoch, and admission pressure prevents unsafe progression. A deterministic oracle rejects unsafe terminal or transition states with typed reasons, while canonical JSON makes every campaign byte-replayable.
