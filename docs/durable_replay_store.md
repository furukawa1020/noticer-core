# Durable ATv2 replay state

FileReplayStore is a single-writer, single-epoch implementation of the existing
ReplayStore interface. It appends each consumed token ID and calls sync_data
before returning authorization. A duplicate, wrong epoch, write or sync error,
poisoned lock, or capacity exhaustion returns false.

The file has a fixed header and fixed-size records with redundant complement
bytes to detect incomplete writes. Reopening rejects an incomplete header,
partial record, altered record, duplicate record, or wrong epoch. It never
truncates, reseals, silently repairs, or falls back to memory.

A sibling .lock file prevents concurrent writers. A crash can leave this lock
behind. An operator must establish that the old process is stopped and inspect
the ledger before removing it; the API will not remove a stale lock. Each epoch
needs its own ledger file. The ledger and lock belong in trusted, access
controlled storage and must not be published as evaluation artifacts.

This is software durability, not adversarial disk tamper protection or
hardware-backed secure storage. Power-loss behavior on target hardware and
physical Menfugu deployment remain NOT_VERIFIED.
