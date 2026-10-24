# Atomic Compaction File Store

Compaction images are immutable generation files. A keyed manifest binds the generation, checkpoint authenticator, and complete image bytes. Staging syncs an inactive image and manifest; activation replaces only the active manifest. Therefore a crash before activation retains the old generation, while a crash after activation restores the new generation. Orphan staging files are discarded during recovery and active-image substitution fails closed.
