# K7 production backend integration

The production binding registry connects the reference, CEGIS, SMT, and QBF
workers to the K7 process-runner boundary. Loading is fail-closed: the registry
must contain exactly four identities, every binding must remain inside the
repository, fixture results must be disabled, and every command placeholder must
be resolved.

Before a 92-case run, the caller resolves the four installed executables with
ProductionBindingRegistry.command. The returned ProductionCommand supplies the
executable and argv accepted by the existing bounded process adapter. The caller
then creates one production run lock. Its digest binds the registry bytes, each
binding file, every executable binary, expanded argv, and environment identity.
Changing any binary or binding therefore changes the experiment identity.

Executable names containing fixture, helper, mock, or test are rejected before
process launch. Solver absence is still represented by the backend workers as
NOT_RUN; it is never replaced with fixture output. Generated locks and backend
results belong under artifacts/ and are not committed. This integration does not
claim deployment or hardware validation; hardware remains NOT_VERIFIED.
