export const gameScenes = Object.freeze({
  hedge: {
    title: "A safe first send exists",
    evidence: "Verified policy",
    decision: "Send B before seeing which receiver returns.",
    early: "3/3",
    hedge: "3/3",
    reference: "2/3",
    why: "The same public policy meets all deadlines in each of the two listed futures.",
  },
  late: {
    title: "The conflict appears one slot later",
    evidence: "Verified no policy",
    decision: "Send the common action now. At slot 1 the correct next send still depends on slot 2.",
    early: "3/3",
    hedge: "None",
    reference: "2/3",
    why: "Each future is individually feasible offline. No causal choice works across both.",
  },
  cutoff: {
    title: "Search ran out of budget",
    evidence: "Inconclusive",
    decision: "Stop after one evaluated move.",
    early: "Not reported",
    hedge: "Not verified",
    reference: "Not reported",
    why: "No certificate is attached. Absence of a result is not proof of impossibility.",
  },
});
