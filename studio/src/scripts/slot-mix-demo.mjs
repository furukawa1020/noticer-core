export const exactLaw = [1, 1, 1, 2];
export const moves = [
  { label: "Keep A for last", mask: 3 },
  { label: "Keep B for last", mask: 5 },
  { label: "Keep C for last", mask: 6 },
  { label: "Keep D for last", mask: 8 },
];
export const tapes = ["Future 1", "Future 2", "Future 3", "Future 4"];

export function viewRows() {
  return tapes.map((label, i) => {
    let accepted = 0;
    let weighted = 0;
    for (const [j, move] of moves.entries()) {
      if (move.mask & (1 << i)) {
        accepted += 1;
        weighted += exactLaw[j];
      }
    }
    return { label, uniform: `${accepted}/4`, certified: `${weighted}/5` };
  });
}
