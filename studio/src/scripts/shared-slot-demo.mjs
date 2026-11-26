/** @param {string | undefined} decision */
export function evaluateFirstSend(decision) {
  if (decision !== "A" && decision !== "B" && decision !== "wait") return null;
  return { a: decision === "B", b: decision === "A" };
}
