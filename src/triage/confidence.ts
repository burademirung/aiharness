import type { Confidence, Verdict } from "../types";

export function computeConfidence(input: { deterministic: boolean; verdict: Verdict }): { confidence: Confidence; evidence: string } {
  const { deterministic, verdict } = input;
  if (deterministic && verdict === "confirmed") {
    return { confidence: "high", evidence: "Flagged by deterministic engine and confirmed by model." };
  }
  if (deterministic && verdict === "uncertain") {
    return { confidence: "medium", evidence: "Flagged by deterministic engine; model uncertain." };
  }
  if (deterministic && verdict === "refuted") {
    return { confidence: "low", evidence: "Deterministic engine flagged but model refuted; likely false positive." };
  }
  return { confidence: "low", evidence: "Model-originated without deterministic basis; needs review." };
}
