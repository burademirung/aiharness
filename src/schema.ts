import { z } from "zod";

export const ScanRequestSchema = z.object({
  language: z.string().min(1),
  // Either files or repoUrl must be provided (enforced in validateScanRequest).
  files: z.array(z.object({ path: z.string().min(1), content: z.string() })).optional(),
  repoUrl: z.string().url().optional(),
  // Optional: if omitted/blank, the server falls back to the configured demo key.
  apiKey: z.string().optional(),
});
export type ScanRequest = z.infer<typeof ScanRequestSchema>;

// Strict schema the model MUST fill (Task 9).
export const TriageOutputSchema = z.object({
  verdict: z.enum(["confirmed", "refuted", "uncertain"]),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  explanation: z.string().min(1),
  remediation: z.string().min(1),
});
