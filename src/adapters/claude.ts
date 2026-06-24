import Anthropic from "@anthropic-ai/sdk";
import type { ModelAdapter, ModelCapabilities } from "./model-adapter";
import { SYSTEM_PROMPT, buildUserPrompt } from "./model-adapter";
import { TriageOutputSchema } from "../schema";
import type { TriageInput, TriageOutput } from "../types";

export const CLAUDE_MODEL = "claude-opus-4-8";

type CallModel = (system: string, user: string) => Promise<string>;

export class ClaudeAdapter implements ModelAdapter {
  readonly id = "claude";
  readonly capabilities: ModelCapabilities = { maxContextTokens: 200000, supportsStructuredOutput: true, supportsSeed: false };
  private call: CallModel;

  constructor(apiKey: string, callModel?: CallModel) {
    this.call =
      callModel ??
      (async (system, user) => {
        const client = new Anthropic({ apiKey });
        const msg = await client.messages.create({
          // Note: claude-opus-4-8 deprecates `temperature`; omit it (the model is
          // low-variance by default). Determinism is anchored via the pinned model
          // id + recorded prompt hash in the audit log rather than temperature=0.
          model: CLAUDE_MODEL,
          max_tokens: 1024,
          system,
          messages: [{ role: "user", content: user }],
        });
        const block = msg.content.find((b) => b.type === "text");
        return block && block.type === "text" ? block.text : "";
      });
  }

  async analyze(input: TriageInput): Promise<TriageOutput> {
    const user = buildUserPrompt(input);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const text = await this.call(
          SYSTEM_PROMPT,
          attempt === 0 ? user : `${user}\n\nYour previous reply was not valid JSON. Reply with ONLY the JSON object.`
        );
        const parsed = this.tryParse(text);
        if (parsed) return parsed;
      } catch {
        // treat a thrown error (network, 429, 500, timeout) as a failed attempt
      }
    }
    return {
      verdict: "uncertain",
      severity: input.finding.severity,
      explanation: "needs review (model output invalid)",
      remediation: "Manual review required.",
    };
  }

  private tryParse(text: string): TriageOutput | null {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start === -1 || end === -1 || end < start) return null;
    try {
      const obj = JSON.parse(text.slice(start, end + 1));
      const res = TriageOutputSchema.safeParse(obj);
      return res.success ? res.data : null;
    } catch {
      return null;
    }
  }
}
