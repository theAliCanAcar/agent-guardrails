/**
 * agent-guardrails: paranoia as a library. Wrap any tool (or text stream) with
 * PII redaction, jailbreak/banned-topic sniffing, and hard budgets on calls
 * and spend. Fail closed, log everything, trust nothing an LLM says.
 *
 *   const safeSend = guard(sendEmail, {
 *     redactPii: true,
 *     bannedTopics: ["insider trading"],
 *     budget: { maxCalls: 5, maxCostUsd: 1 },
 *   });
 */
import {
  failure,
  isFailure,
  runTool,
  type Tool,
  type ToolContext,
  type ToolResult,
} from "agent-tools";

export type RedactionPattern = { name: string; pattern: RegExp; mask?: string };

export const DEFAULT_PII_PATTERNS: RedactionPattern[] = [
  { name: "email", pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, mask: "[EMAIL]" },
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, mask: "[SSN]" },
  { name: "credit_card", pattern: /\b(?:\d[ -]?){13,16}\b/g, mask: "[CARD]" },
  { name: "phone", pattern: /\b(?:\+?\d{1,3}[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b/g, mask: "[PHONE]" },
];

export const DEFAULT_JAILBREAK_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+|previous\s+|prior\s+|earlier\s+|the\s+|my\s+)*instructions/i,
  /disregard (all |previous |prior )?(your |the )?(rules|instructions)/i,
  /\bjailbreak\b/i,
  /\bdo anything now\b/i,
  /reveal (your |the )?(system|hidden) prompt/i,
  /\bpretend (you have|there are) no rules\b/i,
];

export type GuardVerdict = { clean: boolean; violations: Array<{ rule: string; detail: string }> };

export type GuardrailsConfig = {
  /** Replace emails, cards, phones, SSNs in outgoing payloads. */
  redactPii?: boolean;
  /** Extra redaction rules merged with the defaults. */
  piiPatterns?: RedactionPattern[];
  /** Phrases/topics that must never appear (case-insensitive substring). */
  bannedTopics?: string[];
  /** Prompt-injection / jailbreak heuristics applied to free text. */
  detectJailbreaks?: boolean;
  jailbreakPatterns?: RegExp[];
  /** Hard ceilings enforced across calls. */
  budget?: { maxCalls?: number; maxCostUsd?: number; costPerCallUsd?: number };
  /** Called on every violation — wire to agent-audit. */
  onViolation?: (violation: { rule: string; detail: string }) => void;
};

export type Guarded<I, O> = Tool<I, ToolResult<O>> & {
  /** Remaining call/cost budget snapshot. */
  budgetLeft: () => { calls: number | null; costUsd: number | null };
  violations: () => Array<{ rule: string; detail: string }>;
};

/** Scan free text and return every guardrail violation found. */
export function inspectText(text: string, config: GuardrailsConfig = {}): GuardVerdict {
  const violations: Array<{ rule: string; detail: string }> = [];

  for (const topic of config.bannedTopics ?? []) {
    if (topic && text.toLowerCase().includes(topic.toLowerCase())) {
      violations.push({ rule: "banned_topic", detail: `Contains banned topic: ${topic}` });
    }
  }

  if (config.detectJailbreaks ?? true) {
    const patterns = config.jailbreakPatterns ?? DEFAULT_JAILBREAK_PATTERNS;
    for (const pattern of patterns) {
      if (pattern.test(text)) {
        violations.push({ rule: "jailbreak", detail: `Matches jailbreak pattern: ${pattern}` });
      }
    }
  }

  return { clean: violations.length === 0, violations };
}

/** Replace PII in any stringified payload. Returns redacted text + hit counts. */
export function redactPii(
  text: string,
  extraPatterns: RedactionPattern[] = []
): { text: string; redactions: Record<string, number> } {
  const redactions: Record<string, number> = {};
  let out = text;
  for (const rule of [...DEFAULT_PII_PATTERNS, ...extraPatterns]) {
    const matches = out.match(rule.pattern);
    if (matches) {
      redactions[rule.name] = (redactions[rule.name] ?? 0) + matches.length;
      out = out.replace(rule.pattern, rule.mask ?? `[${rule.name.toUpperCase()}]`);
    }
  }
  return { text: out, redactions };
}

/**
 * Wrap a tool with guardrails. Order of operations:
 * budget -> jailbreak/topic scan on input -> PII redaction on input -> tool ->
 * PII redaction on output.
 */
export function guard<I, O>(t: Tool<I, O>, config: GuardrailsConfig = {}): Guarded<I, O> {
  const seen: Array<{ rule: string; detail: string }> = [];
  let calls = 0;
  let spent = 0;
  const maxCalls = config.budget?.maxCalls;
  const maxCost = config.budget?.maxCostUsd;
  const costPerCall = config.budget?.costPerCallUsd ?? 0;

  function violate(rule: string, detail: string): ToolResult<O> {
    const v = { rule, detail };
    seen.push(v);
    config.onViolation?.(v);
    return failure("GUARDRAIL_BLOCKED", detail, { retryable: false, details: v });
  }

  function deepRedact(value: unknown): unknown {
    if (!config.redactPii) return value;
    if (typeof value === "string") return redactPii(value, config.piiPatterns).text;
    if (Array.isArray(value)) return value.map(deepRedact);
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = deepRedact(v);
      return out;
    }
    return value;
  }

  const wrapped: Guarded<I, O> = {
    name: t.name,
    description: `${t.description} (guarded)`,
    schema: t.schema,
    ...(t.inputSchema ? { inputSchema: t.inputSchema } : {}),
    budgetLeft: () => ({
      calls: maxCalls === undefined ? null : Math.max(0, maxCalls - calls),
      costUsd: maxCost === undefined ? null : Math.max(0, maxCost - spent),
    }),
    violations: () => [...seen],
    async execute(input: I, ctx: ToolContext): Promise<ToolResult<O>> {
      if (maxCalls !== undefined && calls >= maxCalls) {
        return violate("budget_calls", `Call budget exhausted (${maxCalls}).`);
      }
      if (maxCost !== undefined && spent + costPerCall > maxCost) {
        return violate("budget_cost", `Spend budget exhausted ($${maxCost}).`);
      }
      calls += 1;
      spent += costPerCall;

      const rawInput = JSON.stringify(input ?? null);
      const verdict = inspectText(rawInput, config);
      if (!verdict.clean) {
        for (const v of verdict.violations) violate(v.rule, v.detail);
        return failure("GUARDRAIL_BLOCKED", `Input blocked: ${verdict.violations.map((v) => v.rule).join(", ")}`, {
          retryable: false,
          details: verdict.violations,
        });
      }

      const safeInput = deepRedact(input) as I;
      const outcome = await runTool(t, safeInput, ctx);
      if (isFailure(outcome)) return outcome;
      return deepRedact(outcome.value) as O;
    },
  };
  return wrapped;
}