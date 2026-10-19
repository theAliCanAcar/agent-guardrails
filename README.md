# Agent Guardrails

Paranoid agent guardrails: PII redaction, jailbreak heuristics, banned-topic filters, and spend/call budgets as tool wrappers.

TypeScript package `agent-guardrails`.

## Install

```sh
npm install github:theAliCanAcar/agent-guardrails#main
```

## How to use

```ts
import { tool } from 'agent-tools';
import { guard, redactPii } from 'agent-guardrails';
import { z } from 'zod';

const raw = tool({
  name: 'echo',
  description: 'Echo text',
  schema: z.object({ text: z.string() }),
  execute: async ({ text }) => text,
});

const safe = guard(raw, { maxCalls: 20 });
console.log(redactPii('Reach me at ada@example.com'));
console.log(await safe.execute({ text: 'hello' }, {}));
```

## Use cases

### 1. Redact PII before a tool runs

- **Scenario:** Model output may include emails or phone numbers.
- **Outcome:** Wrap tools so sensitive patterns are stripped or blocked.

### 2. Cap spend and call volume

- **Scenario:** A runaway loop burns budget.
- **Outcome:** Enforce call/spend budgets as tool wrappers.

## Dependencies

- `agent-tools`: `github:theAliCanAcar/agent-tools#main`

## Scripts

```sh
npm install
npm run build
```

## Notes

- Keep API keys in environment variables or a gitignored `.env`. Never commit secrets.
- Side-effecting tools should go through approval when used with `agent-approval`.
- Related packages live in separate repositories under [theAliCanAcar](https://github.com/theAliCanAcar).

## License

MIT
