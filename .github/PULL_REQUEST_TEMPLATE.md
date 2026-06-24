## Summary

<!-- What does this PR do? One or two sentences. -->

## What Changed

<!-- List the files / components modified and why. -->

- 

## Testing Done

- [ ] `npm test` passes (all 31 tests in both Vitest projects)
- [ ] `npx tsc --noEmit` passes (no type errors)
- [ ] Manually verified in `npm run dev` (if the change touches runtime behavior)

## Checklist

- [ ] Tests pass locally
- [ ] No secrets committed (`.dev.vars` not staged; no API keys in any file)
- [ ] Security invariants preserved:
  - [ ] Model adapter output validated + repair loop intact (zod, 3 attempts, degrade on failure)
  - [ ] Parameterized D1 queries only (no string interpolation of user input)
  - [ ] Any new user-supplied content rendered via `textContent`, not `innerHTML`
  - [ ] Prompt-injection defense maintained if prompt changed (code-as-data delimiters, strict schema)
  - [ ] BYO-key shredding in `finally` block preserved if crypto/scan flow changed
- [ ] Docs updated if behavior changed (AGENTS.md, relevant `docs/` files)
- [ ] Conventional Commit message on all commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`)
