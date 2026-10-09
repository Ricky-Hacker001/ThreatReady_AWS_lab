# ThreatReady — Cloud Security Lab 001: The Compromised Startup

Standalone working prototype of lab **TR-CLOUD-001**. A learner investigates NovaCart's simulated AWS environment through an AWS-style console, finds ten vulnerabilities, contains an active intruder, remediates, verifies, and files an incident report across four levels.

**SIMULATION ONLY.** No AWS account, credentials, LLM or paid service is used. Every identity, key, log line and secret is synthetic.

## Run it

Requires Node.js 20.11+ (22 recommended).

```bash
npm install
npm run build      # builds the React client into dist/
npm start          # http://localhost:4000  (API + client)
```

Development with hot reload: `npm run dev` → client on http://localhost:5173, API on :4000.

Sign in with any display name (prototype login). Progress is stored in `data/store.json`; set `DATA_FILE` to move it, `PORT` to change the port.

## Tests

```bash
npm test            # 39 unit, integration and API security tests (Vitest + Supertest)
npm run build && npm run test:e2e   # browser end-to-end (Playwright; needs Chromium: npx playwright install chromium)
npm run typecheck
```

`tests/helpers.ts` contains a full scripted solution (`steps.level1` … `steps.level4`) — useful as an answer key for reviewers. It is never shipped to the browser.

## Reset a lab

Profile menu → **Reset lab…** → type `RESET`. The server archives the current run (still readable, with its report) and starts a new run from the fixture. API: `POST /api/sessions/:id/reset {"confirm":"RESET"}`.

## Architecture

```
client/src        React + Vite + TypeScript. Presentation only: renders server state, sends actions.
server/policy.ts  IAM-style evaluation: identity policies, bucket/key policies, SCPs, Block Public Access, CIDR maths.
server/fixture.ts Initial NovaCart environment (the vulnerable state).
server/sim.ts     Shared simulation: network reachability, S3 access incl. KMS, Lambda execution, app health probes.
server/scenario.ts SERVER-ONLY: findings, verification predicates, objectives, hints, attacker script, report rubric.
server/engine.ts  LabEngine implementation: action handlers, post-action simulation, scoring, public projections, report.
server/app.ts     REST API: auth, ownership checks, idempotency, pagination.
server/store.ts   Persistence boundary (atomic JSON file).
```

Rules the code enforces:

- **Server-authoritative.** The client sends `{type, params, requestId}`. The engine validates input, checks the learner's simulated IAM permissions, checks preconditions, applies the change to a copy of the state and commits state + event + idempotency record together. A failed action changes nothing except the failure log.
- **No answers in the browser.** `engine.view()` and `engine.status()` are the only projections sent to clients. Predicates, hints not yet requested, attacker script, triage truth and secret values never leave the server (asserted in tests).
- **Fix ≠ verified.** A finding is *remediated* when its server-side predicate over the live configuration holds, and *verified* only after the learner runs passing tests while it holds. Regressions reopen findings.
- **Shared state.** One policy engine backs every console: an IAM edit changes Lambda results, a key policy change changes S3 results, an SCP overrides administrators, a stopped trail starves a CloudWatch alarm.
- **Deterministic.** The simulated clock advances per action (change +5 min, test +2, inspect +1). The intruder's script runs at fixed offsets from the start of Level 2 and succeeds or fails purely from the current configuration.

## Add a vulnerability

1. Put the misconfiguration into `server/fixture.ts`.
2. If it needs a new operation, add a handler to `H` in `server/engine.ts` (validate → `learnerAuth` → mutate → return message). Tests call `recordTest`.
3. Add a `FindingDef` to `FINDINGS` in `server/scenario.ts`: `resources` (where it may be reported), `inspect` (evidence the learner must have opened), `remediated(state)`, `checks` (which test results count as verification), `explanation`.
4. Add `find(...)`/`fix(...)` objectives with hints to `OBJECTIVES`.
5. Add UI for the new configuration in `client/src/services*.tsx`, and a test in `tests/engine.test.ts`.

A second lab is a new object implementing `LabEngine`, registered in `ENGINES` in `server/app.ts`; auth, sessions, persistence and the report endpoint are reused.

## Differences from the platform build prompt (deliberate, for a standalone prototype)

| Prompt | This prototype | To integrate |
|---|---|---|
| NestJS modular monolith | Express, one router | Wrap `LabEngine` in a Nest module; controllers map 1:1 to `app.ts` routes |
| PostgreSQL | Atomic JSON file behind `Store` | Implement `Store` on Prisma: `lab_sessions` (state JSONB), `lab_events`, `lab_requests` |
| Platform auth | Display-name login issuing a bearer token | Replace the auth middleware; ownership check stays |
| Worker for reports | Report generated synchronously (milliseconds) | Not needed at this size |
| Vulnerabilities hidden until found | Titles visible from the start, locations hidden (your choice) | `definition().vulnerabilities` |
