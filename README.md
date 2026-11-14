# Agent Games Agent

Verifiable AI agent for the [zkVerify Agent Games](https://agentgames.zkverify.io)
(21 Oct – 21 Nov 2026), competing in **Proof Gatekeeper** and **Steal the VFY**,
plus the **Wildcard** track.

## What it does

- Receives signed task envelopes at a public HTTPS endpoint, verifies the HMAC
  signature on the raw body, and answers inside the platform's time limit.
- **Proof Gatekeeper:** decides APPROVE / REJECT on proof-verification tasks
  with deterministic, fail-closed checks, and attaches a Groth16 proof (BN254,
  Circom 2.x) generated locally with `snarkjs` that the platform re-verifies
  against its own registered verification key.
- **Steal the VFY:** plays 20-turn matches from a frozen strategy commitment;
  every move carries a policy proof whose public-inputs hash matches the
  platform's computation.
- No LLM in the decision path: the final call is deterministic code. Secrets
  come from environment variables only.

## Circuit findings first

Before writing the agent, I read the published circuits instead of trusting
the docs. Using the circom witness calculator's FNV-hash signal oracle, I
recovered the full input schema of both circuits empirically:

- **Gatekeeper:** 13 inputs, ALL public, zero private. Signals:
  `registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
  taskId, salt`. No `proof_tx` signal — reuse/finality checks are agent-side.
- **VFY policy:** 17 inputs — 9 public, 8 private. Public signals:
  `commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
  amount, circuitVersion, salt`. The private strategy inputs and the
  commitment construction are intentionally hidden; they are pinned down via
  the strategy-registration flow and practice mode.

Full details: [docs/circuit-findings.md](docs/circuit-findings.md). The story
of the analysis is also the project's Creator Track article:
"The Referee Is Math" (Medium).

## Status

- [x] Circuit input schemas recovered empirically
- [x] Registered on Agent Games as @johncalta
- [x] Creator Track entry submitted (article, pending manual review)
- [ ] Agent registration (HMAC secret) — in progress
- [ ] Endpoint live + practice mode verified
- [ ] Gatekeeper scored rounds R03–R08 (daily 17:30–03:30 WIB)
- [ ] Steal the VFY Swiss rounds (if entry still open)

## Layout (planned)

```
src/
  server.ts        # HTTPS endpoint: HMAC verify -> decide -> prove -> respond
  gatekeeper.ts    # deterministic Gatekeeper decision checks
  prover.ts        # snarkjs proof generation (gatekeeper + vfy-policy)
  steal.ts         # Steal the VFY strategy + move proofs
docs/
  circuit-findings.md
```

## Run (planned)

```sh
npm install
AGENT_GAMES_HMAC_SECRET=... npm start
```

Proving keys and WASM artifacts are downloaded from the platform's public
circuit endpoints at deploy time; they are not committed to this repo.
