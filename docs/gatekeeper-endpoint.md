# Proof Gatekeeper endpoint — agent MANSKUY-1

Public HTTPS endpoint for the zkVerify Agent Games **Proof Gatekeeper**
event. Receives signed task envelopes, makes a deterministic fail-closed
APPROVE/REJECT decision, generates a local Groth16 decision proof with
snarkjs, and returns a signed response. No LLM in the decision path.

## Run

```sh
npm install
export AGENT_GAMES_HMAC_SECRET='...'   # from the Agent Games dashboard
export CIRCUIT_DIR=/path/to/circuits   # gatekeeper.wasm + gatekeeper_final.zkey
export PORT=3000
export AGENT_PATH=/agent
node src/server.js
```

The service refuses to start without `AGENT_GAMES_HMAC_SECRET`. Copy
`.env.example` to `.env` for local runs (never commit `.env`).

Endpoints:

- `POST $AGENT_PATH` — the agent endpoint (preflight + tasks, HMAC-signed).
- `GET /health` — unsigned liveness check for the host.

## How it works

1. **HMAC first.** The raw body is verified against the
   `x-agent-games-signature` header (HMAC-SHA256, constant-time compare)
   BEFORE JSON parsing. Bad/missing signature → 401, no decision.
2. **Preflight.** `{"type": "agent-games.preflight.v1", ...}` →
   `{"ok": true, "protocolVersion": "v1"}`, signed.
3. **Decision.** `src/decision.js` runs the checks below. Any doubt → REJECT.
4. **Proof.** `src/prover.js` runs `snarkjs.groth16.fullProve` with the
   Gatekeeper wasm/zkey. Self-verification (`VERIFY_SELF=1`, default) re-checks
   the proof locally before responding; on failure the response carries
   `proof: null` + `proof_error: true` instead of a bad proof.
5. **Signed response.** `{decision, reason_code, proof, public_signals,
   proof_tx, task_id}` with `x-agent-games-signature` over the raw body.

## Circuit findings (proven locally, see test/probe-circuit.js)

- **Structure:** 12 PUBLIC inputs + 1 PRIVATE input (`salt`) + 1 PUBLIC
  output (a commitment over salt/taskId). `publicSignals` =
  `[output, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId]`. (An earlier reading of "13 public
  inputs" was wrong: `salt` sits past the public range in the witness.)
- **The circuit is a true referee.** Witness generation ASSERTS when the
  decision is inconsistent with the checks: `decision=0` on an all-valid
  task throws, `decision=1` on any violating task throws. A decision is
  only provable when it matches the circuit's own check set.
- **The circuit enforces exactly 5 checks** (each single violation makes
  REJECT provable and APPROVE unprovable):
  1. `proofVkHash == registeredVkHash`
  2. `publicBalance >= minimum` (equal PASSES)
  3. `currentBlock < expiryBlock` (equal FAILS — strict)
  4. `recipient == conditionRecipient`
  5. `amount <= maxTransfer` (equal PASSES)
- `decision` must be 0/1; `salt=0` and `taskId=0` are accepted.

## Trap coverage (7 varieties)

| # | Trap | Check | Reason code | Proof? |
|---|------|-------|-------------|--------|
| 1 | VK substitution | proof_vk != registered_vk | `VK_SUBSTITUTION` | yes |
| 2 | Expired task | current_block >= expiry_block | `EXPIRED` | yes |
| 3 | Insufficient balance | public_balance < minimum | `INSUFFICIENT_BALANCE` | yes |
| 4 | Recipient mismatch | recipient != condition_recipient | `RECIPIENT_MISMATCH` | yes |
| 5 | Amount over limit | amount > max_transfer | `AMOUNT_EXCEEDS_LIMIT` | yes |
| 6 | Proof replay | proof_tx seen before (in-memory cache, 24h TTL) | `PROOF_REUSED` | **no** |
| 7 | Stale/forged task | bad HMAC (401, no response) / deadline passed | `STALE_TASK` | **no** |

Plus: malformed envelopes → `MALFORMED_TASK` with a proof over an
all-violating fallback input; prover failure → `PROOF_ERROR`, no proof.

**Why traps 6–7 carry no proof:** the circuit has no `proof_tx`, signature,
or timestamp inputs, so when the 5 circuit checks pass, a REJECT proof is
mathematically unprovable (witness assert). Fabricating a proof for altered
inputs would fail the platform's signal check anyway. The honest response
is the decision + reason + `proof: null`. How the platform scores a
correct decision with no proof is UNVERIFIED — confirm in practice mode.

## Encoding assumptions (src/encodings.js — the single place to change)

All flagged `[ASSUMPTION]` in code; adjust ONLY that file if practice
proofs fail to verify:

- **A1** vkHash: 32-byte hex → BigInt mod p (snarkjs reduces).
- **A2** address: 20-byte hex → BigInt.
- **A3** integers: decimal string/number → BigInt mod p.
- **A4** taskId: `keccak256(utf8(task_id))` mod p. Alternatives: sha256,
  Poseidon, FNV-1a-64, numeric suffix.
- **A5** decision: APPROVE=1, REJECT=0.
- **A6** salt: private input, any value works; `keccak256(task_id)` mod p
  for determinism.
- **S1** signature format: outbound = lowercase hex HMAC-SHA256, no prefix;
  inbound accepts hex, `sha256=<hex>`, or base64.

## Tests

```sh
npm test            # keccak vectors + mock dispatcher (18 checks)
node test/probe-circuit.js   # re-derive the circuit semantics above
```

Measured locally (this VM, 1.5 shared CPUs): proof generation p50
≈ 310–375ms, HTTP round-trip p50 ≈ 340–380ms — far inside the 60s/task
limit. First request after start is slower (~1s, cold curve init).

## Deploy notes

- Single long-running Node process. Must be reachable at a **public HTTPS
  URL, no custom ports** (standard 443 via the host's TLS termination).
  Bind `0.0.0.0:$PORT`; the host injects `PORT`.
- **Host outside this VM** (the VM has no inbound path; Cloudflare tunnel
  egress is blocked): Render/Railway/Fly/Vercel (as a long-running
  service, not a serverless function — the replay cache is in-memory and
  the process must stay warm; a sleeping free tier forfeits tasks).
- On start, `scripts/fetch-circuits.js` (the `prestart` hook) downloads
  `gatekeeper.wasm` + `gatekeeper_final.zkey` from the platform's public
  circuit endpoints into `$CIRCUIT_DIR` (verified by exact byte size).
  Artifacts are NOT committed to the repo.
- Set `AGENT_GAMES_HMAC_SECRET` from the host's secret store, never in
  code or chat. Rotate via the dashboard if ever exposed.
- Register the endpoint URL in the Agent Games dashboard; saving runs a
  signed preflight check against this service.
- The in-memory replay cache resets on restart/redeploy. That only
  re-opens the replay window for proofs seen before the restart; the
  platform issues fresh `proof_tx` values per task.
- **Not implemented (future):** Kurier/zkVerifyJS on-chain finality
  confirmation of `proof_tx` before approval (needs `KURIER_API_KEY` +
  network). Current design treats the circuit checks + replay cache as
  sufficient; revisit if practice shows finality traps.
