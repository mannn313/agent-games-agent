# Agent Games circuit findings

Probed locally with snarkjs + a FNV-hash signal-name oracle
(`signal_oracle.js`) against the published artifacts. All names below were
confirmed present in the wasm (getInputSignalSize == 1); every other tested
variant returned 0.

## Gatekeeper circuit (gatekeeper.wasm / gatekeeper_final.zkey)

- Groth16 / bn128, vkHash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Structure (proven empirically with snarkjs, see test/probe-circuit.js):
  **12 PUBLIC inputs + 1 PRIVATE input (`salt`) + 1 PUBLIC output** (a
  commitment over salt/taskId). `publicSignals` =
  `[output, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId]`. An earlier reading of "13 public
  inputs" was wrong: `salt` sits past the public range in the witness and
  never leaves the agent.
- Input signal names (13 total, all scalars):
  registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  decision, taskId, salt (private).
- The circuit ASSERTS decision/check consistency: witness generation
  throws when the decision contradicts the checks, so a decision is only
  provable when it matches the circuit's own check set. The circuit
  enforces exactly 5 checks: `proofVkHash == registeredVkHash`;
  `publicBalance >= minimum` (equal passes); `currentBlock < expiryBlock`
  (strict — equal fails); `recipient == conditionRecipient`;
  `amount <= maxTransfer` (equal passes).
- No proof_tx signal: reuse/finality checks are agent-side, off-circuit.
  When the 5 checks pass, a REJECT proof is mathematically unprovable, so
  circuit-blind traps (replay/stale) are answered REJECT with `proof: null`.
- OPEN: value encodings (vkHash hex→field? recipient address→field?
  taskId string→field? decision APPROVE=1/REJECT=0?). Current assumptions
  live in exactly one place: `src/encodings.js`. Pin down via practice-mode
  iteration (platform re-verifies; 10 practice dispatches/hour).

## VFY policy circuit (vfy-policy.wasm / vfy-policy_final.zkey)

- Groth16 / bn128, vkHash
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
- nPublic = 9, total inputs = 17 → 9 public + 8 private.
- Public signal names (all scalars):
  commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
  amount, circuitVersion, salt
- The 8 PRIVATE input names are unknown, and the commitment construction
  (how the frozen strategy hash is derived from private strategy params)
  is unknown. Needs the strategy-registration flow / protocol docs.
- publicInputsHash formula (from the /build page): keccak256 of ABI-packed
  32-byte fields: commitment, matchId-as-int, turn, selfBalance,
  opponentBalance, action (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount
  (0 for HOLD/FORTIFY), circuitVersion "v1" → 1.

## Protocol specs

- Gatekeeper response: `{decision, reason_code, proof, public_signals}`,
  HMAC-signed over the raw body. Preflight: `{ok:true, protocolVersion:"v1"}`.
- Scoring: +12 correct, −6 approving a trap, −3 rejecting valid,
  −2 timeout/offline, −2 proof fails to verify, + reliability bonus.
- Full envelope schemas: see the platform's /build page.
