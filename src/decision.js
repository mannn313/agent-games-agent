// Deterministic, fail-closed Gatekeeper decision logic.
//
// CIRCUIT CHECKS — MUST match the circuit exactly (proven empirically in
// test/probe-circuit.js: the circuit asserts when the decision is
// inconsistent with these checks, so a mismatched decision is UNPROVABLE):
//   1. proofVkHash == registeredVkHash        (equality, field values)
//   2. publicBalance >= minimum              (boundary: equal PASSES)
//   3. currentBlock < expiryBlock            (boundary: equal FAILS — strict)
//   4. recipient == conditionRecipient       (case-insensitive addresses)
//   5. amount <= maxTransfer                 (boundary: equal PASSES)
//
// AGENT-SIDE CHECKS — the circuit cannot see these (no proof_tx signal,
// no signature/timestamp inputs). When they fail but the 5 circuit checks
// pass, a REJECT proof is UNPROVABLE (witness assert), so the response
// carries proof:null / public_signals:null with an honest reason_code.
// [OPEN] How the platform scores a correct decision with no proof is
// unverified — confirm in practice mode.
//   6. proof_tx not previously seen (replay cache)
//   7. deadline_at not passed (when parseable; unparseable = skipped)
//
// Malformed tasks (missing/unparseable fields) -> REJECT with a proof over
// the all-violating fallback input (provable; signals cannot match a
// malformed task anyway).
'use strict';

const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';

const REASONS = {
  ALL_CHECKS_PASSED: 'all checks passed',
  VK_SUBSTITUTION: 'proof_vk does not match registered_vk',
  EXPIRED: 'current_block >= expiry_block',
  INSUFFICIENT_BALANCE: 'public_balance < minimum',
  RECIPIENT_MISMATCH: 'recipient != condition_recipient',
  AMOUNT_EXCEEDS_LIMIT: 'amount > max_transfer',
  PROOF_REUSED: 'proof_tx seen before (replay)',
  STALE_TASK: 'deadline_at passed',
  MALFORMED_TASK: 'missing or unparseable input field',
};

function parseBig(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === 'string' && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(v.trim())) return BigInt(v.trim());
  return null;
}

function parseAddress(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(s) ? s : null;
}

function parseDeadline(v, nowMs) {
  if (v === undefined || v === null) return null;
  let ms = NaN;
  if (typeof v === 'number') ms = v < 1e12 ? v * 1000 : v;
  else if (typeof v === 'string') {
    if (/^[0-9]+$/.test(v.trim())) { const n = Number(v.trim()); ms = n < 1e12 ? n * 1000 : n; }
    else ms = Date.parse(v);
  }
  if (!Number.isFinite(ms)) return null; // unparseable -> check skipped (documented)
  return ms;
}

// Returns: { decision, reason_code, proofMode, failedChecks[] }
// proofMode: 'true-inputs' | 'fallback-inputs' | 'none'
function decide(task, { replayCache, nowMs = Date.now() }) {
  const failedChecks = [];
  const input = task && task.input;

  // Well-formedness: all 10 input fields must parse.
  const f = input ? {
    registeredVk: parseBig(input.registered_vk),
    proofVk: parseBig(input.proof_vk),
    minimum: parseBig(input.minimum),
    publicBalance: parseBig(input.public_balance),
    expiryBlock: parseBig(input.expiry_block),
    currentBlock: parseBig(input.current_block),
    recipient: parseAddress(input.recipient),
    conditionRecipient: parseAddress(input.condition_recipient),
    amount: parseBig(input.amount),
    maxTransfer: parseBig(input.max_transfer),
  } : null;
  const malformed = !f || Object.values(f).some((v) => v === null)
    || typeof task.task_id !== 'string' || task.task_id.length === 0
    || typeof input.proof_tx !== 'string' || input.proof_tx.length === 0;
  if (malformed) {
    return { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proofMode: 'fallback-inputs', failedChecks: ['malformed'] };
  }

  // Circuit checks, in checklist order. First failure wins the reason_code,
  // but ALL failures are recorded for logging.
  if (f.proofVk !== f.registeredVk) failedChecks.push('VK_SUBSTITUTION');
  if (f.currentBlock >= f.expiryBlock) failedChecks.push('EXPIRED');
  if (f.publicBalance < f.minimum) failedChecks.push('INSUFFICIENT_BALANCE');
  if (f.recipient !== f.conditionRecipient) failedChecks.push('RECIPIENT_MISMATCH');
  if (f.amount > f.maxTransfer) failedChecks.push('AMOUNT_EXCEEDS_LIMIT');
  if (failedChecks.length > 0) {
    return { decision: 'REJECT', reason_code: failedChecks[0], proofMode: 'true-inputs', failedChecks };
  }

  // Agent-side checks (circuit-blind). REJECT here is unprovable.
  if (replayCache && replayCache.checkAndRecord(input.proof_tx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proofMode: 'none', failedChecks: ['PROOF_REUSED'] };
  }
  const deadlineMs = parseDeadline(task.deadline_at, nowMs);
  if (deadlineMs !== null && nowMs > deadlineMs) {
    return { decision: 'REJECT', reason_code: 'STALE_TASK', proofMode: 'none', failedChecks: ['STALE_TASK'] };
  }

  // reason_code must ALWAYS be a string: the platform's protocol-v1 schema
  // rejects null (practice dispatch 2026-11-15: "reason_code: Invalid input:
  // expected string, received null" on a valid APPROVE task).
  return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASSED', proofMode: 'true-inputs', failedChecks: [] };
}

module.exports = { TASK_TYPE, REASONS, decide, parseBig, parseAddress, parseDeadline };
