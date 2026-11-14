// ENCODING ASSUMPTIONS — single module, single place to change.
//
// CORRECTED CIRCUIT STRUCTURE (proven in test/probe-circuit.js, 02:5x WIB):
// the circuit has 12 PUBLIC inputs + 1 PRIVATE input (salt) + 1 PUBLIC
// output (a commitment over salt/taskId). publicSignals = [output,
// registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
// currentBlock, recipient, conditionRecipient, amount, maxTransfer,
// decision, taskId]. Salt never leaves the agent, so its encoding is a free
// choice; the other 12 encodings MUST match the platform's, because the
// platform checks the public signals against the task.
//
// The platform re-verifies our decision proof against its own VK and checks
// the public signals against the task. The EXACT value encodings are NOT
// published in the /build blocks; every assumption below is flagged [ASSUMPTION]
// and must be confirmed/adjusted during practice-mode iteration (10 dispatches/
// hour). If practice proofs fail to verify, change ONLY this file.
//
// Field: bn128 scalar field, p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
// snarkjs reduces inputs mod p when building the witness, so oversized
// 256-bit hashes are accepted and reduced — that reduction itself is [ASSUMPTION A1].
'use strict';
const { keccak256 } = require('./keccak');

const FIELD_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function toField(x) {
  const v = BigInt(x) % FIELD_P;
  return (v < 0n ? v + FIELD_P : v).toString();
}

// [ASSUMPTION A1] vkHash: 32-byte hex string -> BigInt, reduced mod p.
// The registered/proof VK values in the envelope are 0x-prefixed 32-byte
// hashes; equality is what the circuit checks, and reduction preserves
// equality for distinct hashes with overwhelming probability.
function encodeVkHash(hex) {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`encodeVkHash: bad hex value ${JSON.stringify(hex)}`);
  }
  return toField(BigInt(hex));
}

// [ASSUMPTION A2] address: 20-byte hex -> BigInt (fits in the field).
function encodeAddress(hex) {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(hex)) {
    throw new Error(`encodeAddress: bad address ${JSON.stringify(hex)}`);
  }
  return toField(BigInt(hex));
}

// [ASSUMPTION A3] plain integers (minimum, publicBalance, blocks, amounts):
// decimal string or JS number -> BigInt, reduced mod p.
function encodeUint(v, name) {
  if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'bigint') {
    throw new Error(`encodeUint(${name}): bad value ${JSON.stringify(v)}`);
  }
  return toField(BigInt(v));
}

// [ASSUMPTION A4] taskId: "gk_..." string -> keccak256(utf8) as BigInt mod p.
// Alternatives if practice fails: sha256, Poseidon, FNV-1a-64, numeric suffix.
// The platform's own docs use keccak256 (viem) for hashes, hence this choice.
function encodeTaskId(taskId) {
  if (typeof taskId !== 'string' || taskId.length === 0) {
    throw new Error('encodeTaskId: taskId must be a non-empty string');
  }
  return toField(BigInt('0x' + keccak256(taskId).toString('hex')));
}

// [ASSUMPTION A5] decision: APPROVE = 1, REJECT = 0.
function encodeDecision(decision) {
  if (decision === 'APPROVE') return '1';
  if (decision === 'REJECT') return '0';
  throw new Error(`encodeDecision: unknown decision ${JSON.stringify(decision)}`);
}

// [ASSUMPTION A6] salt: PRIVATE input — the platform never sees it, so any
// value works (probe: salt=0 also proves). keccak256(taskId) mod p keeps
// the commitment deterministic per task and distinct across tasks.
function encodeSalt(taskId) {
  return encodeTaskId(taskId);
}

// Build the full 13-signal circuit input for a task + decision.
// Throws on any malformed field -> caller must fail closed (REJECT) — but a
// REJECT proof needs valid encodings too, so malformed tasks use the
// zero-input fallback in buildFallbackInput() instead of throwing here.
function buildCircuitInput(task, decision) {
  const input = task.input;
  return {
    registeredVkHash: encodeVkHash(input.registered_vk),
    proofVkHash: encodeVkHash(input.proof_vk),
    minimum: encodeUint(input.minimum, 'minimum'),
    publicBalance: encodeUint(input.public_balance, 'publicBalance'),
    expiryBlock: encodeUint(input.expiry_block, 'expiryBlock'),
    currentBlock: encodeUint(input.current_block, 'currentBlock'),
    recipient: encodeAddress(input.recipient),
    conditionRecipient: encodeAddress(input.condition_recipient),
    amount: encodeUint(input.amount, 'amount'),
    maxTransfer: encodeUint(input.max_transfer, 'maxTransfer'),
    decision: encodeDecision(decision),
    taskId: encodeTaskId(task.task_id),
    salt: encodeSalt(task.task_id),
  };
}

// Fallback input for malformed tasks: all checks encoded as failing, decision
// REJECT. taskId uses the raw task_id when usable, else a fixed sentinel so
// the proof still binds to *something* deterministic.
function buildFallbackInput(task) {
  let taskId = '0';
  let salt = '0';
  try { taskId = encodeTaskId(task.task_id); salt = encodeSalt(task.task_id); } catch { /* sentinel */ }
  return {
    registeredVkHash: '1', proofVkHash: '2', // deliberately unequal
    minimum: '1', publicBalance: '0',        // balance below minimum
    expiryBlock: '1', currentBlock: '2',     // expired
    recipient: '1', conditionRecipient: '2', // mismatch
    amount: '2', maxTransfer: '1',           // over limit
    decision: '0',
    taskId, salt,
  };
}

module.exports = {
  FIELD_P, toField, encodeVkHash, encodeAddress, encodeUint,
  encodeTaskId, encodeDecision, encodeSalt,
  buildCircuitInput, buildFallbackInput,
};
