// Empirical probe of the Gatekeeper circuit. KEY FINDING (02:5x WIB): the
// circuit ASSERTS during witness generation when the decision is inconsistent
// with the checks — decision=0 on an all-valid task throws, decision=1 on a
// violating task throws. The circuit is a true referee: a decision is only
// provable when it matches the circuit's own check set.
//
// This probe maps, for each single violation: (a) is REJECT provable?
// (b) is APPROVE blocked? plus boundary semantics (>= vs >, <= vs <) and
// salt/taskId domain checks. Local only. Run: node test/probe-circuit.js
'use strict';
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { WitnessCalculatorBuilder } = require('circom_runtime');

const CIRCUITS = (() => { for (const c of [path.join(__dirname, '..', 'circuits'), path.join(__dirname, '..', '..', 'circuits')]) { if (require('fs').existsSync(path.join(c, 'gatekeeper.wasm'))) return c; } return path.join(__dirname, '..', 'circuits'); })();
const WASM = path.join(CIRCUITS, 'gatekeeper.wasm');
const ZKEY = path.join(CIRCUITS, 'gatekeeper_final.zkey');

const RECIP = BigInt('0xDe42000000000000000000000000000000009f01').toString();
const OTHER = BigInt('0x1234000000000000000000000000000000000001').toString();

function baseInput() {
  return {
    registeredVkHash: 1111, proofVkHash: 1111,
    minimum: 1000, publicBalance: 1460,
    expiryBlock: 8430000, currentBlock: 8420000,
    recipient: RECIP, conditionRecipient: RECIP,
    amount: 500, maxTransfer: 1000,
    decision: 1, taskId: 777001, salt: 777002,
  };
}

// Single-violation overrides (each violates exactly one check).
const VIOLATIONS = {
  vk_mismatch: { proofVkHash: 2222 },
  low_balance: { publicBalance: 500 },
  expired: { currentBlock: 8440000 },
  recipient_mismatch: { recipient: OTHER },
  amount_over: { amount: 1500 },
};
const ALL_VIOLATIONS = {
  proofVkHash: 2222, publicBalance: 500, currentBlock: 8440000,
  recipient: OTHER, amount: 1500,
};

const CASES = [];
CASES.push(['valid, d=1', {}]);
CASES.push(['valid, d=0', { decision: 0 }]);
CASES.push(['ALL violations, d=0', { ...ALL_VIOLATIONS, decision: 0 }]);
CASES.push(['ALL violations, d=1', { ...ALL_VIOLATIONS }]);
for (const [name, over] of Object.entries(VIOLATIONS)) {
  CASES.push([`single:${name}, d=0 (REJECT provable?)`, { ...over, decision: 0 }]);
  CASES.push([`single:${name}, d=1 (APPROVE blocked?)`, { ...over }]);
}
// Boundary semantics: equality cases with d=1.
CASES.push(['boundary: balance==minimum, d=1', { publicBalance: 1000 }]);
CASES.push(['boundary: currentBlock==expiryBlock, d=1', { currentBlock: 8430000 }]);
CASES.push(['boundary: amount==maxTransfer, d=1', { amount: 1000 }]);
// Domain checks.
CASES.push(['d=2 (out of domain)', { decision: 2 }]);
CASES.push(['d=1, salt=0', { salt: 0 }]);
CASES.push(['d=1, taskId=0', { taskId: 0 }]);
CASES.push(['d=1, minimum=0, balance=0', { minimum: 0, publicBalance: 0 }]);

async function classify(vk, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    return { cls: ok ? 'PROVABLE ' : 'UNPROVABLE', ms: Date.now() - t0 };
  } catch (e) {
    const msg = String(e.message || e);
    if (/Assert Failed/i.test(msg)) return { cls: 'ASSERT   ', ms: Date.now() - t0 };
    return { cls: 'THROW(' + msg.slice(0, 40) + ')', ms: Date.now() - t0 };
  }
}

async function main() {
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(WASM), { sanityCheck: false });
  const w = await wc.calculateWitness({ ...baseInput(), decision: 0, ...ALL_VIOLATIONS }, false);
  console.log('witness len', w.length, '| public = w[1..13] = [output, 12 inputs]; salt private at w[14]');
  const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
  console.log('VK nPublic =', vk.IC.length - 1);
  console.log('\nCASE RESULTS:');
  for (const [label, over] of CASES) {
    const { cls, ms } = await classify(vk, { ...baseInput(), ...over });
    console.log(`  [${cls}] ${label} (${ms}ms)`);
  }
  process.exit(0); // snarkjs leaves worker handles open; exit explicitly.
}
main().catch((e) => { console.error('FATAL', e); process.exit(1); });
