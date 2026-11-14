// Mock dispatcher: starts the server with a DUMMY secret, sends a preflight,
// a valid task, every trap variant, a replay, a stale task, a malformed
// task, and a bad-signature request. Asserts decisions, reason codes,
// response HMACs, and local Groth16 verification of every returned proof.
// NEVER uses the real secret. Run: node test/mock-dispatcher.js
'use strict';
const http = require('http');
const crypto = require('crypto');
const { fork } = require('child_process');
const path = require('path');
const snarkjs = require('snarkjs');
const { loadCircuit, getVk, proveDecision } = require('../src/prover');
const { buildCircuitInput, encodeTaskId } = require('../src/encodings');

const DUMMY_SECRET = 'test-only-dummy-secret-do-not-use-in-prod';
const PORT = 18731;
const PATH = '/agent';
const CIRCUIT_DIR = (() => { for (const c of [path.join(__dirname, '..', 'circuits'), path.join(__dirname, '..', '..', 'circuits')]) { if (require('fs').existsSync(path.join(c, 'gatekeeper.wasm'))) return c; } return path.join(__dirname, '..', 'circuits'); })();

const RECIP = '0xDe42000000000000000000000000000000009f01';
const OTHER = '0x1234000000000000000000000000000000000001';
const VK = '0x7d00000000000000000000000000000000000000000000000000000000000091';

let txCounter = 0;
function freshTx() {
  txCounter += 1;
  return '0x' + txCounter.toString(16).padStart(64, 'a');
}

function makeTask(over = {}, inputOver = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_test_${txCounter}_${Math.random().toString(36).slice(2, 8)}`,
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIP,
      condition_recipient: RECIP,
      amount: '500',
      max_transfer: '1000',
      proof_tx: freshTx(),
      ...inputOver,
    },
    ...over,
  };
}

function post(body, { sign = true, badSig = false } = {}) {
  return new Promise((resolve, reject) => {
    const raw = Buffer.from(JSON.stringify(body));
    const sig = badSig ? 'deadbeef'.repeat(8)
      : crypto.createHmac('sha256', DUMMY_SECRET).update(raw).digest('hex');
    const req = http.request({
      host: '127.0.0.1', port: PORT, path: PATH, method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(sign ? { 'x-agent-games-signature': sig } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        raw: Buffer.concat(chunks),
      }));
    });
    req.on('error', reject);
    req.end(raw);
  });
}

function responseSigValid(res) {
  const presented = res.headers['x-agent-games-signature'];
  if (!presented) return false;
  const expected = crypto.createHmac('sha256', DUMMY_SECRET).update(res.raw).digest('hex');
  return presented === expected;
}

async function waitHealthy(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const ok = await new Promise((resolve) => {
        const req = http.get({ host: '127.0.0.1', port: PORT, path: '/health' }, (res) => {
          res.resume(); resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
      });
      if (ok) return true;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function main() {
  const results = [];
  const check = (name, cond, extra = '') => {
    results.push([name, !!cond, extra]);
    console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${extra ? ' — ' + extra : ''}`);
  };

  const server = fork(path.join(__dirname, '..', 'src', 'server.js'), [], {
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: DUMMY_SECRET,
      PORT: String(PORT),
      AGENT_PATH: PATH,
      CIRCUIT_DIR,
      VERIFY_SELF: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[srv] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[srv:err] ' + d));
  try {
    if (!(await waitHealthy())) throw new Error('server did not become healthy');
    const circuit = loadCircuit(CIRCUIT_DIR);
    const vk = await getVk(circuit);
    const verifyProof = (proof, sigs) => snarkjs.groth16.verify(vk, sigs, proof);
    const roundTrips = [];

    async function sendTask(task) {
      const t0 = Date.now();
      const res = await post(task);
      const ms = Date.now() - t0;
      roundTrips.push(ms);
      return { res, body: JSON.parse(res.raw.toString('utf8')), ms };
    }

    // 1. Preflight
    const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    const pfBody = JSON.parse(pf.raw.toString('utf8'));
    check('preflight 200 + {ok, v1} + signed', pf.status === 200 && pfBody.ok === true && pfBody.protocolVersion === 'v1' && responseSigValid(pf));

    // 2. Valid task -> APPROVE + verifying proof
    const t1 = await sendTask(makeTask());
    check('valid -> APPROVE', t1.body.decision === 'APPROVE' && t1.body.reason_code === null, `${t1.ms}ms`);
    check('valid proof verifies', t1.body.proof && await verifyProof(t1.body.proof, t1.body.public_signals));
    check('valid signals: decision=1, taskId encoded',
      t1.body.public_signals[11] === '1'
      && t1.body.public_signals[12] === encodeTaskId(t1.body.task_id)
      && t1.body.public_signals.length === 13);
    check('valid response signed', responseSigValid(t1.res));

    // 3-7. Circuit traps -> REJECT + verifying proof
    const traps = [
      ['vk_mismatch', { proof_vk: '0x13000000000000000000000000000000000000000000000000000000000000aa' }, 'VK_SUBSTITUTION'],
      ['low_balance', { public_balance: '500' }, 'INSUFFICIENT_BALANCE'],
      ['expired', { current_block: 8430000 }, 'EXPIRED'],
      ['recipient_mismatch', { recipient: OTHER }, 'RECIPIENT_MISMATCH'],
      ['amount_over', { amount: '1500' }, 'AMOUNT_EXCEEDS_LIMIT'],
    ];
    for (const [name, inputOver, reason] of traps) {
      const t = await sendTask(makeTask({}, inputOver));
      const proofOk = t.body.proof && await verifyProof(t.body.proof, t.body.public_signals);
      check(`trap ${name} -> REJECT ${reason} + proof verifies`,
        t.body.decision === 'REJECT' && t.body.reason_code === reason && proofOk && t.body.public_signals[11] === '0',
        `${t.ms}ms`);
    }

    // 8. Boundary-valid: balance==minimum, amount==max, current==expiry-1 -> APPROVE
    const tb = await sendTask(makeTask({}, { public_balance: '1000', amount: '1000', current_block: 8429999 }));
    check('boundary-valid -> APPROVE + proof verifies',
      tb.body.decision === 'APPROVE' && tb.body.proof && await verifyProof(tb.body.proof, tb.body.public_signals));

    // 9. Replay: same task twice (same proof_tx) -> 2nd is REJECT PROOF_REUSED, no proof
    const replayTask = makeTask();
    const r1 = await sendTask(replayTask);
    const r2 = await sendTask(replayTask);
    check('replay 1st -> APPROVE', r1.body.decision === 'APPROVE');
    check('replay 2nd -> REJECT PROOF_REUSED + proof null',
      r2.body.decision === 'REJECT' && r2.body.reason_code === 'PROOF_REUSED' && r2.body.proof === null);

    // 10. Stale deadline -> REJECT STALE_TASK, no proof
    const ts = await sendTask(makeTask({ deadline_at: new Date(Date.now() - 1000).toISOString() }));
    check('stale -> REJECT STALE_TASK + proof null',
      ts.body.decision === 'REJECT' && ts.body.reason_code === 'STALE_TASK' && ts.body.proof === null);

    // 11. Malformed (missing amount) -> REJECT MALFORMED_TASK + fallback proof verifies
    const bad = makeTask(); delete bad.input.amount;
    const tm = await sendTask(bad);
    check('malformed -> REJECT MALFORMED_TASK + fallback proof verifies',
      tm.body.decision === 'REJECT' && tm.body.reason_code === 'MALFORMED_TASK'
      && tm.body.proof && await verifyProof(tm.body.proof, tm.body.public_signals));

    // 12. Bad signature -> 401, no decision
    const bu = await post(makeTask(), { badSig: true });
    check('bad signature -> 401', bu.status === 401);
    const ns = await post(makeTask(), { sign: false });
    check('missing signature -> 401', ns.status === 401);

    // 13. Direct proving p50 (clean, no HTTP): 5 proves of a valid task.
    const directTimes = [];
    for (let i = 0; i < 5; i++) {
      const input = buildCircuitInput(makeTask(), 'APPROVE');
      const { proveMs } = await proveDecision(circuit, input);
      directTimes.push(proveMs);
    }
    directTimes.sort((a, b) => a - b);
    const p50 = directTimes[Math.floor(directTimes.length / 2)];
    roundTrips.sort((a, b) => a - b);
    const rtP50 = roundTrips[Math.floor(roundTrips.length / 2)];
    console.log(`\nTIMING: direct prove times ms = [${directTimes.join(', ')}], p50=${p50}ms`);
    console.log(`TIMING: HTTP round-trip p50=${rtP50}ms over ${roundTrips.length} task requests (60s limit)`);
    check('prove p50 < 5000ms', p50 < 5000);

    const failed = results.filter(([, ok]) => !ok);
    console.log(`\n${results.length - failed.length}/${results.length} checks PASS`);
    if (failed.length > 0) process.exitCode = 1;
  } finally {
    server.kill('SIGTERM');
  }
  // snarkjs leaves worker handles open; exit explicitly.
  setTimeout(() => process.exit(process.exitCode || 0), 500).unref();
}

main().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
