// Proof Gatekeeper endpoint service (agent MANSKUY-1).
// Stdlib HTTP server + snarkjs. One long-running process, no localhost
// assumptions: binds 0.0.0.0:$PORT, path from $AGENT_PATH.
// Request flow: raw body -> HMAC verify (BEFORE JSON parse) -> route by
// `type` (preflight / task) -> deterministic decision -> local Groth16
// proof -> signed JSON response. Fail closed at every step.
// NEVER logs the secret, request bodies, or proofs (task_id + decision +
// reason + timing only).
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { HEADER, verifySignature, signBody } = require('./hmac');
const { TASK_TYPE, decide } = require('./decision');
const { buildCircuitInput, buildFallbackInput } = require('./encodings');
const { loadCircuit, proveDecision, verifyLocally } = require('./prover');
const { ReplayCache } = require('./replay');

const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
const MAX_BODY_BYTES = 1024 * 1024;

function resolveCircuitDir() {
  if (process.env.CIRCUIT_DIR) return process.env.CIRCUIT_DIR;
  // Repo layout: <root>/circuits. Workspace layout: <workspace>/circuits.
  for (const cand of [path.join(__dirname, '..', 'circuits'),
                      path.join(__dirname, '..', '..', 'circuits')]) {
    if (fs.existsSync(path.join(cand, 'gatekeeper.wasm'))) return cand;
  }
  return path.join(__dirname, '..', 'circuits');
}

function config() {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) throw new Error('AGENT_GAMES_HMAC_SECRET is not set — refusing to start');
  return {
    secret,
    port: Number(process.env.PORT || 3000),
    agentPath: process.env.AGENT_PATH || '/agent',
    circuitDir: resolveCircuitDir(),
    verifySelf: process.env.VERIFY_SELF !== '0',
  };
}

function sendJson(res, status, obj, secret) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (secret) headers[HEADER] = signBody(secret, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(task, ctx) {
  const { circuit, replayCache, verifySelf } = ctx;
  const outcome = decide(task, { replayCache });
  const base = {
    decision: outcome.decision,
    reason_code: outcome.reason_code,
    proof_tx: task.input ? task.input.proof_tx : null,
    task_id: task.task_id || null,
  };
  if (outcome.proofMode === 'none') {
    // Agent-side REJECT on a circuit-valid task: no valid proof exists.
    console.log(`[task ${task.task_id}] ${outcome.decision} ${outcome.reason_code} (no proof: agent-side check)`);
    return { ...base, proof: null, public_signals: null };
  }
  try {
    const circuitInput = outcome.proofMode === 'fallback-inputs'
      ? buildFallbackInput(task)
      : buildCircuitInput(task, outcome.decision);
    const { proof, publicSignals, proveMs } = await proveDecision(circuit, circuitInput);
    if (verifySelf) {
      const ok = await verifyLocally(circuit, proof, publicSignals);
      if (!ok) {
        console.error(`[task ${task.task_id}] self-verify FAILED, sending proof:null`);
        return { ...base, proof: null, public_signals: null, proof_error: true };
      }
    }
    console.log(`[task ${task.task_id}] ${outcome.decision} ${outcome.reason_code || ''} prove=${proveMs}ms`);
    return { ...base, proof, public_signals: publicSignals };
  } catch (e) {
    // Proving must not fail for consistent decisions; if it does, fail
    // closed with an honest REJECT and no fabricated proof.
    console.error(`[task ${task.task_id}] prove error: ${String(e.message || e).slice(0, 200)}`);
    return { ...base, decision: 'REJECT', reason_code: 'PROOF_ERROR', proof: null, public_signals: null };
  }
}

async function handleAgent(req, res, ctx) {
  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    res.writeHead(413); res.end(); return;
  }
  // HMAC BEFORE parsing. 401 reveals nothing beyond the failure.
  if (!verifySignature(ctx.secret, raw, req.headers[HEADER])) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'bad signature' }));
    return;
  }
  let msg;
  try {
    msg = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, { error: 'bad json' }, ctx.secret); return;
  }
  if (msg && msg.type === PREFLIGHT_TYPE) {
    sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, ctx.secret);
    return;
  }
  if (msg && msg.type === TASK_TYPE) {
    const out = await handleTask(msg, ctx);
    sendJson(res, 200, out, ctx.secret);
    return;
  }
  sendJson(res, 400, { error: 'unknown type' }, ctx.secret);
}

function main() {
  const cfg = config();
  const circuit = loadCircuit(cfg.circuitDir);
  const ctx = { ...cfg, circuit, replayCache: new ReplayCache() };
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method === 'POST' && req.url === cfg.agentPath) {
      handleAgent(req, res, ctx).catch((e) => {
        console.error('handler error:', String(e.message || e).slice(0, 200));
        if (!res.headersSent) { res.writeHead(500); res.end(); }
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  server.listen(cfg.port, '0.0.0.0', () => {
    console.log(`gatekeeper listening on 0.0.0.0:${cfg.port}${cfg.agentPath} (verifySelf=${cfg.verifySelf})`);
  });
}

if (require.main === module) main();
module.exports = { handleTask, handleAgent, config };
