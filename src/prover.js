// Local Groth16 proving with snarkjs: decision proofs for the Gatekeeper
// circuit + optional self-verification before responding.
// Proving time is sub-second locally (~0.3-0.4s on this VM); the platform
// allows 60s/task, so there is ample headroom.
'use strict';
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

let cached = null;

function loadCircuit(circuitDir) {
  if (cached && cached.dir === circuitDir) return cached;
  const wasmPath = path.join(circuitDir, 'gatekeeper.wasm');
  const zkeyPath = path.join(circuitDir, 'gatekeeper_final.zkey');
  if (!fs.existsSync(wasmPath)) throw new Error(`missing circuit artifact: ${wasmPath}`);
  if (!fs.existsSync(zkeyPath)) throw new Error(`missing circuit artifact: ${zkeyPath}`);
  cached = { dir: circuitDir, wasmPath, zkeyPath, vk: null };
  return cached;
}

async function getVk(circuit) {
  if (!circuit.vk) circuit.vk = await snarkjs.zKey.exportVerificationKey(circuit.zkeyPath);
  return circuit.vk;
}

// Returns { proof, publicSignals, proveMs }. Throws if the witness asserts
// (decision inconsistent with the circuit checks) — caller fails closed.
async function proveDecision(circuit, circuitInput) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, circuit.wasmPath, circuit.zkeyPath);
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}

async function verifyLocally(circuit, proof, publicSignals) {
  const vk = await getVk(circuit);
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { loadCircuit, getVk, proveDecision, verifyLocally };
