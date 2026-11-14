// HMAC-SHA256 request/response signing.
//
// Header: x-agent-games-signature (per the /build starter prompt: "compute
// the HMAC over the RAW request body and compare it to the
// x-agent-games-signature header BEFORE parsing JSON").
//
// [ASSUMPTION S1] Signature FORMAT is not specified in the published blocks.
// Outbound: lowercase hex digest, no prefix (the most common convention).
// Inbound verification accepts: raw hex, "sha256=<hex>", and base64 —
// compared in constant time after decoding to bytes. If practice shows the
// platform uses exactly one format, narrow this to that format.
// The secret is NEVER logged; only presence/absence is ever reported.
'use strict';
const crypto = require('crypto');

const HEADER = 'x-agent-games-signature';

function computeHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function decodeSignature(sig) {
  const s = String(sig).trim();
  if (s.startsWith('sha256=')) return Buffer.from(s.slice(7), 'hex');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return Buffer.from(s, 'hex');
  // Fall back to base64.
  const b = Buffer.from(s, 'base64');
  if (b.length === 0) throw new Error('empty signature');
  return b;
}

// Constant-time comparison of the presented signature against the expected
// HMAC of the raw body. Returns false (never throws) on any mismatch.
function verifySignature(secret, rawBody, presented) {
  if (!secret || !presented) return false;
  try {
    const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
    const got = decodeSignature(presented);
    if (got.length !== expected.length) return false;
    return crypto.timingSafeEqual(got, expected);
  } catch {
    return false;
  }
}

function signBody(secret, rawBody) {
  return computeHex(secret, rawBody);
}

module.exports = { HEADER, computeHex, verifySignature, signBody };
