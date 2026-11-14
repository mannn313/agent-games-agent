// In-memory proof_tx replay cache. Reuse/finality checks are agent-side
// (the circuit has no proof_tx signal). A proof_tx seen before — in ANY
// earlier task, regardless of that task's decision — marks the new task as
// a replay trap. Entries expire after REPLAY_TTL_MS so a stale cache can
// never permanently block a legitimate re-issue; the platform issues fresh
// proof_tx values per task, so TTL expiry is safe.
'use strict';

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const MAX_ENTRIES = 10000;

class ReplayCache {
  constructor(ttlMs = DEFAULT_TTL_MS) {
    this.ttlMs = ttlMs;
    this.seen = new Map(); // proof_tx (lowercased) -> first-seen epoch ms
  }

  // Returns true if proof_tx was already seen (replay). Otherwise records it
  // and returns false. Call BEFORE deciding: first sighting claims the slot.
  checkAndRecord(proofTx) {
    if (typeof proofTx !== 'string' || proofTx.length === 0) return false;
    const key = proofTx.toLowerCase();
    const now = Date.now();
    this._prune(now);
    if (this.seen.has(key)) return true;
    if (this.seen.size >= MAX_ENTRIES) this._prune(now, true);
    this.seen.set(key, now);
    return false;
  }

  has(proofTx) {
    if (typeof proofTx !== 'string') return false;
    this._prune(Date.now());
    return this.seen.has(proofTx.toLowerCase());
  }

  size() { this._prune(Date.now()); return this.seen.size; }

  _prune(now, forceOldest = false) {
    for (const [k, t] of this.seen) {
      if (now - t > this.ttlMs) this.seen.delete(k);
    }
    if (forceOldest && this.seen.size >= MAX_ENTRIES) {
      // Evict oldest 10% to bound memory.
      const keys = [...this.seen.keys()].slice(0, Math.floor(MAX_ENTRIES / 10));
      for (const k of keys) this.seen.delete(k);
    }
  }
}

module.exports = { ReplayCache };
