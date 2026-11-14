// Keccak-256 test vectors (empty, short, multi-block). Run: node test/test-keccak.js
'use strict';
const assert = require('assert');
const { keccak256 } = require('../src/keccak');

const VECTORS = [
  ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
  ['abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
  ['hello world', '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad'],
];

let passed = 0;
for (const [input, expected] of VECTORS.slice(0, 3)) {
  const got = keccak256(input).toString('hex');
  assert.strictEqual(got, expected, `keccak256(${JSON.stringify(input)})`);
  passed++;
}
// Multi-block determinism (200 bytes > 136-byte rate): same input, same output,
// and different from the single-block case.
const a = keccak256('a'.repeat(200)).toString('hex');
const b = keccak256(Buffer.from('a'.repeat(200))).toString('hex');
assert.strictEqual(a, b, 'string vs Buffer input must agree');
assert.strictEqual(a, '96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d');
passed++;
console.log(`keccak: ${passed}/${VECTORS.length + 1} vectors PASS`);
