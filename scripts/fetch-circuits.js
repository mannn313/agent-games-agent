// Download the Gatekeeper circuit artifacts from the platform's public
// circuit endpoints into CIRCUIT_DIR (default: <repo-root>/circuits).
// Skips files already present with the expected byte size. Run as the
// `prestart` hook so deploys self-provision; artifacts are NOT committed.
'use strict';
const fs = require('fs');
const https = require('https');
const path = require('path');

const BASE = 'https://agentgames.zkverify.io/circuits';
const FILES = [
  ['gatekeeper.wasm', 1755820],
  ['gatekeeper_final.zkey', 309750],
];

const dir = process.env.CIRCUIT_DIR || path.join(__dirname, '..', 'circuits');

function download(url, dest, expectedSize) {
  return new Promise((resolve, reject) => {
    const tmp = dest + '.tmp';
    const file = fs.createWriteStream(tmp);
    https.get(url, { timeout: 60000 }, (res) => {
      if (res.statusCode !== 200) {
        file.destroy();
        fs.rmSync(tmp, { force: true });
        reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        return;
      }
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => {
          const size = fs.statSync(tmp).size;
          if (size !== expectedSize) {
            fs.rmSync(tmp, { force: true });
            reject(new Error(`${dest}: got ${size} bytes, expected ${expectedSize}`));
            return;
          }
          fs.renameSync(tmp, dest);
          resolve();
        });
      });
    }).on('error', (err) => {
      file.destroy();
      fs.rmSync(tmp, { force: true });
      reject(err);
    });
  });
}

async function main() {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, size] of FILES) {
    const dest = path.join(dir, name);
    if (fs.existsSync(dest) && fs.statSync(dest).size === size) {
      console.log(`circuits: ${name} already present (${size} bytes)`);
      continue;
    }
    console.log(`circuits: downloading ${name} ...`);
    await download(`${BASE}/${name}`, dest, size);
    console.log(`circuits: ${name} OK (${size} bytes)`);
  }
}

main().catch((err) => { console.error('circuits: FAILED:', err.message); process.exit(1); });
