// Independently verifies synthetic PPOI fixtures with snarkjs 0.7.6.
// Download https://registry.npmjs.org/snarkjs/-/snarkjs-0.7.6.tgz as data and
// extract package/build/snarkjs.js without installing or running package scripts.
// The registry archive integrity is:
// sha512-4uH1xA5JzVU5jaaWS2fXej3+RC6L5Erhr6INTJtUA27du4Elbh4VXCeeRjB4QiwL6N6y7SNKePw5prTxyEf4Zg==
//
// Run from the workspace root:
//   node crates/core/tests/fixtures/verify-ppoi.cjs <snarkjs.js> <fixture-directory>
//
// The pinned reference bundle runs unmodified in a VM context without filesystem,
// process, worker, or network APIs. Only public synthetic fixture data is supplied.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash, webcrypto } = require('node:crypto');

const [referencePath, fixtureDirectory] = process.argv.slice(2);
assert.ok(referencePath && fixtureDirectory, 'Provide snarkjs.js and fixture directory');
const reference = fs.readFileSync(referencePath);
assert.equal(
  createHash('sha256').update(reference).digest('hex'),
  '4816f1229755d93d7235eec73323374978f847b6acb40a56bf4a31d370932e05',
  'Unexpected snarkjs reference bundle',
);
const context = vm.createContext({
  TextEncoder, TextDecoder, setTimeout, clearTimeout, atob, btoa, crypto: webcrypto,
});
vm.runInContext(reference.toString(), context, { filename: 'snarkjs-0.7.6.js' });

async function main() {
  for (const [fixtureName, variant, keyHash] of [
    ['ppoi_3x3.json', 'POI_3x3', 'e6ac836dcabb1d70f3924f172d8edd52e09269f87a0d5b977650c63a8070bd31'],
    ['ppoi_3x3_two_outputs.json', 'POI_3x3', 'e6ac836dcabb1d70f3924f172d8edd52e09269f87a0d5b977650c63a8070bd31'],
    ['ppoi_13x13_unshield.json', 'POI_13x13', 'b939fbc34c9ba9cc294a8b5c1e72ddc4088e559d351dc4fab7b71234d34bbb17'],
  ]) {
    const fixture = JSON.parse(fs.readFileSync(path.join(fixtureDirectory, fixtureName)));
    const keyBytes = fs.readFileSync(path.join(__dirname, '../../resources/poi', variant, 'vkey.json'));
    assert.equal(createHash('sha256').update(keyBytes).digest('hex'), keyHash);
    const key = JSON.parse(keyBytes);
    const signals = fixture.snarkjs_public_signals;
    assert.equal(signals.length, key.nPublic);
    assert.equal(key.IC.length, signals.length + 1);
    assert.equal(await context.snarkjs.groth16.verify(key, signals, fixture.snarkjs_proof), true,
      `${fixtureName}: reference verification failed`);
    const changed = [...signals];
    changed[0] = (BigInt(changed[0]) + 1n).toString();
    assert.equal(await context.snarkjs.groth16.verify(key, changed, fixture.snarkjs_proof), false,
      `${fixtureName}: changed public signal was accepted`);
    console.log(`${fixtureName}: reference verification passed; changed signal rejected`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
