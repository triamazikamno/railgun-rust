// Generates executor.json: public compatibility fixtures produced by the
// reference JavaScript SDK. Never supply a real wallet to this script, and never
// fund the derived addresses. The synthetic transactions carry dummy proofs that
// exercise ABI encoding only and cannot authorize a real RAILGUN spend.
//
// Reference: Terminal Wallet CLI revision 806e804798fc48799c8dc4bf8a7884cdc29aee5d,
// which pins wallet 10.10.0-rc.1 and ethers 6.14.3. Wallet uses engine 9.7.0-rc.0.
// The nonce-bearing contract is RelayAdapt7702 at contract revision
// 1ea5e472867df1a14975a1ee5bf43dac21b89bde.
//
// Download the exact registry archives without installing packages or running
// package scripts:
//   https://registry.npmjs.org/ethers/-/ethers-6.14.3.tgz
//   https://registry.npmjs.org/@railgun-community/engine/-/engine-9.7.0-rc.0.tgz
//
// Extract these archive members into one directory under the local names the
// `checksums` table below expects:
//   ethers  package/dist/ethers.umd.js
//           -> ethers.umd.js
//   engine  package/dist/key-derivation/ephemeral-key.js
//           -> ephemeral-key.js
//   engine  package/dist/transaction/relay-adapt-7702-signature.js
//           -> relay-adapt-7702-signature.js
//   engine  package/dist/abi/typechain/factories/RelayAdapt7702__factory.js
//           -> engine-package_dist_abi_typechain_factories_RelayAdapt7702__factory.js
//   engine  package/dist/abi/V2/RelayAdapt7702_Legacy_PreExecuteNonce.json
//           -> RelayAdapt7702_Legacy_PreExecuteNonce.json
//
// From the workspace root run
//   node crates/core/tests/fixtures/generate-executor.cjs <directory>
// and compare stdout with executor.json. Every input is SHA-256 checked before
// it is loaded, then run unmodified in a VM context with no filesystem, process,
// provider, or network APIs. Multicall hashes use the pinned contract's
// abi.encode(bool, Call[], uint256) definition. historicalCalldata is a decoding
// fixture, not a valid historical execution signature. Authorization fixtures
// include SDK yParity and chain-zero input; wallet-generated authorizations must
// still use their selected chain.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const assert = require('node:assert/strict');

const directory = process.argv[2];
if (!directory) throw new Error('Provide the reference download directory');
const sandbox = vm.createContext({ TextEncoder, TextDecoder });
vm.runInContext('globalThis.self = globalThis', sandbox);
const checksums = {
  'ethers.umd.js': 'aadcb8a6122198b0c0aa2c5191efaa23e84060ec6ab300093dad619e4bdc21e5',
  'ephemeral-key.js': '8617d5a996012a549430a2e74e59ad420c8e55ea10caef92a50c48e52f397509',
  'relay-adapt-7702-signature.js': 'e800cb7606bcb739b8dcd25979bbb835be9e4d184bf4eb795355206bfa62fef7',
  'engine-package_dist_abi_typechain_factories_RelayAdapt7702__factory.js': '4b5ff2ace8d8c665542e1c671114c7d6306f765fad070585c287684399e4059a',
  'RelayAdapt7702_Legacy_PreExecuteNonce.json': 'b49258eecc5dec2445f24d58a6965691d47232042ee2072b4e6274011732ea9e',
};
function read(name) {
  const source = fs.readFileSync(path.join(directory, name));
  if (checksums[name]) {
    assert.equal(createHash('sha256').update(source).digest('hex'), checksums[name]);
  }
  return source.toString();
}
vm.runInContext(read('ethers.umd.js'), sandbox);
const ethers = sandbox.ethers;
function load(name, imports) {
  const factory = vm.runInContext(`(function(exports, require) {\n${read(name)}\n})`, sandbox);
  const exports = {};
  factory(exports, (id) => {
    assert.ok(Object.hasOwn(imports, id), `Unexpected import: ${id}`);
    return imports[id];
  });
  return exports;
}
const factory = load('engine-package_dist_abi_typechain_factories_RelayAdapt7702__factory.js', { ethers });
const reference = load('relay-adapt-7702-signature.js', {
  ethers,
  '../abi/typechain/factories/RelayAdapt7702__factory': factory,
});
const derivation = load('ephemeral-key.js', { ethers });
const iface = factory.RelayAdapt7702__factory.createInterface();
const legacy = new ethers.Interface(JSON.parse(read('RelayAdapt7702_Legacy_PreExecuteNonce.json')));
const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const cases = [
  { walletIndex: 0, chainId: 1, index: 0, passphrase: '' },
  { walletIndex: 1, chainId: 1, index: 0, passphrase: '' },
  { walletIndex: 0, chainId: 56, index: 1, passphrase: '' },
  { walletIndex: 7, chainId: 137, index: 1000064, passphrase: 'TREZOR' },
  { walletIndex: 0, chainId: 42161, index: 2147483647, passphrase: 'e\u0301clair' },
  { walletIndex: 0, chainId: 1, index: 0, passphrase: 'TREZOR' },
];
const address = (byte) => `0x${byte.repeat(20)}`;
const hash = (byte) => `0x${byte.repeat(32)}`;

async function main() {
  const derivations = cases.map((input) => {
    const wallet = derivation.deriveEphemeralWallet(mnemonic, input.walletIndex, BigInt(input.chainId), input.index, input.passphrase);
    return { ...input, path: wallet.path, address: wallet.address };
  });
  const wallet = derivation.deriveEphemeralWallet(mnemonic, 0, 1n, 0, '');
  const transactions = [{
    proof: { a: { x: 1n, y: 2n }, b: { x: [3n, 4n], y: [5n, 6n] }, c: { x: 7n, y: 8n } },
    merkleRoot: hash('11'), nullifiers: [hash('22'), hash('23')], commitments: [hash('33')],
    boundParams: {
      treeNumber: 2, minGasPrice: 1000000000n, unshield: 1, chainID: 1,
      adaptContract: wallet.address, adaptParams: ethers.ZeroHash,
      commitmentCiphertext: [{
        ciphertext: [hash('44'), hash('45'), hash('46'), hash('47')],
        blindedSenderViewingKey: hash('55'), blindedReceiverViewingKey: hash('66'),
        annotationData: '0x010203', memo: '0x04050607',
      }],
    },
    unshieldPreimage: { npk: hash('77'), token: { tokenType: 0, tokenAddress: address('88'), tokenSubID: 0 }, value: 123456789n },
  }];
  const calls = [
    { to: wallet.address, data: iface.encodeFunctionData('unwrapBase', [123456n]), value: 0n },
    { to: address('99'), data: '0x12345678', value: 123456n },
  ];
  const actionData = { requireSuccess: true, minGasLimit: 234567n, calls };
  const domain = { name: 'RelayAdapt7702', version: '1', chainId: 1, verifyingContract: wallet.address };
  const executions = [];
  for (const nonce of [0n, 9n]) {
    const details = { executionType: reference.RelayAdapt7702ExecutionType.ExecuteWithNonce, executeNonce: nonce };
    const payloadHash = reference.getExecutePayloadHash(transactions, actionData, details);
    const signature = await reference.signExecutionAuthorization(wallet, transactions, actionData, 1n, details);
    const types = { Execute: [{ name: 'payloadHash', type: 'bytes32' }] };
    assert.equal(ethers.verifyTypedData(domain, types, { payloadHash }, signature), wallet.address);
    executions.push({ nonce, payloadHash, signingHash: ethers.TypedDataEncoder.hash(domain, types, { payloadHash }), signature,
      calldata: iface.encodeFunctionData('execute', [transactions, actionData, nonce, signature]) });
  }
  const nonce = 9n;
  const multicallPayloadHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bool', 'tuple(address to,bytes data,uint256 value)[]', 'uint256'], [true, calls, nonce]));
  const multicallTypes = { Multicall: [{ name: 'payloadHash', type: 'bytes32' }] };
  const multicallSignature = await wallet.signTypedData(domain, multicallTypes, { payloadHash: multicallPayloadHash });
  const delegate = '0x05ae73c5925d843864ae6f261f3175de2ebcd963';
  const authorizations = [];
  for (const chainId of [0n, 1n]) {
    const auth = await wallet.authorize({ address: delegate, chainId, nonce: 0 });
    authorizations.push({ address: auth.address, chainId, nonce: auth.nonce,
      signature: { yParity: auth.signature.yParity, r: auth.signature.r, s: auth.signature.s } });
  }
  const fixture = {
    reference: { engine: '9.7.0-rc.0', wallet: '10.10.0-rc.1', ethers: '6.14.3', contract: '1ea5e472867df1a14975a1ee5bf43dac21b89bde' },
    mnemonic, derivations, executor: wallet.address, chainId: 1, transactions, actionData, executions,
    historicalCalldata: legacy.encodeFunctionData('execute', [transactions, actionData, executions[0].signature]),
    multicall: { nonce, payloadHash: multicallPayloadHash, signingHash: ethers.TypedDataEncoder.hash(domain, multicallTypes, { payloadHash: multicallPayloadHash }),
      signature: multicallSignature, calldata: iface.encodeFunctionData('multicall', [true, calls, nonce, multicallSignature]) },
    authorizations,
  };
  process.stdout.write(`${JSON.stringify(fixture, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2)}\n`);
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
