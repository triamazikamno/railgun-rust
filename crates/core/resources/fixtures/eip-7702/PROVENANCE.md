# EIP-7702 Fixture Input Provenance

These are deterministic test-only inputs selected locally for later static
compatibility vectors. They are not upstream outputs, cryptographic proof
vectors, deployment safety evidence, or source-code audit results.

## Selection

- Selected and implementation-start revalidated: `2026-08-11`
- Input file: `inputs.json`
- Input file SHA-256: `3fda1c2ab1fd1b9523a11e9f9f1c0d8ca13afaa005c7a6536ed92cac7cd566ac`
- Fixture inputs are committed independently of the reference checkout.
- The cited `UNLICENSED` source/tests were inspected separately as citation-only behavioral evidence.
- No source/test content was copied, vendored, cloned, compiled, or used to derive any fixture, vector, or value.
- See [RelayAdapt7702 ABI provenance](../../abi/relay-adapt-7702/PROVENANCE.md) for the pinned source citation and evidence classification; this file does not duplicate that matrix.
- Runtime tests must not require Node, npm, or the reference checkout.

## Frozen RC Packages

| Package | Version | Integrity |
| --- | --- | --- |
| `@railgun-community/engine` | `9.7.0-rc.0` | `sha512-68mjGZAWNIblnGWIb/ISDLc0BIdM9xVOnmh1No/o0tLYlZWHpiFjc4lIxWhA4v57Z0+zalzXWiN1/zWGh7Wihg==` |
| `@railgun-community/shared-models` | `8.1.0-rc.1` | `sha512-cHT1kRtReRYbNWc5ynR6QW/OEqkqpuJcjzUVo0SCOMFb4ynbdHf+cynis85SiuaofnU+52EuWB+j/CvQqPWkFw==` |
| `@railgun-community/wallet` | `10.10.0-rc.1` | `sha512-+Std8YOL4DNVGqFh+asq9Npmo0WotGvsCXN+nhUBoN/VchLCV8iDgbS/O9PncTofcr+uwhewfyPTihpdEGo2HQ==` |
| `@railgun-community/waku-broadcaster-client-node` | `9.2.0-rc.2` | `sha512-+N+8qLsPeJgB7X6+23q5Ki/L3Ky7WpD4cYWXkQgXAMs/QrvK2hBeusP0PEaA9hVT1aoMe/4uDqu6CdbObmj5Kg==` |
| `ethers` | `6.14.3` | `sha512-qq7ft/oCJohoTcsNPFaXSQUm457MA5iWqkf1Mb11ujONdg7jBI6sAOrHaTi3j0CBqIGFSCeR/RMc+qwRRub7IA==` |

## Reference Baseline

- Reference checkout: `/media/psf/git/railgun/terminal-wallet-cli`
- Branch: `feat/7702-integration-base`
- Commit: `5c8b5a78e52bbf21d5b5bd79c0c6b44b974e0881`
- The reference worktree was dirty only in its pre-existing `package-lock.json`;
  that modification was not changed.

## ABI Evidence

| Artifact | Source path | SHA-256 |
| --- | --- | --- |
| Current nonce-aware ABI | `@railgun-community/engine/dist/abi/V2/RelayAdapt7702.json` | `0d2beba55d192224a298e39f660fe4927514a4f6bc65de406848f51cd3c3e8ec` |
| Legacy pre-execute-nonce ABI | `@railgun-community/engine/dist/abi/V2/RelayAdapt7702_Legacy_PreExecuteNonce.json` | `b49258eecc5dec2445f24d58a6965691d47232042ee2072b4e6274011732ea9e` |

## Implementation Evidence

| File | SHA-256 |
| --- | --- |
| `shared-models/dist/models/network-config.js` | `74fe2cbd3979e2945c971bb8857f974bdb309aa0e99eabefcb08d760ba93c569` |
| `wallet/dist/services/transactions/tx-shield-base-token-7702.js` | `c72753e7d6176d7572a1f91ff4088279de1a28d0fa7e71e7b50771fbce039615` |
| `wallet/dist/services/transactions/tx-unshield-base-token-7702.js` | `ea98b12c8207159dd3e7c85abcc77b74411d1d1711e65b5ccc2ca8f371083fef` |
| `waku-broadcaster-client-node/dist/transact/broadcaster-transaction.js` | `12bbc9993629db348175f997283bae2aedbbf23d6e42e962950e4321851d2c1d` |

## Fixture Rules

- The authority and wrong-authority private keys, and the encryption/shared
  key, are deterministic TEST ONLY material and are explicitly non-secret.
- The nested transaction is labeled ABI encoding only and makes no claim of
  proof validity or cryptographic validity.
- The baseline contains no recovery planner or fixed-index inputs.
- Concrete fixture inputs were selected locally and are not upstream outputs.
- Any update requires an explicit provenance update and review.

## Static Compatibility Outputs

The following files are committed cross-language outputs generated from the
deterministic inputs above:

| File | SHA-256 | Contents |
| --- | --- | --- |
| `expected-vectors.json` | `ec4bb694caa723b0168b3e46541f1b0dc1db2ac91133e96ad5cb3e006b71437d` | Current and legacy execute selectors, payload hashes, authorization and Execute EIP-712 signatures/digests/calldata, test-only Multicall domain vectors, nonce separation, and empty-batch vectors |
| `wire.json` | `0d3f4d4fdb9bb92356fe541af90d0bc64eb477e1ca721b0bc3c3c0c4db7d97dd` | Strict TX7702 broadcaster request in the reviewed runtime JSON shape |
| `wire-cases.json` | `04ed5f2b57745ef217cc4b431713036478f95337b3baf7e58e1ca60b25de3d9e` | Named malformed and semantic wire boundary cases |
| `encrypted-envelope.json` | `4d418fa6f152958566cc5fb0adb66385365e246ee8bf63b26a57c19bc2395683` | One static AES-256-GCM encrypted envelope and its expected plaintext |

Generation was performed once in the reviewed reference environment with the
already-installed packages and Ethers baseline:

```text
node /tmp/opencode/generate_eip7702_vectors.cjs
```

The generator used these MIT package APIs and source paths without adding any
runtime dependency to Rust tests:

- `@railgun-community/engine/dist/transaction/relay-adapt-7702-signature.js`: `getExecutePayloadHash`, `signExecutionAuthorization`, and `RelayAdapt7702ExecutionType`.
- `@railgun-community/engine/dist/transaction/eip7702.js`: Ethers-native `signEIP7702Authorization` behavior through `Wallet.authorize`.
- `@railgun-community/engine/dist/contracts/relay-adapt/relay-adapt-7702-helper.js`: the reviewed Execute encoding shape.
- `@railgun-community/wallet/dist/services/railgun/wallets/relay-adapt-7702-execution.js`: current/legacy Execute selection and encoding shape.
- `@railgun-community/waku-broadcaster-client-node/dist/transact/broadcaster-transaction.js`: TX7702 base fields, decimal fee fields, nested authorization, and omission of `minGasPrice`.
- `@railgun-community/engine/dist/utils/ecies.js` and `dist/utils/encryption/aes.js`: `encryptJSONDataWithSharedKey` and AES-256-GCM envelope layout.
- Ethers `6.14.3`: `Wallet.authorize`, `TypedDataEncoder`, `Interface`, signature recovery, and RLP authorization hashing.

The package versions, npm integrities, reference checkout, and reference commit
are the frozen values in the tables above and in `Reference Baseline`; no
package was installed or changed. The authority keys and shared encryption key
are deterministic test-only material explicitly marked non-secret in
`inputs.json`. The encrypted fixture uses that existing shared test key and is
not a production secret.

## Compatibility Test Matrix

The static tests bind the new outputs to the existing Rust implementation while
retaining the broader regressions already present:

| Evidence | Rust test coverage |
| --- | --- |
| Execute ABI/hash/signature/recovery and current-versus-legacy no fallback | `eip7702::tests::static_mit_vectors_match_rust_abi_hash_signature_and_recovery_paths`; existing `execute_encoding_is_version_exact_without_fallback`, `parse_transact_envelope_preserves_7702_version_data_without_fallback`, and `current_execute_and_multicall_signatures_are_type_isolated` |
| Empty-batch selector parsing and `MissingTransactions` | Existing `parse_transact_envelope_classifies_empty_batches_by_selector` and `parse_transact_returns_missing_transactions_for_empty_batches` |
| TX7702 wire shape, required fields, decimal/parity boundaries, semantic mismatch, and no downgrade | `transact::tests::static_tx7702_wire_and_encryption_fixtures_match_rust_boundaries`; existing strict TX7702 boundary, validation, and dispatch tests |
| Package encryption/decryption and legacy absent/COMMON behavior | The static encryption assertion in the test above; existing `strict_tx7702_public_encryption_roundtrips_validated_plaintext_and_dispatches_strictly` and `legacy_absent_and_common_requests_keep_legacy_decrypt_and_dispatch_behavior` |
| Downstream planner and sync metadata compatibility | Existing `relay_adapt_7702_planner_fixture_is_static_and_provenance_bound`, `relay_adapt_7702_public_native_shield_has_exact_empty_batch_recipe`, `relay_adapt_7702_private_unshield_preserves_metadata_and_binds_authority_before_proof`, and sync-service `four_chain_defaults_use_reviewed_current_relay_adapt_7702_addresses`, `history_order_does_not_infer_execution_version`, and `explicit_current_and_legacy_metadata_are_retained` |

These files are compatibility evidence only. They do not claim deployment
bytecode, immutable values, source or deployment safety, implementation
identity, address mapping, cryptographic proof validity, or validity of the
dummy Railgun transaction. The cited `Railgun-Privacy/contract` source and
tests are `UNLICENSED` citation-only material: they were inspected separately
as behavioral evidence. No source/test content was copied, vendored, cloned,
compiled, or used to derive any fixture, vector, or value.
Any change to these fixtures requires explicit review of the provenance and
cross-language outputs.
