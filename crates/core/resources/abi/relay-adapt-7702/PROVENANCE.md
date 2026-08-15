# RelayAdapt7702 ABI Evidence

These files are source-visible compatibility evidence for RelayAdapt7702. The
cited `UNLICENSED` source and tests provide citation-only behavioral context,
while the MIT npm ABI snapshots remain the normative implementation and
redistribution authority. Deployment mapping is unproven; these files are not
a source-code copy, deployment-safety audit, or proof of exact compiled
equivalence.

## Package

- Package: `@railgun-community/engine`
- Version: `9.7.0-rc.0`
- Integrity: `sha512-68mjGZAWNIblnGWIb/ISDLc0BIdM9xVOnmh1No/o0tLYlZWHpiFjc4lIxWhA4v57Z0+zalzXWiN1/zWGh7Wihg==`
- Reference CLI branch: `feat/7702-integration-base`
- Reference CLI commit: `5c8b5a78e52bbf21d5b5bd79c0c6b44b974e0881`
- Extraction and revalidation date: `2026-08-11`

## ABI Snapshots

| File | Package source path | SHA-256 |
| --- | --- | --- |
| `RelayAdapt7702.json` | `@railgun-community/engine/dist/abi/V2/RelayAdapt7702.json` | `0d2beba55d192224a298e39f660fe4927514a4f6bc65de406848f51cd3c3e8ec` |
| `RelayAdapt7702_Legacy_PreExecuteNonce.json` | `@railgun-community/engine/dist/abi/V2/RelayAdapt7702_Legacy_PreExecuteNonce.json` | `b49258eecc5dec2445f24d58a6965691d47232042ee2072b4e6274011732ea9e` |

The snapshots were copied byte-for-byte from the installed package at
`/media/psf/git/railgun/terminal-wallet-cli/node_modules/@railgun-community/engine`.

## License

- License file: `LICENSE-MIT`
- Source: `/media/psf/git/railgun/terminal-wallet-cli/node_modules/@railgun-community/engine/LICENSE`
- License: MIT
- Attribution: Copyright (c) 2022 RAILGUN Project Contributors
- SHA-256: `4529c1c9f6971d3c8d5aa2f4d101a45413233ab4199af02f15d2d2dcc1b6c6bf`

## Evidence Matrix

| Evidence class | Status and permitted use |
| --- | --- |
| MIT npm ABI authority | The current and legacy ABI snapshots are normative implementation and redistribution evidence. |
| UNLICENSED behavioral citation | Current source and test inspection only. No copying, vendoring, cloning, or compiling, and no source-derived committed fixtures. |
| Deployment mapping | Bytecode, deployed address, immutable values, and exact compiled equivalence are unproven. |

## Source Citation

- Repository: `Railgun-Privacy/contract`
- Branch: `zy0n/7702-relay-adapt`
- Signed head commit: `1ea5e472867df1a14975a1ee5bf43dac21b89bde`
- Source: `contracts/adapt/RelayAdapt7702.sol` blob `4525a3a0dba730accf4c7834cb88e6c83f959da4`
- Test: `test/adapt/relayAdapt7702.ts` blob `f3f7f130d463f971495ee41e1c816aef963ef2a8`
- The source/package declares `UNLICENSED`.
- The branch is unprotected; there is no PR, no commit statuses, and no check runs.
- The source is absent from `main`.

## Inspection Result

- By inspection only, the current package ABI function/tuple surface matches the current source citation.
- The exact legacy package ABI has no clean committed source mapping.
- Behavioral evidence only: the current source has one storage nonce shared by `execute` and `multicall`, distinct `Execute`/`Multicall` EIP-712 typehashes under the same domain, and no implication that wallet Multicall construction or signing is supported.
