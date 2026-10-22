## 22-10-2026

- `erc1967ProxyCode`: Match the `ERC1967Clones` proxy bytecode from OpenZeppelin Contracts `v5.7.0`, used by `OpenAccountFactory` to predict account addresses.

## 31-07-2026

- Add `packages/sdk/src/signers/`: composable signer abstraction that produces the on-chain envelopes the accounts library already knows how to verify.
  - `toSigner(LocalAccount | WebAuthnAccount) → Signer` — normalizes viem's account shapes, unwrapping `WebAuthnAccount`'s discriminated return object so downstream code only sees `Hex`.
  - `toERC7913Signer(inner, { verifier, key } | { address }) → ERC7913Signer` — wraps the inner signer's output as `abi.encode(bytes signer, bytes rawSig)` per ERC-7913. Returns a signer that exposes `signerBytes` and `unwrap()` (which returns the inner signer for further composition).
  - `toCrossChainSigner(inner, config) → CrossChainSigner` — wraps the inner signer's output as an ERC-7964 cross-chain envelope. Selects the current chain via `currentChainIndex` or `chainId` (first-match DFS lookup for a canonical `chainId` field per the ERC-7964 §Message Array Encoding amendment). Supports optional `domain.verifyingContract` and auto-computes the ERC-5267 `fields` byte. Config is snapshotted at construction, so post-construction mutations of `operations` / `domain` / `message` are ignored. The returned signer also exposes `signCrossChainEnvelopes()` for the "one inner signature, N envelopes" dispatch pattern. `signMessage` throws (spec is EIP-712-only).
  - `signCrossChainEnvelopes(inner, config)` — standalone helper equivalent to the method on `CrossChainSigner`.
  - `toMultisigner([{ signer, signerBytes } | ERC7913Signer, ...]) → Signer` — packs `abi.encode(bytes[] signers, bytes[] signatures)` for `Multisig.tryDecodeMultisignatureCalldata` and the ERC-7579 multisig validators. Sorts pairs by `keccak256(signerBytes)` to match `SignatureChecker.areValidSignaturesNow`'s efficient-dedup path. ERC-7913-wrapped inputs are unwrapped via `.unwrap()` so the multisig envelope carries raw inner signatures rather than nested envelopes.
- Widen the `signer` parameter of `toERC7579Account` and `toOpenAccount` to accept the SDK's `Signer` alongside viem's `LocalAccount | WebAuthnAccount`. Existing call sites keep working — `Signer` is a structural subset of `LocalAccount`.

## 27-02-2026

- `toOpenAccount` now requires a `validator: Address` parameter identifying the ERC-7579 validator module that authorises the signer. This parameter drives two automatic behaviors:
  - **ERC-1271 routing**: `signMessage` and `signTypedData` prepend `validator` (20 bytes) to the inner signature so that the account's `isValidSignature` can extract and route to the correct module without any manual encoding.
  - **UserOp nonce routing**: `getNonce` encodes `validator` in the upper 20 bytes of the 24-byte nonce key. An optional user-supplied `key` (at most 4 bytes) occupies the lower bytes, allowing parallel nonce sequences per validator. Passing a `key` larger than 4 bytes throws at runtime.
- `toERC7579Account` no longer overrides `getNonce`. It now relies on the default nonce implementation provided by Viem's `toSmartAccount`, which reads from the entry point without any validator encoding. Applications that need validator-aware nonces should use `toOpenAccount`, or pass a custom `getNonce` override directly to `toERC7579Account`.

## 26-02-2026

- Add `toOpenAccount`: a `SmartAccount` factory for the `OpenAccount` contract. Supports two modes — factory-based deployment (deterministic CREATE2 address) and connecting to an already-deployed account (with on-chain `accountId` validation).
- Add `toERC7579Account`: a lower-level `SmartAccount` factory for any ERC-7579 account, accepting caller-supplied `getAddress` and `getFactoryArgs` callbacks. The `signer` parameter accepts both a `LocalAccount` (ECDSA) and a `WebAuthnAccount` (passkey).
- Rename `account.ts` to `erc7579-account.ts` to match the exported function name.
- Add `erc1967.utils.ts`: helper that returns the ERC-1967 proxy creation bytecode for a given implementation address, used during counterfactual address derivation.
- Add `erc7579.actions.ts`: Viem client extension (`erc7579Actions`) providing typed action methods — `accountId`, `installModules`, `uninstallModules`, `isModuleInstalled`, `supportsExecutionMode`, `supportsModule`, and `execute` — for interacting with ERC-7579 accounts through a bundler client.
- Expand `erc7579.utils.ts` with `encodeCalls` / `decodeCalls` for automatic single/batch call encoding and `encodeMode` / `decodeMode` for execution mode packing.
- Replace plain-object constants with TypeScript `enum`s in `erc7579.utils.ts`: `ModuleTypes`, `ExecutionTypes`, and `CallTypes` are now proper enums while retaining string-literal union aliases (`ModuleType`, `ExecType`, `CallType`) for type-safe string input.

## 20-10-2025

- Add `erc7579.utils.ts`: Utility functions for encoding and decoding ERC-7579 modular smart account calls, execution batching, delegatecall, and execution mode packing/unpacking.
