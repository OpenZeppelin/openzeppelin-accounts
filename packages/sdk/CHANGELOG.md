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
