## 26-10-2026

- `ERC7579NativeSpender` and `ERC7579ERC20Spender`: Installed with a single `installModule(MODULE_TYPE_EXECUTOR, module, initData)` call. The executor-role `onInstall` installs the validator role through `executeFromExecutor` and then writes the spending policies. `initData` is `abi.encode(bytes sessionKeysInitData, bytes spendingInitData)`, where `sessionKeysInitData` is `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)` and `spendingInitData` is the previous executor bundle. Installing the module directly as a validator reverts with `ERC7579NativeSpenderInvalidInstallFlow` / `ERC7579ERC20SpenderInvalidInstallFlow`, and so does the executor install while the validator role is still installed. **Breaking change** to the install data layout.

## 22-10-2026

- Pin OpenZeppelin Contracts and OpenZeppelin Contracts Upgradeable to `v5.7.0`. `EIP712` domain names and versions must now fit in 31 bytes, and `ERC1967Clones` proxies use updated bytecode, which changes `OpenAccountFactory` account addresses.

## 22-07-2026

- Renamed `OpenAccountERC8043` to `AccountERC8043Upgradeable` and retargeted it to extend `AccountERC7579Upgradeable` directly, so the ERC-8043 init mode extension can be composed with any ERC-7579-based account instead of only `OpenAccount`.
- Added `ERC8043Utils` library exposing pure decoding and EIP-712 struct-hash helpers for ERC-8043 init mode payloads.

## 23-05-2026

- `ERC7579NativeSpender` and `ERC7579ERC20Spender`: Redesigned as session-key-driven spending policies. Both modules now extend `ERC7579SessionKeysValidator` and are installed under BOTH the validator (`MODULE_TYPE_VALIDATOR = 1`) and executor (`MODULE_TYPE_EXECUTOR = 2`) module types. Spending is gated by ERC-7913 session keys instead of `address spender`. **Breaking change** to all public surfaces (function signatures, install data layout, events, errors).
  - Install flow is split in two: the **first** `onInstall` call (validator role) accepts `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)` and registers session keys via `ERC7579SessionKeys-_addKeys`; the **second** call (executor role) accepts the spending-policy bundle and writes one row per `(key[, token], limit, renewPeriod)`. Reconfiguration is banned: subsequent `onInstall` calls revert with `AlreadyInstalled`. To change policies, uninstall and reinstall (which bumps the installation nonce and resets state).
  - ERC-1271 signing is disabled on both modules (`isValidSignatureWithSender` returns `0xffffffff`) so a spending session key cannot be repurposed to authorize arbitrary off-chain digests on behalf of the account.
  - `_validateUserOp` is overridden in both modules to enforce the `callData` shape: the user operation must call `IERC7579Execution.execute(CALLTYPE_SINGLE, encodeSingle(address(this), 0, transferFromOrBatchTransferFrom(...)))`, and the `key` parameter inside the inner call must match the key in `userOp.signature` (prevents one key's signature from charging another key's allowance).
- `ERC7579ERC20Spender`: A single session key can have spending policies for multiple tokens. The executor `initData` encodes `(bytes[] keys, address[] tokens, uint160[] limits, uint48[] renewPeriods)` and may repeat the same key across rows. Adds `tokensCount(account)` and `tokens(account, startIdx, endIdx)` accessors.
- `ERC7579ERC20Spender`: `removeKeys` clears the session key's validity range but does NOT clear `(key, token)` spending configs. Re-registering the same key bytes via `addKeys` inherits the previously-stored configs; use `addKeysWithConfig` to overwrite with a fresh policy.
- `ERC7579NativeSpender`: `removeKeys` clears both the validity range and the per-key config; spending history at the historical `start` is preserved and readable via the explicit-start overload of `spent`.

## 24-03-2026

- `ERC7579ERC20Spender`: Fixed return value validation in `_transferFrom` and `_batchTransferFrom` to correctly accept non-standard ERC20 tokens that return no data (e.g. old USDT-style tokens). Previously the check would incorrectly revert for such tokens due to reading the length field of the `bytes memory` returndata as the boolean value.
- `ERC7579ERC20Spender`: Replaced raw returndata bubbling on failed transfers with the new `ERC7579ERC20SpenderFailedTransfer(address token)` custom error. Since `EXECTYPE_DEFAULT` already propagates EVM-level reverts, only the `false`-return case needed explicit handling.
- `ERC7579DelayedExecutor`: Renamed `minSetback` to `delayChangeWindow` to better reflect its dual role as a cap on delay increases and a floor on uninstall/reinstall transitions.
- `ERC7579DelayedExecutor`: `setDelay` now uses an asymmetric transition period depending on the direction of the change. When increasing the delay, the new value takes effect after `min(newDelay, delayChangeWindow())`. When decreasing the delay, the new value takes effect after `currentDelay - newDelay`.

## 18-03-2026

- Add `CrossChainSignatureChecker` utility library to verify cross-chain signatures following ERC-7964.

## 12-03-2026

- Add `MultisigCoordinator` utility contract, bridging multisig accounts with Zama's Fully Homomorphic Encryption (FHE). It allows any caller to register externally-encrypted FHE values on behalf of an account (granting ACL access to both the coordinator and the account), and allows any authorized signer to permanently grant FHE ACL decryption rights over a handle to an EOA address.

## 09-03-2026

- Add `ERC7579SessionKeys` abstract contract module, providing per-account registration of ERC-7913 session keys with configurable validity ranges. Supports arbitrary key types (EOA, P256, WebAuthn, etc.). Concrete implementations must add policy enforcement (e.g., selector whitelist, spending limits).
- Add `ERC7579SessionKeysValidator` abstract contract, extending `ERC7579SessionKeys` with ERC-4337 user-operation validation and ERC-1271 message signing. Packs session key validity range into `validationData` for EntryPoint enforcement. Developers extend it to enforce custom policies (e.g., by overriding `_validateUserOp` to inspect `userOp.callData`).

## 04-03-2026

- Renamed `OpenAccountEnableMode` to `OpenAccountERC8043`, now implementing atomic module installation and usage (_enable mode_) following ERC-8043. When `userOp.initCode` starts with the `0x80438043` magic value, the account installs one or more modules and validates the user operation in a single transaction.
- `ERC7579ERC20Spender`: The underlying transfer revert is now bubbled up directly. For batch transfers, the revert reason of the first failed transfer is bubbled up directly.
- `ERC7579ERC20Spender`: Removed `_decodeERC20SpenderInitData` from the internal interface.
- `ERC7579NativeSpender`: Removed `_decodeNativeSpenderInitData` from the internal interface.
- `ERC7579NativeSpender`: The underlying transfer revert is now bubbled up directly.

## 28-02-2026

- `ERC7579Multisig`: `isSigner`, `addSigners`, `removeSigners`, `_addSigners`, and `_removeSigners` now use `calldata` instead of `memory` for `bytes` parameters.
- `ERC7579MultisigWeighted`: `signerWeight`, `setSignerWeights`, `_setSignerWeights`, and `_addSigners` now use `calldata` instead of `memory` for `bytes` parameters.
- `ERC7579SocialRecoveryExecutor`: `isGuardian`, `addGuardians`, and `removeGuardians` now use `calldata` instead of `memory` for `bytes` parameters.
- `ERC7579MultisigWeightedValidator`: `_addSigners` and `_removeSigners` now use `calldata` instead of `memory` for `bytes` parameters.
- Add `ERC7579ECDSA`, `ERC7579P256`, and `ERC7579WebAuthn` abstract contract modules, extracting the signer management and signature validation logic from their respective validator contracts into reusable primitives.
- `ERC7579ECDSAValidator`, `ERC7579P256Validator`, and `ERC7579WebAuthnValidator` now extend these abstract primitives and compose them with `ERC7579Validator`.
- `ERC7579WebAuthnValidator`: The `_rawERC7579Validation` function now returns `false` when the signature is not a valid WebAuthn authentication assertion. P256 fallback is removed.

## 21-02-2026

- `ERC7579MultisigConfidentialValidator`: User op validation now requires only 2 steps instead of 3. The explicit `discloseOperation` call is no longer needed: users can instead embed the FHE decryption proof directly in the user op signature (relayer address in the first 20 bytes, proof thereafter), and the validator verifies it inline during `validateUserOp`. The prior 3-step flow (request → disclose → submit) remains supported as a fallback via the `disclosed` flag.

## 17-02-2026

- `ERC7579MultisigConfidential`: Removed the `requestDisclosure` function that allowed submitting arbitrary encrypted booleans (`ebool`) for disclosure. The internal `_requestDisclosure` function has been renamed to `_requestDiscloseOperation`. Only `requestDiscloseOperation` is now supported for requesting decryption of validated operations.

## 16-02-2026

- Add `ERC7579MultisigConfidential` and `ERC7579MultisigWeightedConfidential` abstract contract modules, providing confidential multisignature validation using Fully Homomorphic Encryption (FHE). Signer identities and the approval threshold are kept encrypted on-chain, enabling privacy-preserving multisignature authorization for ERC-7579 accounts.
- Add `ERC7579MultisigConfidentialValidator` and `ERC7579MultisigWeightedConfidentialValidator` contract modules, extending the confidential multisig abstract contracts with ERC-7579 validator module support.

## 06-02-2026

- `ERC7579ERC20Spender` and `ERC7579NativeSpender`: `newStart` can now be set to `0` as a sentinel value that resolves to the current timepoint. Previously, the current timepoint had to be passed explicitly for immediate-start configurations.

## 09-01-2026

- Add `ERC7579SocialRecoveryExecutor` contract module, combining weighted multisignatures with time-delayed execution to provide a secure social recovery mechanism. Trusted guardians can collectively schedule recovery operations, which execute after a security delay, giving the account owner time to detect and cancel malicious recovery attempts.
- Add `Multisig` utility library to decode multisignatures.

## 07-01-2026

- `OpenAccountEnableMode`: Correctly validates UserOp signatures after successful module installation in enable mode. Previously, the contract would return success without validating the UserOp signature, allowing an attacker with a valid installation signature to execute arbitrary operations.
- The `execute` function of `ERC7579Executor` is now `payable` and forwards the payment to the account.
- The `validateUserOp` function of `ERC7579Validator` is not `view` anymore.

## 06-01-2026

- `ERC7579DelayedExecutor`: The `onInstall` function now enforces `delayChangeWindow()` when reinstalling the module with a prior delay configuration still present. This ensures consistent delay transition behavior whether updating via `setDelay` or through module reinstallation.
- `ERC7579DelayedExecutor`: The `_scheduleAt` internal function does not return an `Schedule` struct anymore. Previously, the returned struct was empty.

## 30-12-2025

- Add `ERC7579ERC20Spender` and `ERC7579NativeSpender` contract modules extending `ERC7579Executor` with spending limits and automatic renewal periods for ERC20 tokens and native tokens (ETH) respectively.

## 29-12-2025

- `OpenAccount` now uses `draft-AccountERC7579Upgradeable` instead of `draft-AccountERC7579` for ERC-7579 compatibility.
- Add `OpenAccountFactory` contract, a factory to create OpenAccount instances on demand using ERC-1967 proxy clones with CREATE2 for deterministic addresses.
- Add `ERC1967Clones` library, providing gas-efficient methods to create deterministic ERC-1967 proxy clones.

## 24-12-2025

- `ERC7579Executor` no longer provides public `execute` and internal `_validateExecution` functions. Developers must now implement their own public `execute` function with custom validation and access control logic, and call the internal `_execute` function after validation.
- `ERC7579DelayedExecutor` no longer provides public `schedule` and `cancel` functions, nor internal `_validateSchedule` and `_validateCancel` functions. Developers must now implement their own public `schedule` and `cancel` functions with custom validation and access control logic, and call the internal `_schedule` or `_cancel` functions after validation.

## 22-12-2025

- `OpenAccount` initialization now supports installing multiple modules in a single transaction and executing arbitrary configuration calls during initialization via the `configMode` and `configCalldata` parameters.

## 05-12-2025

- The `onInstall` function of `ERC7579Multisig`, `ERC7579MultisigWeighted`, `ERC7579DelayedExecutor`, `ERC7579ECDSAValidator`, `ERC7579P256Validator` now explicitly revert if the module is already installed or if their configuration is invalid.

## 14-11-2025

- Rearrange modules folder into `validators` and `executors` folders.
  - `ERC7579Validator`, `ERC7579Multisig`, `ERC7579MultisigWeighted`, `ERC7579P256Validator`, `ERC7579WebAuthnValidator`, `ERC7579ECDSAValidator` contracts are now in the `validators` folder.
  - `ERC7579Executor`, `ERC7579DelayedExecutor` contracts are now in the `executors` folder.
- Rename `ERC7579Multisig` and `ERC7579MultisigWeighted` to `ERC7579MultisigValidator` and `ERC7579MultisigWeightedValidator`, respectively.
- Add `ERC7579Multisig` and `ERC7579MultisigWeighted` abstract contracts, providing a base interface for multisignature authorization for ERC-7579 accounts.

## 10-11-2025

- Add `ERC7579P256Validator` module, implementing P256-based signature validation for ERC-7579 accounts.
- Add `ERC7579WebAuthnValidator` module, implementing WebAuthn-based signature validation for ERC-7579 accounts.

## 07-11-2025

- Add `ERC7579ECDSAValidator` module, implementing ECDSA-based signature validation for ERC-7579 accounts.

## 28-10-2025

- Add `ERC7579Validator` abstract contract, providing a base interface for ERC-7579 validator modules. Implements basic validator wiring, including the `_rawERC7579Validation` interface for custom signature validation logic.
- Add `ERC7579Multisig` contract module supporting multisignature authorization for ERC-7579 accounts following ERC-7913.
- Add `ERC7579MultisigWeighted` module, extending `ERC7579Multisig` with weighted signer support.
- Add `ERC7579Executor` abstract contract, a minimal ERC-7579 executor module allowing arbitrary operation execution from a smart account, with extensibility hooks for custom validation and access control.
- Add `ERC7579DelayedExecutor` abstract contract module. Extends `ERC7579Executor` with scheduling and time-delayed execution support for operations, including customizable per-account delay and expiration windows.

## 12-09-2025

- Add `OpenAccount` contract, a modular smart account implementation following the ERC-7579 standard.
