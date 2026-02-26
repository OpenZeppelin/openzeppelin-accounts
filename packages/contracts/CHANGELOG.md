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

- `ERC7579DelayedExecutor`: The `onInstall` function now enforces `minSetback()` when reinstalling the module with a prior delay configuration still present. This ensures consistent delay transition behavior whether updating via `setDelay` or through module reinstallation.
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
