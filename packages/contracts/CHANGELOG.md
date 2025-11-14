## 14-11-2025

- Rearrange modules folder into `validators` and `executors` folders.
  - `ERC7579Validator`, `ERC7579Multisig`, `ERC7579MultisigWeighted`, `ERC7579P256Validator`, `ERC7579WebAuthnValidator`, `ERC7579ECDSAValidator` contracts are now in the `validators` folder.
  - `ERC7579Executor`, `ERC7579DelayedExecutor` contracts are now in the `executors` folder.

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
