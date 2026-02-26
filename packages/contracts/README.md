# @open-accounts-framework/contracts

**ERC-7579 modules and smart account contracts for the Open Accounts Framework.**

This package provides production-ready Solidity contracts: a base smart account implementation and a set of ERC-7579 modules that can be used with any ERC-7579 compliant account.

## Installation

```bash
npm install @open-accounts-framework/contracts
```

## Contents

### OpenAccount

A production-ready, ERC-4337 and ERC-7579 compliant smart account built on top of [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts). It provides full module support (validators, executors, hooks, fallbacks), EIP-712 signature validation, and NFT holder capabilities.

`OpenAccountFactory` deploys minimal ERC-1967 proxy clones with deterministic addresses via CREATE2. It is pre-deployed on all major EVM chains at:

```
0x9045eF209067701bE7b78AaC216C04Ffa6543330
```

### Validators

Validator modules authorize user operations and ERC-1271 signature requests.

| Contract | Description |
| :--- | :--- |
| `ERC7579Validator` | Abstract base for all validators |
| `ERC7579ECDSAValidator` | Single ECDSA signer (EOA private key) |
| `ERC7579P256Validator` | Single P-256 / secp256r1 signer |
| `ERC7579WebAuthnValidator` | WebAuthn / passkey signer |
| `ERC7579MultisigValidator` | ERC-7913 multisig threshold validator |
| `ERC7579MultisigWeightedValidator` | ERC-7913 weighted multisig validator |
| `ERC7579MultisigConfidentialValidator` | FHE-encrypted multisig validator |
| `ERC7579MultisigWeightedConfidentialValidator` | FHE-encrypted weighted multisig validator |

### Executors

Executor modules trigger actions through the account's `executeFromExecutor` callback.

| Contract | Description |
| :--- | :--- |
| `ERC7579Executor` | Abstract base for all executors |
| `ERC7579NativeSpender` | Native token (ETH) spending limits |
| `ERC7579ERC20Spender` | ERC-20 token spending limits |
| `ERC7579SocialRecoveryExecutor` | Time-locked social recovery |
| `ERC7579DelayedExecutor` | Generic delayed execution with cancellation |

### Multisig

Base modules that implement ERC-7913 threshold and weighted multisig logic, combinable with validator or executor roles.

| Contract | Description |
| :--- | :--- |
| `ERC7579Multisig` | Threshold multisig (e.g. 3-of-5) |
| `ERC7579MultisigWeighted` | Weighted multisig (variable signer weights) |
| `ERC7579MultisigConfidential` | FHE-encrypted threshold multisig |
| `ERC7579MultisigWeightedConfidential` | FHE-encrypted weighted multisig |

## Usage

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ECDSAValidator} from "@open-accounts-framework/contracts/modules/validators/ERC7579ECDSAValidator.sol";

contract MyECDSAValidator is ERC7579ECDSAValidator {}
```

Install it on an ERC-7579 account:

```solidity
MyECDSAValidator validator = new MyECDSAValidator();

account.installModule(
    MODULE_TYPE_VALIDATOR,
    address(validator),
    abi.encodePacked(signerAddress) // 20-byte ECDSA signer address
);
```

## Documentation

Full documentation: [docs.openzeppelin.com/accounts/contracts](https://docs.openzeppelin.com/accounts/contracts)

## License

Released under the [MIT License](../../LICENSE).
