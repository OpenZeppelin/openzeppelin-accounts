# OpenZeppelin Accounts

**Standardized modular tooling and SDK for EVM smart accounts.**

OpenZeppelin Accounts delivers production-ready [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) modules and a TypeScript SDK for interacting with smart accounts. Because the modules conform to the ERC-7579 standard they can be installed on any compatible account: including [OpenZeppelin's `AccountERC7579`](https://docs.openzeppelin.com/contracts/5.x/api/account#AccountERC7579), [Kernel](https://github.com/zerodevapp/kernel), and the bundled `OpenAccount`.

## Packages

| Package                                                      | Description                                                                                     |
| :----------------------------------------------------------- | :---------------------------------------------------------------------------------------------- |
| [`@openzeppelin-accounts/contracts`](./packages/contracts) | Solidity contracts: `OpenAccount`, validator modules, executor modules, and multisig primitives |
| [`@openzeppelin-accounts/sdk`](./packages/sdk)             | TypeScript SDK: Viem-native account factories and ERC-7579 bundler client actions               |

## Installation

**Contracts (Hardhat / Foundry)**

```bash
npm install @openzeppelin-accounts/contracts
```

**SDK**

```bash
npm install @openzeppelin-accounts/sdk viem
```

## Overview

### Contracts

The contracts package provides:

- **`OpenAccount`**: A production-ready, ERC-4337 and ERC-7579 compliant smart account with EIP-712 signature support and NFT holder capabilities. Deployed via `OpenAccountFactory` at a deterministic address on all major EVM chains:
  ```
  0x9045eF209067701bE7b78AaC216C04Ffa6543330
  ```
- **Validators**: Signature validation modules (ECDSA, WebAuthn/passkey).
- **Executors**: Execution modules for spending limits, social recovery, and more.
- **Multisig**: ERC-7913-based multisig and weighted multisig modules, including confidential variants.

### SDK

The SDK wraps [Viem's account abstraction primitives](https://viem.sh/account-abstraction/accounts/smart/toSmartAccount) with ERC-7579-aware helpers:

- **`toOpenAccount`**: Creates a `SmartAccount` instance for the `OpenAccount` contract, supporting both factory-based (counterfactual) and existing-address modes.
- **`toERC7579Account`**: Creates a `SmartAccount` for any ERC-7579 account, accepting caller-supplied address and factory args.
- **`erc7579Actions`**: Viem bundler client extension providing typed methods: `installModules`, `uninstallModules`, `isModuleInstalled`, `supportsModule`, `supportsExecutionMode`, `execute`, and `accountId`.

## Quick Start

```typescript
import { createPublicClient, http, getContract, encodePacked } from 'viem';
import { mainnet } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { createBundlerClient } from 'viem/account-abstraction';
import { toOpenAccount, erc7579Actions } from '@openzeppelin-accounts/sdk';
import OpenAccountFactoryABI from '@openzeppelin-accounts/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' assert { type: 'json' };

const client = createPublicClient({ chain: mainnet, transport: http() });
const signer = privateKeyToAccount('0x<privateKey>');

const factory = getContract({
  address: '0x9045eF209067701bE7b78AaC216C04Ffa6543330',
  abi: OpenAccountFactoryABI.abi,
  client,
});

// Create a smart account backed by an ECDSA validator
const account = await toOpenAccount({
  client,
  signer,
  factory,
  moduleTypeIds: ['validator'],
  modules: ['0x<ecdsaValidatorAddress>'],
  initDatas: [encodePacked(['address'], [signer.address])],
  getStubSignature: async () => '0x' + 'ff'.repeat(65),
});

// Extend a bundler client with ERC-7579 actions
const bundlerClient = createBundlerClient({
  account,
  client,
  transport: http('https://bundler.example.com'),
}).extend(erc7579Actions());

// The first user operation deploys the account automatically
const hash = await bundlerClient.execute({
  calls: [{ to: '0x<recipient>', data: '0x', value: 0n }],
});
```

## Documentation

Full documentation is available at **[docs.openzeppelin.com/accounts](https://docs.openzeppelin.com/accounts)**. Its sources live in [`docs`](./docs) and are synced to the [OpenZeppelin docs site](https://github.com/OpenZeppelin/docs) on release.

- [Contracts overview](https://docs.openzeppelin.com/accounts/contracts): account setup, module installation, factory usage
- [SDK overview](https://docs.openzeppelin.com/accounts/sdk): account factories, signers, and bundler client setup
- [ERC-7579 Actions](https://docs.openzeppelin.com/accounts/sdk/actions): full action reference
- [OpenAccount parameters](https://docs.openzeppelin.com/accounts/sdk/open-account): detailed `toOpenAccount` parameter reference
- [API reference](https://docs.openzeppelin.com/accounts/api): generated from the contracts' NatSpec

## Security

This project is maintained by [OpenZeppelin](https://openzeppelin.com). Smart contracts are a nascent technology and carry a high level of technical risk and uncertainty. Using this library is not a substitute for a security audit.

This project has not yet had a stable release. Please report security vulnerabilities by email to [security@openzeppelin.com](mailto:security@openzeppelin.com).

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/OpenZeppelin/openzeppelin-accounts).

## License

Released under the [MIT License](./LICENSE).
