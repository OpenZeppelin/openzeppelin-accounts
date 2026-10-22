# @openzeppelin-accounts/sdk

**Viem-native TypeScript SDK for OpenZeppelin Accounts.**

This package provides typed account factories and a bundler client extension for interacting with ERC-7579 smart accounts. It is the off-chain counterpart to [`@openzeppelin-accounts/contracts`](../contracts).

## Installation

```bash
npm install @openzeppelin-accounts/sdk viem
```

## Contents

### Account factories

| Export | Description |
| :--- | :--- |
| `toOpenAccount` | Creates a Viem `SmartAccount` for the `OpenAccount` contract. Supports factory-based (counterfactual) and existing-address modes. |
| `toERC7579Account` | Creates a Viem `SmartAccount` for any ERC-7579 account with caller-supplied `getAddress` and `getFactoryArgs`. |

### Bundler client extension

| Export | Description |
| :--- | :--- |
| `erc7579Actions` | Extends a Viem bundler client with `installModules`, `uninstallModules`, `isModuleInstalled`, `supportsModule`, `supportsExecutionMode`, `execute`, and `accountId`. |

### ERC-7579 utilities

| Export | Description |
| :--- | :--- |
| `encodeMode` / `decodeMode` | Pack/unpack a 32-byte ERC-7579 execution mode |
| `encodeCalls` / `decodeCalls` | Encode/decode `execute` calldata (auto-selects single or batch) |
| `encodeSingle` / `decodeSingle` | Pack/unpack a single `(address, uint256, bytes)` execution |
| `encodeBatch` / `decodeBatch` | ABI-encode/decode a batch of executions |
| `encodeDelegate` / `decodeDelegate` | Pack/unpack a delegatecall execution |
| `ModuleTypes` | Enum of module type IDs (VALIDATOR, EXECUTOR, FALLBACK, HOOK) |
| `parseModuleTypeId` | Convert a string or numeric module type to `bigint` |

## Usage

```typescript
import { createPublicClient, http, getContract, encodePacked } from 'viem';
import { mainnet } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { createBundlerClient } from 'viem/account-abstraction';
import { toOpenAccount, erc7579Actions } from '@openzeppelin-accounts/sdk';
import OpenAccountFactoryABI from '@openzeppelin-accounts/contracts/build/contracts/OpenAccountFactory.json' assert { type: 'json' };

const client = createPublicClient({ chain: mainnet, transport: http() });
const signer = privateKeyToAccount('0x<privateKey>');

// Create a smart account
const account = await toOpenAccount({
  client,
  signer,
  validator: '0x<ecdsaValidatorAddress>',
  factory: getContract({
    address: '0xcdbE9DD6F837b6E894a8F8402857cF3fDABCaE37',
    abi: OpenAccountFactoryABI.abi,
    client,
  }),
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

// Execute calls: first user op deploys the account automatically
const hash = await bundlerClient.execute({
  calls: [{ to: '0x<recipient>', data: '0x', value: 0n }],
});

await bundlerClient.waitForUserOperationReceipt({ hash });
```

### Using with an existing account

```typescript
const account = await toOpenAccount({
  client,
  signer,
  validator: '0x<validatorAddress>',
  address: '0x<deployedAccountAddress>',
  getStubSignature: async () => '0x' + 'ff'.repeat(65),
});
```

### Using with a different ERC-7579 account

```typescript
import { toERC7579Account } from '@openzeppelin-accounts/sdk';

const account = await toERC7579Account({
  client,
  signer,
  async getAddress() { return '0x<accountAddress>'; },
  async getFactoryArgs() { return { factory: '0x...', factoryData: '0x...' }; },
  getStubSignature: async () => '0x' + 'ff'.repeat(65),
});
```

## Documentation

Full documentation: [docs.openzeppelin.com/accounts/sdk](https://docs.openzeppelin.com/accounts/sdk)

## License

Released under the [MIT License](../../LICENSE).
