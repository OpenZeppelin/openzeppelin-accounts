import _test, { TestFn } from 'ava';
import {
  Chain,
  createTestClient,
  http,
  toHex,
  Transport,
  publicActions,
  type Address,
  type Hex,
  parseEther,
  createWalletClient,
  type Client,
  type Account,
  getContract,
  encodePacked,
  bytesToHex,
  keccak256,
  PublicActions,
  RpcSchema,
  WalletActions,
  ContractFunctionExecutionError,
  padHex,
} from 'viem';
import {
  type ToSmartAccountReturnType,
  createBundlerClient,
  entryPoint09Address,
  estimateUserOperationGas,
} from 'viem/account-abstraction';
import { erc7579Actions, InstallModulesParameters } from '../erc7579.actions.js';
import { toOpenAccount } from '../accounts/index.js';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import OpenAccountFactoryArtifact from '@open-accounts-framework/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import { MODULE_TYPE_VALIDATOR } from '../erc7579.utils.js';
import { cleanup, clientArgs, Context, setup, testClientArgs } from './helpers/setup.js';

interface ERC7579ActionsTestContext extends Context {
  deployer: Client<Transport, Chain, Account, RpcSchema, PublicActions & WalletActions<Chain, Account>>;
  account: ToSmartAccountReturnType;
  ECDSAValidator: ReturnType<typeof getContract>;
  deployAccount: () => Promise<void>;
}

const test = _test as TestFn<ERC7579ActionsTestContext>;

const deployECDSAValidator = async (
  deployer: Client<Transport, Chain, Account, RpcSchema, PublicActions & WalletActions<Chain, Account>>,
): Promise<ReturnType<typeof getContract>> => {
  return deployer
    .deployContract({
      abi: ECDSAValidatorArtifact.abi,
      bytecode: ECDSAValidatorArtifact.bytecode.object as Hex,
    })
    .then(hash => deployer.waitForTransactionReceipt({ hash }))
    .then(receipt =>
      getContract({
        address: receipt.contractAddress as Address,
        abi: ECDSAValidatorArtifact.abi,
        client: deployer,
      }),
    );
};

test.before(setup);
test.after.always(cleanup);

test.beforeEach(async t => {
  const deployerKey = privateKeyToAccount(generatePrivateKey());
  const signerKey = privateKeyToAccount(generatePrivateKey());

  const deployer = createWalletClient({
    account: deployerKey,
    ...clientArgs,
  }).extend(publicActions);
  await t.context.testClient.setBalance({ address: deployerKey.address, value: parseEther('100') });
  const factory = await deployer
    .deployContract({
      abi: OpenAccountFactoryArtifact.abi,
      bytecode: OpenAccountFactoryArtifact.bytecode.object as Hex,
    })
    .then(hash => deployer.waitForTransactionReceipt({ hash }))
    .then(receipt =>
      getContract({
        address: receipt.contractAddress as Address,
        abi: OpenAccountFactoryArtifact.abi,
        client: deployer,
      }),
    );
  t.context.ECDSAValidator = await deployECDSAValidator(deployer);

  const salt = keccak256(toHex('salt'));

  const bundlerClient = createBundlerClient({
    client: t.context.testClient,
    transport: http('http://localhost:3000/'),
  });

  t.context.deployer = deployer;
  t.context.account = await toOpenAccount({
    client: deployer,
    signer: signerKey,
    factory,
    moduleTypeIds: [MODULE_TYPE_VALIDATOR],
    modules: [t.context.ECDSAValidator.address],
    initDatas: [encodePacked(['address'], [signerKey.address])],
    salt,
    getStubSignature: async () => bytesToHex(crypto.getRandomValues(new Uint8Array(65))),
    userOperation: {
      estimateGas: async userOp => {
        const gas = await estimateUserOperationGas(bundlerClient, {
          account: t.context.account,
          calls: [{ to: t.context.account.address, data: userOp.callData }],
        });
        const MIN_VERIFICATION_GAS = 150000n;
        return {
          verificationGasLimit:
            gas.verificationGasLimit < MIN_VERIFICATION_GAS ? MIN_VERIFICATION_GAS : gas.verificationGasLimit,
        };
      },
    },
  });
  await t.context.testClient.setBalance({ address: t.context.account.address, value: parseEther('100') });
  t.context.deployAccount = async () => {
    await t.context.account.getFactoryArgs().then(({ factory, factoryData }) =>
      t.context.deployer.sendTransaction({
        to: factory as Address,
        data: factoryData as Hex,
      }),
    );
  };
});

test('erc7579Actions returns action functions', t => {
  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());
  t.is(typeof client.accountId, 'function');
  t.is(typeof client.installModules, 'function');
  t.is(typeof client.isModuleInstalled, 'function');
  t.is(typeof client.supportsExecutionMode, 'function');
  t.is(typeof client.supportsModule, 'function');
  t.is(typeof client.uninstallModules, 'function');
  t.is(typeof client.execute, 'function');
});

test('accountId', async t => {
  await t.throwsAsync(async () => createTestClient(testClientArgs).extend(erc7579Actions()).accountId(), {
    message: /Account not found/,
  });

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  await t.throwsAsync(async () => client.accountId(), {
    instanceOf: ContractFunctionExecutionError,
  });

  await t.context.deployAccount();

  t.is(await client.accountId(), '@openzeppelin/contracts.AccountERC7579.v1.0.0');
});

test('isModuleInstalled', async t => {
  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  await t.throwsAsync(
    async () =>
      client.isModuleInstalled({
        type: MODULE_TYPE_VALIDATOR,
        address: t.context.ECDSAValidator.address,
        additionalContext: '0x',
      }),
    {
      message: /Account not found/,
    },
  );

  await t.throwsAsync(
    async () =>
      client.isModuleInstalled({
        account: t.context.account,
        type: MODULE_TYPE_VALIDATOR,
        address: t.context.ECDSAValidator.address,
        additionalContext: '0x',
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );

  await t.context.deployAccount();

  t.is(
    await client.isModuleInstalled({
      account: t.context.account,
      type: MODULE_TYPE_VALIDATOR,
      address: t.context.ECDSAValidator.address,
      additionalContext: '0x',
    }),
    true,
  );
});

test('supportsExecutionMode', async t => {
  const clientWithoutAccount = createTestClient(testClientArgs).extend(erc7579Actions());
  await t.throwsAsync(
    async () =>
      clientWithoutAccount.supportsExecutionMode({
        account: t.context.account,
        callType: 'call',
        execType: 'default',
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  await t.throwsAsync(
    async () =>
      client.supportsExecutionMode({
        callType: 'call',
        execType: 'default',
      }),
    {
      message: /Account not found/,
    },
  );

  await t.context.deployAccount();

  t.is(
    await client.supportsExecutionMode({
      account: t.context.account,
      callType: 'call',
      execType: 'default',
    }),
    true,
  );

  t.is(
    await client.supportsExecutionMode({
      account: t.context.account,
      callType: 'batchcall',
      execType: 'try',
    }),
    true,
  );

  t.is(
    await client.supportsExecutionMode({
      account: t.context.account,
      callType: 'batchcall',
      execType: 'try',
      selector: '0x12345678',
      payload: '0x00000000000000000000000000000000000000000000',
    }),
    true,
  );
});

test('supportsModule', async t => {
  const clientWithoutAccount = createTestClient(testClientArgs).extend(erc7579Actions());
  await t.throwsAsync(
    async () => clientWithoutAccount.supportsModule({ account: t.context.account, type: 'validator' }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  await t.throwsAsync(async () => client.supportsModule({ type: 'validator' }), {
    message: /Account not found/,
  });

  await t.context.deployAccount();

  t.is(await client.supportsModule({ account: t.context.account, type: 'validator' }), true);
  t.is(await client.supportsModule({ account: t.context.account, type: 'executor' }), true);
  t.is(await client.supportsModule({ account: t.context.account, type: 'hook' }), false);
  t.is(await client.supportsModule({ account: t.context.account, type: 'fallback' }), true);
});

test('installModules and uninstallModules', async t => {
  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  });

  const bundlerClient = createBundlerClient({
    client,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());

  await t.throwsAsync(
    async () =>
      bundlerClient.installModules({
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /No modules to install/,
    },
  );

  const validators: InstallModulesParameters<typeof t.context.account>['modules'] = [
    {
      type: 'validator',
      address: (await deployECDSAValidator(t.context.deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
    {
      type: 'validator',
      address: (await deployECDSAValidator(t.context.deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
    {
      type: 'validator',
      address: (await deployECDSAValidator(t.context.deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
  ];

  await t.throwsAsync(
    async () =>
      bundlerClient.installModules({
        entryPointAddress: entryPoint09Address,
        modules: validators.slice(0, 1),
      }),
    {
      message: /Account not found/,
    },
  );

  // Install 1
  // First user op deploys the account
  await bundlerClient
    .installModules({
      entryPointAddress: entryPoint09Address,
      account: t.context.account,
      modules: validators.slice(0, 1),
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Install 2
  await bundlerClient
    .installModules({
      entryPointAddress: entryPoint09Address,
      account: t.context.account,
      modules: validators.slice(1, 3),
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  for (const validator of validators) {
    t.is(
      await bundlerClient.isModuleInstalled({
        account: t.context.account,
        type: 'validator',
        address: validator.address,
        additionalContext: '0x',
      }),
      true,
    );
  }

  await t.throwsAsync(
    async () =>
      bundlerClient.uninstallModules({
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /No modules to uninstall/,
    },
  );

  await t.throwsAsync(
    async () =>
      bundlerClient.uninstallModules({
        entryPointAddress: entryPoint09Address,
        modules: validators.slice(0, 1).map(validator => ({
          ...validator,
          deInitData: '0x',
        })),
      }),
    {
      message: /Account not found/,
    },
  );

  // Uninstall 1
  await bundlerClient
    .uninstallModules({
      entryPointAddress: entryPoint09Address,
      account: t.context.account,
      modules: validators.slice(2, 3).map(validator => ({
        ...validator,
        deInitData: '0x',
      })),
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Uninstall 2
  await bundlerClient
    .uninstallModules({
      entryPointAddress: entryPoint09Address,
      account: t.context.account,
      modules: validators.slice(0, 2).map(validator => ({
        ...validator,
        deInitData: '0x',
      })),
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  for (const validator of validators) {
    t.is(
      await bundlerClient.isModuleInstalled({
        account: t.context.account,
        type: 'validator',
        address: validator.address,
        additionalContext: '0x',
      }),
      false,
    );
  }
});

test('execute', async t => {
  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(publicActions);

  const bundlerClient = createBundlerClient({
    client,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());

  await t.throwsAsync(
    async () =>
      bundlerClient.execute({
        entryPointAddress: entryPoint09Address,
        calls: [],
        nonce: await t.context.account.getNonce({
          key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
        }),
      }),
    {
      message: /Account not found/,
    },
  );

  const receiver = privateKeyToAccount(generatePrivateKey());

  await bundlerClient
    .execute({
      account: t.context.account,
      entryPointAddress: entryPoint09Address,
      calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }],
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  t.is(await client.getBalance({ address: receiver.address }), parseEther('1'));

  await bundlerClient
    .execute({
      account: t.context.account,
      entryPointAddress: entryPoint09Address,
      calls: [
        { to: receiver.address, data: '0x', value: parseEther('1') },
        { to: receiver.address, data: '0x', value: parseEther('2') },
        { to: receiver.address, data: '0x', value: parseEther('3') },
      ],
      nonce: await t.context.account.getNonce({
        key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
      }),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  t.is(await client.getBalance({ address: receiver.address }), parseEther('7'));
});
