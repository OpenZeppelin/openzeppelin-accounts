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

  await client.accountId().then(id => t.is(id, '@openzeppelin/contracts.AccountERC7579.v1.0.0'));
});

test('isModuleInstalled', async t => {
  const isModuleInstalledWithoutAccount = async () =>
    createTestClient(testClientArgs)
      .extend(erc7579Actions())
      .isModuleInstalled({
        type: MODULE_TYPE_VALIDATOR,
        address: t.context.ECDSAValidator.address,
        account: undefined as unknown as ToSmartAccountReturnType,
      });
  await t.throwsAsync(isModuleInstalledWithoutAccount, {
    message: /Account not found/,
  });

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  const isModuleInstalledWithAccount = async () =>
    client.isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: t.context.ECDSAValidator.address,
    });
  await t.throwsAsync(isModuleInstalledWithAccount, {
    instanceOf: ContractFunctionExecutionError,
  });

  await t.context.deployAccount();

  await isModuleInstalledWithAccount().then(installed => t.is(installed, true));
});

test('supportsExecutionMode', async t => {
  const clientWithoutAccount = createTestClient(testClientArgs).extend(erc7579Actions());
  const supportsExecutionModeWithoutAccount = async () =>
    clientWithoutAccount.supportsExecutionMode({
      callType: 'call',
      execType: 'default',
      account: undefined as unknown as ToSmartAccountReturnType,
    });
  await t.throwsAsync(supportsExecutionModeWithoutAccount, {
    message: /Account not found/,
  });
  const supportsExecutionModeWithAccount = async () =>
    clientWithoutAccount.supportsExecutionMode({
      account: t.context.account,
      callType: 'call',
      execType: 'default',
    });
  await t.throwsAsync(supportsExecutionModeWithAccount, {
    instanceOf: ContractFunctionExecutionError,
  });

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  const supportsExecutionMode = async () =>
    client.supportsExecutionMode({
      callType: 'call',
      execType: 'default',
    });
  await t.throwsAsync(supportsExecutionMode, {
    instanceOf: ContractFunctionExecutionError,
  });

  await t.context.deployAccount();

  await client
    .supportsExecutionMode({
      callType: 'call',
      execType: 'default',
    })
    .then(supports => t.is(supports, true));

  await client
    .supportsExecutionMode({
      callType: 'batchcall',
      execType: 'try',
    })
    .then(supports => t.is(supports, true));

  await client
    .supportsExecutionMode({
      callType: 'batchcall',
      execType: 'try',
      selector: '0x12345678',
      payload: '0x00000000000000000000000000000000000000000000',
    })
    .then(supports => t.is(supports, true));
});

test('supportsModule', async t => {
  const clientWithoutAccount = createTestClient(testClientArgs).extend(erc7579Actions());
  const supportsModuleWithoutAccount = async () =>
    clientWithoutAccount.supportsModule({
      account: undefined as unknown as ToSmartAccountReturnType,
      type: 'validator',
    });
  await t.throwsAsync(supportsModuleWithoutAccount, {
    message: /Account not found/,
  });
  const supportsModuleWithAccount = async () =>
    clientWithoutAccount.supportsModule({ account: t.context.account, type: 'validator' });
  await t.throwsAsync(supportsModuleWithAccount, {
    instanceOf: ContractFunctionExecutionError,
  });

  const client = createTestClient({
    account: t.context.account,
    ...testClientArgs,
  }).extend(erc7579Actions());

  await t.throwsAsync(async () => client.supportsModule({ type: 'validator' }), {
    instanceOf: ContractFunctionExecutionError,
  });

  await t.context.deployAccount();

  await client.supportsModule({ type: 'validator' }).then(supports => t.is(supports, true));
  await client.supportsModule({ type: 'executor' }).then(supports => t.is(supports, true));
  await client.supportsModule({ type: 'hook' }).then(supports => t.is(supports, false));
  await client.supportsModule({ type: 'fallback' }).then(supports => t.is(supports, true));
});

test('installModules and uninstallModules', async t => {
  const testClient = createTestClient(testClientArgs).extend(erc7579Actions());
  const installModulesWithoutAccount = async () =>
    testClient.installModules({
      account: undefined as unknown as ToSmartAccountReturnType,
      entryPointAddress: entryPoint09Address,
      modules: [],
    });
  await t.throwsAsync(installModulesWithoutAccount, {
    message: /Account not found/,
  });
  const installModulesWithAccount = async () =>
    testClient.installModules({ account: t.context.account, entryPointAddress: entryPoint09Address, modules: [] });
  await t.throwsAsync(installModulesWithAccount, {
    message: /No modules to install/,
  });

  const bundlerClient = createBundlerClient({
    account: t.context.account,
    client: testClient,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());

  await t.throwsAsync(
    async () =>
      bundlerClient.installModules({
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

  const getValidatorNonce = async () =>
    t.context.account.getNonce({
      key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
    });

  // Install 1
  // First user op deploys the account
  await bundlerClient
    .installModules({
      modules: validators.slice(0, 1),
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Install 2
  await bundlerClient
    .installModules({
      modules: validators.slice(1, 3),
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  for (const validator of validators) {
    t.is(
      await bundlerClient.isModuleInstalled({
        type: 'validator',
        address: validator.address,
      }),
      true,
    );
  }

  const uninstallModulesWithoutAccount = async () =>
    testClient.uninstallModules({
      account: undefined as unknown as ToSmartAccountReturnType,
      entryPointAddress: entryPoint09Address,
      modules: [],
    });
  await t.throwsAsync(uninstallModulesWithoutAccount, {
    message: /Account not found/,
  });

  const uninstallModulesWithAccount = async () =>
    testClient.uninstallModules({ account: t.context.account, entryPointAddress: entryPoint09Address, modules: [] });
  await t.throwsAsync(uninstallModulesWithAccount, {
    message: /No modules to uninstall/,
  });

  await t.throwsAsync(
    async () =>
      bundlerClient.uninstallModules({
        modules: [],
      }),
    {
      message: /No modules to uninstall/,
    },
  );

  // Uninstall 1
  await bundlerClient
    .uninstallModules({
      modules: validators.slice(2, 3),
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Uninstall 2
  await bundlerClient
    .uninstallModules({
      modules: validators.slice(0, 2),
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  for (const validator of validators) {
    await bundlerClient
      .isModuleInstalled({
        type: 'validator',
        address: validator.address,
      })
      .then(installed => t.is(installed, false));
  }
});

test('execute', async t => {
  const testClient = createTestClient(testClientArgs).extend(erc7579Actions()).extend(publicActions);
  const executeWithoutAccount = async () =>
    testClient.execute({
      account: undefined as unknown as ToSmartAccountReturnType,
      entryPointAddress: entryPoint09Address,
      calls: [],
    });
  await t.throwsAsync(executeWithoutAccount, {
    message: /Account not found/,
  });

  const bundlerClient = createBundlerClient({
    account: t.context.account,
    client: testClient,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());

  const receiver = privateKeyToAccount(generatePrivateKey());

  const getValidatorNonce = async () =>
    t.context.account.getNonce({
      key: BigInt(padHex(t.context.ECDSAValidator.address, { dir: 'right', size: 24 })),
    });

  await bundlerClient
    .execute({
      calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }],
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  await testClient.getBalance({ address: receiver.address }).then(balance => t.is(balance, parseEther('1')));

  await bundlerClient
    .execute({
      calls: [
        { to: receiver.address, data: '0x', value: parseEther('1') },
        { to: receiver.address, data: '0x', value: parseEther('2') },
        { to: receiver.address, data: '0x', value: parseEther('3') },
      ],
      nonce: await getValidatorNonce(),
    })
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  await testClient.getBalance({ address: receiver.address }).then(balance => t.is(balance, parseEther('7')));
});
