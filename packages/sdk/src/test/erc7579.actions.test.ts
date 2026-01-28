import _test, { TestFn } from 'ava';
import {
  http,
  publicActions,
  parseEther,
  encodePacked,
  bytesToHex,
  ContractFunctionExecutionError,
  GetContractReturnType,
  Client,
  Transport,
} from 'viem';
import { SmartAccount, createBundlerClient, BundlerClient, entryPoint09Address } from 'viem/account-abstraction';
import { erc7579Actions, ERC7579Actions, InstallModulesParameters } from '../erc7579.actions.js';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import { MODULE_TYPE_VALIDATOR } from '../erc7579.utils.js';
import { OpenAccountContext, setup, setupOpenAccount, createAndFundEOA, cleanup } from './helpers/setup.js';
import { deployECDSAValidator, validatorNonceKey } from './helpers/erc7579.modules.js';

interface ERC7579ActionsTestContext extends OpenAccountContext {
  ECDSAValidator: GetContractReturnType<typeof ECDSAValidatorArtifact.abi>;
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
}

const test = _test as TestFn<ERC7579ActionsTestContext>;

test.before(setup);

test.beforeEach(async t => {
  const deployer = await createAndFundEOA(t.context.testClient);
  t.context.ECDSAValidator = await deployECDSAValidator(deployer);
  await setupOpenAccount(t, {
    validator: t.context.ECDSAValidator.address,
    signerKey: privateKeyToAccount(generatePrivateKey()),
    salt: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
  });
  t.context.bundlerClient = createBundlerClient({
    account: t.context.account,
    client: t.context.testClient,
    transport: http('http://localhost:3000/'),
  }).extend(erc7579Actions());
});

test.after.always(cleanup);

test('erc7579Actions returns action functions', t => {
  const client = t.context.bundlerClient;
  t.is(typeof client.accountId, 'function');
  t.is(typeof client.installModules, 'function');
  t.is(typeof client.isModuleInstalled, 'function');
  t.is(typeof client.supportsExecutionMode, 'function');
  t.is(typeof client.supportsModule, 'function');
  t.is(typeof client.uninstallModules, 'function');
  t.is(typeof client.execute, 'function');
});

test('accountId throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).accountId(),
    {
      message: /Account not found/,
    },
  );
});

test('accountId reverts if not deployed', async t => {
  await t.throwsAsync(async () => t.context.bundlerClient.accountId(), {
    instanceOf: ContractFunctionExecutionError,
  });
});

test('accountId returns @openzeppelin/contracts.AccountERC7579.v1.0.0', async t => {
  await t.context.deployAccount();
  await t.context.bundlerClient.accountId().then(id => t.is(id, '@openzeppelin/contracts.AccountERC7579.v1.0.0'));
});

test('isModuleInstalled throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).isModuleInstalled({
        type: MODULE_TYPE_VALIDATOR,
        address: t.context.ECDSAValidator.address,
        account: undefined as unknown as SmartAccount,
      }),
    {
      message: /Account not found/,
    },
  );
});

test('isModuleInstalled reverts if not deployed', async t => {
  await t.throwsAsync(
    async () =>
      t.context.bundlerClient.isModuleInstalled({
        type: MODULE_TYPE_VALIDATOR,
        address: t.context.ECDSAValidator.address,
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );
});

test('isModuleInstalled returns true', async t => {
  await t.context.deployAccount();
  await t.context.bundlerClient
    .isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: t.context.ECDSAValidator.address,
    })
    .then(installed => t.is(installed, true));
});

test('supportsExecutionMode throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>)
        .extend(erc7579Actions())
        .supportsExecutionMode({
          callType: 'call',
          execType: 'default',
          account: undefined as unknown as SmartAccount,
        }),
    {
      message: /Account not found/,
    },
  );
});

test('supportsExecutionMode reverts if not deployed', async t => {
  await t.throwsAsync(
    async () =>
      t.context.bundlerClient.supportsExecutionMode({
        account: t.context.account,
        callType: 'call',
        execType: 'default',
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );

  await t.throwsAsync(
    async () =>
      t.context.bundlerClient.supportsExecutionMode({
        callType: 'call',
        execType: 'default',
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );
});

test('supportsExecutionMode returns true', async t => {
  await t.context.deployAccount();
  const client = t.context.bundlerClient;
  await Promise.all([
    client.supportsExecutionMode({ callType: 'call', execType: 'default' }),
    client.supportsExecutionMode({ callType: 'batchcall', execType: 'try' }),
    client.supportsExecutionMode({
      callType: 'batchcall',
      execType: 'try',
      selector: '0x12345678',
      payload: '0x00000000000000000000000000000000000000000000',
    }),
  ]).then(result => t.deepEqual(result, [true, true, true]));
});

test('supportsModule throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).supportsModule({
        type: 'validator',
        account: undefined as unknown as SmartAccount,
      }),
    {
      message: /Account not found/,
    },
  );
});

test('supportsModule reverts if not deployed', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).supportsModule({
        account: t.context.account,
        type: 'validator',
      }),
    {
      instanceOf: ContractFunctionExecutionError,
    },
  );

  await t.throwsAsync(async () => t.context.bundlerClient.supportsModule({ type: 'validator' }), {
    instanceOf: ContractFunctionExecutionError,
  });
});

test('supportsModule returns true', async t => {
  await t.context.deployAccount();
  await Promise.all([
    t.context.bundlerClient.supportsModule({ type: 'validator' }),
    t.context.bundlerClient.supportsModule({ type: 'executor' }),
    t.context.bundlerClient.supportsModule({ type: 'hook' }),
    t.context.bundlerClient.supportsModule({ type: 'fallback' }),
  ]).then(result => t.deepEqual(result, [true, true, false, true]));
});

test('installModules throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).installModules({
        account: undefined as unknown as SmartAccount,
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /Account not found/,
    },
  );
});

test('installModules throws with no modules', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).installModules({
        account: t.context.account,
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /No modules to install/,
    },
  );
  await t.throwsAsync(
    async () =>
      t.context.bundlerClient.installModules({
        modules: [],
      }),
    {
      message: /No modules to install/,
    },
  );
});

test('uninstallModules throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).uninstallModules({
        account: undefined as unknown as SmartAccount,
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /Account not found/,
    },
  );
});

test('uninstallModules throws with no modules', async t => {
  const testClient = (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions());
  await t.throwsAsync(
    async () =>
      testClient.uninstallModules({
        account: t.context.account,
        entryPointAddress: entryPoint09Address,
        modules: [],
      }),
    {
      message: /No modules to uninstall/,
    },
  );
  await t.throwsAsync(async () => t.context.bundlerClient.uninstallModules({ modules: [] }), {
    message: /No modules to uninstall/,
  });
});

test('installModules and uninstallModules', async t => {
  const bundlerClient = t.context.bundlerClient;
  const deployer = await createAndFundEOA(t.context.testClient);

  const validators: InstallModulesParameters<typeof t.context.account>['modules'] = [
    {
      type: 'validator',
      address: (await deployECDSAValidator(deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
    {
      type: 'validator',
      address: (await deployECDSAValidator(deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
    {
      type: 'validator',
      address: (await deployECDSAValidator(deployer)).address,
      initData: encodePacked(['address'], [privateKeyToAccount(generatePrivateKey()).address]),
    },
  ];

  // Install 1
  // First user op deploys the account
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.installModules({
        modules: validators.slice(0, 1),
        nonce,
      }),
    )
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Install 2
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.installModules({
        modules: validators.slice(1, 3),
        nonce,
      }),
    )
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  for (const validator of validators) {
    await bundlerClient
      .isModuleInstalled({
        type: 'validator',
        address: validator.address,
      })
      .then(installed => t.is(installed, true));
  }

  // Uninstall 1
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.uninstallModules({
        modules: validators.slice(2, 3),
        nonce,
      }),
    )
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));

  // Uninstall 2
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.uninstallModules({
        modules: validators.slice(0, 2),
        nonce,
      }),
    )
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

test('execute throws without account', async t => {
  await t.throwsAsync(
    async () =>
      (t.context.testClient as Client<Transport, undefined, SmartAccount>).extend(erc7579Actions()).execute({
        account: undefined as unknown as SmartAccount,
        entryPointAddress: entryPoint09Address,
        calls: [],
      }),
    {
      message: /Account not found/,
    },
  );
});

test('execute user operations with single call', async t => {
  const bundlerClient = t.context.bundlerClient;
  const receiver = privateKeyToAccount(generatePrivateKey());
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.execute({
        calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }],
        nonce,
      }),
    )
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));
});

test('execute user operations with batch call', async t => {
  const bundlerClient = t.context.bundlerClient;
  const receiver = privateKeyToAccount(generatePrivateKey());
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      bundlerClient.execute({
        calls: [
          { to: receiver.address, data: '0x', value: parseEther('1') },
          { to: receiver.address, data: '0x', value: parseEther('2') },
          { to: receiver.address, data: '0x', value: parseEther('3') },
        ],
        nonce,
      }),
    )
    .then(hash => bundlerClient.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('6')));
});
