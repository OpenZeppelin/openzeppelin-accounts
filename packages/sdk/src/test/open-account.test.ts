import _test, { TestFn } from 'ava';
import {
  bytesToHex,
  GetContractReturnType,
  http,
  encodePacked,
  parseEther,
  publicActions,
  Transport,
  Client,
  Chain,
  LocalAccount,
  RpcSchema,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { BundlerClient, createBundlerClient, SmartAccount } from 'viem/account-abstraction';
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import { deployECDSAValidator, validatorNonceKey } from './helpers/erc7579.modules.js';
import { setup, cleanup } from './helpers/setup.js';
import { erc7579Actions, ERC7579Actions } from '../erc7579.actions.js';
import { MODULE_TYPE_VALIDATOR } from '../erc7579.utils.js';
import { toOpenAccount } from '../open-account.js';
import {
  OpenAccountContext,
  createAndFundOpenAccount,
  createAndFundEOA,
  estimateGasOverride,
} from './helpers/accounts.js';

interface OpenAccountTestContext extends OpenAccountContext {
  ECDSAValidator: GetContractReturnType<typeof ECDSAValidatorArtifact.abi>;
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
}

const test = _test as TestFn<OpenAccountTestContext>;

test.before(setup);
test.after.always(cleanup);

test.beforeEach(async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  t.context.ECDSAValidator = await deployECDSAValidator(deployer);
  await createAndFundOpenAccount(t, {
    validator: t.context.ECDSAValidator.address,
    signerKey: privateKeyToAccount(generatePrivateKey()),
    salt: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
  });
  t.context.bundlerClient = createBundlerClient({
    account: t.context.account,
    client: t.context.testClient,
    transport: http(`http://localhost:${t.context.bundlerPort}/`),
  }).extend(erc7579Actions());
});

test('installs, uses, and uninstalls ECDSAValidator module', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const validator = await deployECDSAValidator(deployer);
  const signer = privateKeyToAccount(generatePrivateKey());
  const client = t.context.bundlerClient;

  // Install module
  await t.context.account
    .getNonce({ key: validatorNonceKey(t.context.ECDSAValidator.address) })
    .then(nonce =>
      client.installModules({
        modules: [
          {
            type: MODULE_TYPE_VALIDATOR,
            address: validator.address,
            initData: encodePacked(['address'], [signer.address]),
          },
        ],
        nonce,
      }),
    )
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await client
    .isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, true));

  // Instantiate account and bundler client with new signer
  const accountWithNewSigner = await toOpenAccount({
    address: t.context.account.address, // Deployed in first user op
    signer,
    client: t.context.testClient as Client<Transport, Chain, LocalAccount, RpcSchema>,
    getStubSignature: async () => bytesToHex(crypto.getRandomValues(new Uint8Array(65))),
    userOperation: {
      estimateGas: userOp =>
        estimateGasOverride(userOp)(t.context.bundlerPort, t.context.account, t.context.testClient),
    },
  });
  const clientWithNewSigner = createBundlerClient({
    account: accountWithNewSigner,
    client: t.context.testClient,
    transport: http(`http://localhost:${t.context.bundlerPort}/`),
  }).extend(erc7579Actions());

  // Use module
  const receiver = privateKeyToAccount(generatePrivateKey());
  await accountWithNewSigner
    .getNonce({ key: validatorNonceKey(validator.address) })
    .then(nonce =>
      clientWithNewSigner.execute({
        calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }],
        nonce,
      }),
    )
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));

  // Uninstall module
  await accountWithNewSigner
    .getNonce({ key: validatorNonceKey(validator.address) })
    .then(nonce =>
      clientWithNewSigner.uninstallModules({
        modules: [{ type: MODULE_TYPE_VALIDATOR, address: validator.address, deInitData: '0x' }],
        nonce,
      }),
    )
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await client
    .isModuleInstalled({
      type: MODULE_TYPE_VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, false));
});
