import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  bytesToHex,
  GetContractReturnType,
  hashMessage,
  hashTypedData,
  http,
  encodePacked,
  parseEther,
  publicActions,
  Transport,
  Client,
  Chain,
  LocalAccount,
  RpcSchema,
  slice,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { BundlerClient, createBundlerClient, SmartAccount } from 'viem/account-abstraction';
import ECDSAValidatorArtifact from '@open-accounts-framework/contracts/out/ERC7579ECDSAValidator.sol/ERC7579ECDSAValidator.json' with { type: 'json' };
import IERC1271Artifact from '@open-accounts-framework/contracts/out/IERC1271.sol/IERC1271.json' with { type: 'json' };
import { deployECDSAValidator, deployWebAuthnValidator } from './helpers/erc7579.modules.js';
import { setup, cleanup } from './helpers/setup.js';
import { erc7579Actions, ERC7579Actions } from '../erc7579.actions.js';
import { p256 } from '@noble/curves/nist.js';
import { ModuleTypes } from '../erc7579.utils.js';
import { toOpenAccount } from '../open-account.js';
import {
  OpenAccountContext,
  createAndFundOpenAccount,
  createAndFundEOA,
  estimateGasOverride,
} from './helpers/accounts.js';
import { toWebAuthnSigner, webAuthnStubSignature } from './helpers/signers.js';

interface OpenAccountTestContext extends OpenAccountContext {
  initialValidator: GetContractReturnType<typeof ECDSAValidatorArtifact.abi>;
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
}

const test = _test as TestFn<OpenAccountTestContext>;

const ERC1271_MAGIC_VALUE = '0x1626ba7e';

test.before(setup);
test.after.always(cleanup);

test.beforeEach(async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  t.context.initialValidator = await deployECDSAValidator(deployer);
  await createAndFundOpenAccount(t, {
    validator: t.context.initialValidator.address,
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
  await client
    .installModules({
      modules: [
        {
          type: ModuleTypes.VALIDATOR,
          address: validator.address,
          initData: encodePacked(['address'], [signer.address]),
        },
      ],
    })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await client
    .isModuleInstalled({
      type: ModuleTypes.VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, true));

  // Instantiate account and bundler client with new signer
  const accountWithNewSigner = await toOpenAccount({
    address: t.context.account.address, // Deployed in first user op
    signer,
    validator: validator.address,
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
  await clientWithNewSigner
    .execute({ calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }] })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));

  // Uninstall module
  await clientWithNewSigner
    .uninstallModules({
      modules: [{ type: ModuleTypes.VALIDATOR, address: validator.address, deInitData: '0x' }],
    })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await client
    .isModuleInstalled({
      type: ModuleTypes.VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, false));
});

test('installs, uses, and uninstalls WebAuthnValidator module', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const validator = await deployWebAuthnValidator(deployer);
  const privateKey = p256.utils.randomSecretKey();
  const client = t.context.bundlerClient;

  // Install module
  const publicKey = p256.getPublicKey(privateKey, false);
  const qx = slice(publicKey, 0x01, 0x21);
  const qy = slice(publicKey, 0x21, 0x41);
  await client
    .installModules({
      modules: [
        {
          type: ModuleTypes.VALIDATOR,
          address: validator.address,
          initData: encodePacked(['bytes32', 'bytes32'], [bytesToHex(qx), bytesToHex(qy)]),
        },
      ],
    })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await client
    .isModuleInstalled({
      type: ModuleTypes.VALIDATOR,
      address: validator.address,
    })
    .then(installed => t.is(installed, true));

  // Instantiate account and bundler client with new signer
  const accountWithNewSigner = await toOpenAccount({
    address: t.context.account.address, // Deployed in first user op
    signer: toWebAuthnSigner(privateKey),
    validator: validator.address,
    client: t.context.testClient as Client<Transport, Chain, LocalAccount, RpcSchema>,
    getStubSignature: webAuthnStubSignature,
    userOperation: {
      estimateGas: userOp =>
        estimateGasOverride(userOp, 500_000n)(t.context.bundlerPort, t.context.account, t.context.testClient),
    },
  });
  const clientWithNewSigner = createBundlerClient({
    account: accountWithNewSigner,
    client: t.context.testClient,
    transport: http(`http://localhost:${t.context.bundlerPort}/`),
  }).extend(erc7579Actions());

  // Use module
  const receiver = privateKeyToAccount(generatePrivateKey());
  await clientWithNewSigner
    .execute({ calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }] })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));

  // Uninstall module
  await clientWithNewSigner
    .uninstallModules({
      modules: [{ type: ModuleTypes.VALIDATOR, address: validator.address, deInitData: '0x' }],
    })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
});

test('signMessage output passes isValidSignature on-chain', async t => {
  await t.context.deployAccount();
  const message = 'hello ERC-1271';
  const sig = await t.context.account.signMessage({ message });
  await t.context.testClient
    .extend(publicActions)
    .readContract({
      abi: IERC1271Artifact.abi,
      address: t.context.account.address,
      functionName: 'isValidSignature',
      args: [hashMessage(message), sig],
    })
    .then(result => t.is(result, ERC1271_MAGIC_VALUE));
});

test('signTypedData output passes isValidSignature on-chain', async t => {
  await t.context.deployAccount();
  const typedData = {
    domain: { name: 'Test', version: '1' },
    types: { Message: [{ name: 'content', type: 'string' }] },
    primaryType: 'Message' as const,
    message: { content: 'hello ERC-1271' },
  } as const;
  const sig = await t.context.account.signTypedData(typedData);
  await t.context.testClient
    .extend(publicActions)
    .readContract({
      abi: IERC1271Artifact.abi,
      address: t.context.account.address,
      functionName: 'isValidSignature',
      args: [hashTypedData(typedData), sig],
    })
    .then(result => t.is(result, ERC1271_MAGIC_VALUE));
});
