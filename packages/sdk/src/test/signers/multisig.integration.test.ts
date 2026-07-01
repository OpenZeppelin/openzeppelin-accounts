import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  bytesToHex,
  encodeAbiParameters,
  GetContractReturnType,
  http,
  parseEther,
  publicActions,
  type Address,
  type Chain,
  type Client,
  type LocalAccount,
  type RpcSchema,
  type Transport,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { BundlerClient, createBundlerClient, SmartAccount } from 'viem/account-abstraction';
import ERC7579MultisigValidatorArtifact from '@openzeppelin-accounts/contracts/out/ERC7579MultisigValidator.sol/ERC7579MultisigValidator.json' with { type: 'json' };
import IERC1271Artifact from '@openzeppelin-accounts/contracts/out/IERC1271.sol/IERC1271.json' with { type: 'json' };
import { setup, cleanup } from '../helpers/setup.js';
import { OpenAccountContext, createAndFundEOA, estimateGasOverride } from '../helpers/accounts.js';
import { erc7579Actions, ERC7579Actions } from '../../erc7579.actions.js';
import { toOpenAccount } from '../../open-account.js';
import { toMultisigSigner } from '../../signers/to-multisig-signer.js';
import { toSigner } from '../../signers/to-signer.js';
import { toERC7913Signer } from '../../signers/to-erc7913-signer.js';

interface MultisigTestContext extends OpenAccountContext {
  initialValidator: GetContractReturnType<typeof ERC7579MultisigValidatorArtifact.abi>;
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
  eoaA: LocalAccount;
  eoaB: LocalAccount;
}

const test = _test as TestFn<MultisigTestContext>;

const deployMultisigValidator = async (deployer: Awaited<ReturnType<typeof createAndFundEOA>>) => {
  const hash = await deployer.deployContract({
    abi: ERC7579MultisigValidatorArtifact.abi,
    bytecode: ERC7579MultisigValidatorArtifact.bytecode.object as `0x${string}`,
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return { address: receipt.contractAddress as Address };
};

const installSignerBytes = (signerBytes: `0x${string}`[], threshold: bigint): `0x${string}` =>
  encodeAbiParameters(
    [
      { type: 'bytes[]', name: 'signers' },
      { type: 'uint64', name: 'threshold' },
    ],
    [signerBytes, threshold],
  );

test.before(setup);
test.after.always(cleanup);

test.beforeEach(async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const validator = await deployMultisigValidator(deployer);
  t.context.initialValidator = { address: validator.address } as GetContractReturnType<
    typeof ERC7579MultisigValidatorArtifact.abi
  >;
  t.context.eoaA = privateKeyToAccount(generatePrivateKey());
  t.context.eoaB = privateKeyToAccount(generatePrivateKey());

  // Sort signers by keccak256 isn't needed at install time; multisig stores them in a set.
  // Use lowercase address bytes as the ERC-7913 signerBytes (verifier-less shortcut).
  const signerBytes: `0x${string}`[] = [
    t.context.eoaA.address.toLowerCase() as `0x${string}`,
    t.context.eoaB.address.toLowerCase() as `0x${string}`,
  ];

  // Build the SDK Signer first so we can pass it to toOpenAccount.
  const signer = toMultisigSigner([
    { signer: toSigner(t.context.eoaA), signerBytes: signerBytes[0]! },
    toERC7913Signer(toSigner(t.context.eoaB), { address: t.context.eoaB.address }),
  ]);

  await createAndFundOpenAccountWithSigner(t, {
    validator: validator.address,
    signer,
    initData: installSignerBytes(signerBytes, 2n),
    salt: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
  });

  t.context.bundlerClient = createBundlerClient({
    account: t.context.account,
    client: t.context.testClient,
    transport: http(`http://localhost:${t.context.bundlerPort}/`),
  }).extend(erc7579Actions());
});

/**
 * Variant of createAndFundOpenAccount that installs a multisig validator with arbitrary
 * initData and accepts an SDK Signer (not just a LocalAccount).
 */
const createAndFundOpenAccountWithSigner = async (
  t: { context: MultisigTestContext },
  args: {
    validator: Address;
    signer: ReturnType<typeof toMultisigSigner>;
    initData: `0x${string}`;
    salt: `0x${string}`;
  },
) => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  // Deploy a fresh factory so this test's account is independent.
  const OpenAccountFactoryArtifact = (
    await import('@openzeppelin-accounts/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json', {
      with: { type: 'json' },
    })
  ).default;
  const factoryHash = await deployer.deployContract({
    abi: OpenAccountFactoryArtifact.abi,
    bytecode: OpenAccountFactoryArtifact.bytecode.object as `0x${string}`,
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const factoryReceipt = await deployer.waitForTransactionReceipt({ hash: factoryHash });
  const factoryAddress = factoryReceipt.contractAddress as Address;

  // viem.getContract for factory.
  const { getContract } = await import('viem');
  t.context.factory = getContract({
    address: factoryAddress,
    abi: OpenAccountFactoryArtifact.abi,
    client: t.context.testClient,
  });

  t.context.account = await toOpenAccount({
    client: t.context.testClient as Client<Transport, Chain, LocalAccount, RpcSchema>,
    signer: args.signer,
    validator: args.validator,
    factory: t.context.factory,
    moduleTypeIds: [1], // ModuleTypes.VALIDATOR
    modules: [args.validator],
    initDatas: [args.initData],
    salt: args.salt,
    getStubSignature: async () =>
      // For multisig stub: two 65-byte dummy ECDSA sigs in the abi.encode(bytes[],bytes[]) layout
      encodeAbiParameters(
        [{ type: 'bytes[]' }, { type: 'bytes[]' }],
        [
          [
            t.context.eoaA.address.toLowerCase() as `0x${string}`,
            t.context.eoaB.address.toLowerCase() as `0x${string}`,
          ],
          [bytesToHex(new Uint8Array(65)), bytesToHex(new Uint8Array(65))],
        ],
      ),
    userOperation: {
      estimateGas: userOp =>
        estimateGasOverride(userOp, 500_000n)(t.context.bundlerPort, t.context.account, t.context.testClient),
    },
  });

  await t.context.testClient.setBalance({ address: t.context.account.address, value: parseEther('100') });
  t.context.deployAccount = () =>
    t.context.account.getFactoryArgs().then(async ({ factory, factoryData }) =>
      deployer
        .sendTransaction({
          to: factory as Address,
          data: factoryData as `0x${string}`,
          nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
        })
        .then(hash => deployer.waitForTransactionReceipt({ hash })),
    );
};

const ERC1271_MAGIC_VALUE = '0x1626ba7e';

test('signMessage from toMultisigSigner (mixed pair + wrapped) passes ERC-1271 isValidSignature', async t => {
  await t.context.deployAccount();
  const message = 'multisig signed';
  const sig = await t.context.account.signMessage({ message });

  const result = await t.context.testClient.extend(publicActions).readContract({
    abi: IERC1271Artifact.abi,
    address: t.context.account.address,
    functionName: 'isValidSignature',
    args: [
      // hashMessage for plain string
      (await import('viem')).hashMessage(message),
      sig,
    ],
  });
  t.is(result, ERC1271_MAGIC_VALUE);
});

test('signTypedData from toMultisigSigner passes ERC-1271 isValidSignature', async t => {
  await t.context.deployAccount();
  const { hashTypedData } = await import('viem');
  const typedData = {
    domain: { name: 'Multisig', version: '1' },
    types: { Msg: [{ name: 'content', type: 'string' }] },
    primaryType: 'Msg' as const,
    message: { content: 'hello' },
  } as const;
  const sig = await t.context.account.signTypedData(typedData);
  const result = await t.context.testClient.extend(publicActions).readContract({
    abi: IERC1271Artifact.abi,
    address: t.context.account.address,
    functionName: 'isValidSignature',
    args: [hashTypedData(typedData), sig],
  });
  t.is(result, ERC1271_MAGIC_VALUE);
});

test('UserOp signed by toMultisigSigner is executed by the bundler', async t => {
  const client = t.context.bundlerClient;
  const receiver = privateKeyToAccount(generatePrivateKey());
  await client
    .execute({ calls: [{ to: receiver.address, data: '0x', value: parseEther('1') }] })
    .then(hash => client.waitForUserOperationReceipt({ hash }));
  await t.context.testClient
    .extend(publicActions)
    .getBalance({ address: receiver.address })
    .then(balance => t.is(balance, parseEther('1')));
});
