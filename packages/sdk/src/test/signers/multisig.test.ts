import 'viem/window';
import _test, { ExecutionContext, TestFn } from 'ava';
import {
  bytesToHex,
  decodeAbiParameters,
  encodeAbiParameters,
  getContract,
  hashMessage,
  hashTypedData,
  http,
  keccak256,
  parseAbiParameters,
  parseEther,
  publicActions,
  recoverAddress,
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
import OpenAccountFactoryArtifact from '@openzeppelin-accounts/contracts/out/OpenAccountFactory.sol/OpenAccountFactory.json' with { type: 'json' };
import { setup, cleanup } from '../helpers/setup.js';
import { OpenAccountContext, createAndFundEOA, estimateGasOverride } from '../helpers/accounts.js';
import { erc7579Actions, ERC7579Actions } from '../../erc7579.actions.js';
import { toOpenAccount } from '../../open-account.js';
import { toERC7913Signer } from '../../signers/erc7913.js';
import { toMultisigner } from '../../signers/multisig.js';
import { toSigner } from '../../signers/index.js';

interface MultisigTestContext extends OpenAccountContext {
  bundlerClient: Omit<
    BundlerClient<Transport, undefined, SmartAccount>,
    'client' | 'paymaster' | 'paymasterContext' | 'userOperation'
  > &
    ERC7579Actions<SmartAccount>;
  eoaA: LocalAccount;
  eoaB: LocalAccount;
}

const test = _test as TestFn<MultisigTestContext>;

test.before(setup);
test.after.always(cleanup);

const ERC1271_MAGIC_VALUE = '0x1626ba7e';

const deployMultisigValidator = async (deployer: Awaited<ReturnType<typeof createAndFundEOA>>) => {
  const hash = await deployer.deployContract({
    abi: ERC7579MultisigValidatorArtifact.abi,
    bytecode: ERC7579MultisigValidatorArtifact.bytecode.object as `0x${string}`,
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return { address: receipt.contractAddress as Address };
};

const encodeMultisigInitData = (signerBytes: `0x${string}`[], threshold: bigint): `0x${string}` =>
  encodeAbiParameters(
    [
      { type: 'bytes[]', name: 'signers' },
      { type: 'uint64', name: 'threshold' },
    ],
    [signerBytes, threshold],
  );

/**
 * Fresh setup per integration test: deploys a multisig validator, a factory, and an
 * OpenAccount installed with a 2-of-2 multisig of `eoaA` (pair-form) + `eoaB` (wrapped).
 */
const setupMultisigAccount = async (t: ExecutionContext<MultisigTestContext>) => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const validator = await deployMultisigValidator(deployer);
  t.context.eoaA = privateKeyToAccount(generatePrivateKey());
  t.context.eoaB = privateKeyToAccount(generatePrivateKey());

  const signerBytes: `0x${string}`[] = [
    t.context.eoaA.address.toLowerCase() as `0x${string}`,
    t.context.eoaB.address.toLowerCase() as `0x${string}`,
  ];

  const signer = toMultisigner([
    { signer: toSigner(t.context.eoaA), signerBytes: signerBytes[0]! },
    toERC7913Signer(toSigner(t.context.eoaB), { address: t.context.eoaB.address }),
  ]);

  const factoryHash = await deployer.deployContract({
    abi: OpenAccountFactoryArtifact.abi,
    bytecode: OpenAccountFactoryArtifact.bytecode.object as `0x${string}`,
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const factoryReceipt = await deployer.waitForTransactionReceipt({ hash: factoryHash });
  t.context.factory = getContract({
    address: factoryReceipt.contractAddress as Address,
    abi: OpenAccountFactoryArtifact.abi,
    client: t.context.testClient,
  });

  t.context.account = await toOpenAccount({
    client: t.context.testClient as Client<Transport, Chain, LocalAccount, RpcSchema>,
    signer,
    validator: validator.address,
    factory: t.context.factory,
    moduleTypeIds: [1],
    modules: [validator.address],
    initDatas: [encodeMultisigInitData(signerBytes, 2n)],
    salt: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
    getStubSignature: async () =>
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

  t.context.bundlerClient = createBundlerClient({
    account: t.context.account,
    client: t.context.testClient,
    transport: http(`http://localhost:${t.context.bundlerPort}/`),
  }).extend(erc7579Actions());
};

test('produces abi.encode(bytes[] signers, bytes[] sigs), sorted by keccak256(signerBytes)', async t => {
  const eoaA = privateKeyToAccount(generatePrivateKey());
  const eoaB = privateKeyToAccount(generatePrivateKey());
  const message = 'multisig hello';

  const multisig = toMultisigner([
    { signer: toSigner(eoaA), signerBytes: eoaA.address.toLowerCase() as `0x${string}` },
    { signer: toSigner(eoaB), signerBytes: eoaB.address.toLowerCase() as `0x${string}` },
  ]);

  const envelope = await multisig.signMessage({ message });
  const [signers, signatures] = decodeAbiParameters(parseAbiParameters(['bytes[]', 'bytes[]']), envelope);

  // Sorted by keccak256(signerBytes) ascending.
  const sortedHashes = [...signers].map(s => keccak256(s)).sort();
  const actualHashes = [...signers].map(s => keccak256(s));
  t.deepEqual(actualHashes, sortedHashes);

  // Each signature recovers to its paired address.
  for (let i = 0; i < signers.length; i++) {
    const recovered = await recoverAddress({ hash: hashMessage(message), signature: signatures[i]! });
    t.is(recovered.toLowerCase(), signers[i]!.toLowerCase());
  }
});

test('accepts already-ERC7913-wrapped signers and uses their raw inner sigs (no double envelope)', async t => {
  const eoaA = privateKeyToAccount(generatePrivateKey());
  const eoaB = privateKeyToAccount(generatePrivateKey());

  const sA = toERC7913Signer(toSigner(eoaA), { address: eoaA.address });
  const sB = toERC7913Signer(toSigner(eoaB), { address: eoaB.address });
  const multisig = toMultisigner([sA, sB]);

  const envelope = await multisig.signMessage({ message: 'mixed' });
  const [, signatures] = decodeAbiParameters(parseAbiParameters(['bytes[]', 'bytes[]']), envelope);

  // Each signature is a raw 65-byte ECDSA sig, not an abi.encode(bytes,bytes) envelope.
  for (const sig of signatures) {
    t.is(sig.length, 132, 'raw ECDSA signature');
  }
});

test('mixes pair-form and wrapped-form inputs in a single multisig', async t => {
  const eoaA = privateKeyToAccount(generatePrivateKey());
  const eoaB = privateKeyToAccount(generatePrivateKey());

  const sWrapped = toERC7913Signer(toSigner(eoaA), { address: eoaA.address });
  const multisig = toMultisigner([
    sWrapped,
    { signer: toSigner(eoaB), signerBytes: eoaB.address.toLowerCase() as `0x${string}` },
  ]);

  const envelope = await multisig.signMessage({ message: 'mixed' });
  const [signers] = decodeAbiParameters(parseAbiParameters(['bytes[]', 'bytes[]']), envelope);
  t.is(signers.length, 2);
});

test('empty inputs throws', t => {
  t.throws(() => toMultisigner([]), { message: /At least one signer/ });
});

test('on-chain: signMessage from toMultisigner (mixed pair + wrapped) passes ERC-1271 isValidSignature', async t => {
  await setupMultisigAccount(t);
  await t.context.deployAccount();
  const message = 'multisig signed';
  const sig = await t.context.account.signMessage({ message });

  const result = await t.context.testClient.extend(publicActions).readContract({
    abi: IERC1271Artifact.abi,
    address: t.context.account.address,
    functionName: 'isValidSignature',
    args: [hashMessage(message), sig],
  });
  t.is(result, ERC1271_MAGIC_VALUE);
});

test('on-chain: signTypedData from toMultisigner passes ERC-1271 isValidSignature', async t => {
  await setupMultisigAccount(t);
  await t.context.deployAccount();
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

test('on-chain: UserOp signed by toMultisigner is executed by the bundler', async t => {
  await setupMultisigAccount(t);
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
