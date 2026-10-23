import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  decodeAbiParameters,
  encodeFunctionData,
  getContract,
  hashTypedData,
  parseAbiParameters,
  publicActions,
  recoverAddress,
  slice,
  TypedDataDefinition,
  type Address,
  type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { ERC7913CrossChainAppMockArtifact } from '../../artifacts/ERC7913CrossChainAppMock.js';
import { setup, cleanup, type Context } from '../helpers/setup.js';
import { createAndFundEOA } from '../helpers/accounts.js';
import { ERC7964_MAGIC, toCrossChainSigner } from '../../signers/crosschain.js';
import { toERC7913Signer } from '../../signers/erc7913.js';
import { toSigner } from '../../signers/index.js';

const test = _test as TestFn<Context>;

test.before(setup);
test.after.always(cleanup);

const application = '0xcafecafecafecafecafecafecafecafecafecafe' as const;

const crossChainTypes = {
  SetValue: [{ name: 'operations', type: 'ChainOperation[]' }],
  ChainOperation: [
    { name: 'domain', type: 'EIP712ChainDomain' },
    { name: 'value', type: 'uint256' },
  ],
  EIP712ChainDomain: [
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
} as const;

const operationTypes = {
  ChainOperation: crossChainTypes.ChainOperation,
  EIP712ChainDomain: crossChainTypes.EIP712ChainDomain,
} as const;

const makeOperation = (chainId: bigint, verifyingContract: `0x${string}`, value: bigint): TypedDataDefinition => ({
  types: operationTypes as unknown as TypedDataDefinition['types'],
  primaryType: 'ChainOperation',
  domain: { name: 'CrossChainApp', version: '1' },
  message: { domain: { chainId, verifyingContract }, value },
});

const deployApp = async (deployer: Awaited<ReturnType<typeof createAndFundEOA>>) => {
  const hash = await deployer.deployContract({
    abi: ERC7913CrossChainAppMockArtifact.abi,
    bytecode: ERC7913CrossChainAppMockArtifact.bytecode.object as Hex,
    args: ['ERC7913CrossChainAppMock', '1.0.0'],
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return getContract({
    abi: ERC7913CrossChainAppMockArtifact.abi,
    address: receipt.contractAddress as Address,
    client: deployer,
  });
};

test('toERC7913Signer(toCrossChainSigner(eoa)): unwraps in two passes to recover the EOA', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const operations = [makeOperation(1n, application, 100n), makeOperation(42161n, application, 100n)];

  const crossChainSigner = toCrossChainSigner(toSigner(eoa), {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  const composed = toERC7913Signer(crossChainSigner, { address: eoa.address });

  // Composed signature is abi.encode(signerBytes, crossChainEnvelope).
  const composedSig = await composed.signTypedData(operations[0]!);

  // Pass 1: strip ERC-7913 envelope.
  const [signerBytes, crossChainEnvelope] = decodeAbiParameters(parseAbiParameters(['bytes', 'bytes']), composedSig);
  t.is(signerBytes.toLowerCase(), eoa.address.toLowerCase());

  // Pass 2: strip ERC-7964 envelope.
  const [header, structsArray, crossChainSignature] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    crossChainEnvelope,
  );
  t.is(slice(header, 0, 10), ERC7964_MAGIC);
  t.is(structsArray.length, 2);

  const outerDigest = hashTypedData({
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
      ],
      ...crossChainTypes,
    } as unknown as TypedDataDefinition['types'],
    message: { operations: operations.map(o => o.message) },
  });
  const recovered = await recoverAddress({ hash: outerDigest, signature: crossChainSignature });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('composition: toERC7913Signer(toCrossChainSigner(eoa)) verifies on-chain via ERC7913CrossChainAppMock', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < 2; i++) apps.push(await deployApp(deployer));

  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 5678n;
  const operations = apps.map(app => makeOperation(chainId, app.address as Address, value));

  for (let i = 0; i < apps.length; i++) {
    const composed = toERC7913Signer(
      toCrossChainSigner(toSigner(eoa), {
        application: apps[i]!.address as Address,
        currentChainIndex: i,
        operations,
        domain: { name: 'ERC7913CrossChainAppMock', version: '1.0.0' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
      { address: eoa.address },
    );

    const composedSig = await composed.signTypedData(operations[i]!);

    const txHash = await deployer.sendTransaction({
      to: apps[i]!.address as Address,
      data: encodeFunctionData({
        abi: ERC7913CrossChainAppMockArtifact.abi,
        functionName: 'setValue',
        args: [value, composedSig],
      }),
    });
    const receipt = await deployer.waitForTransactionReceipt({ hash: txHash });
    t.is(receipt.status, 'success', `setValue succeeded on app ${i}`);

    const stored = (await apps[i]!.read.value!([eoa.address])) as bigint;
    t.is(stored, value, `value persisted on app ${i}`);
  }
});
