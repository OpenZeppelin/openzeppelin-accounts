import 'viem/window';
import _test, { TestFn } from 'ava';
import {
  bytesToHex,
  decodeAbiParameters,
  encodeFunctionData,
  getContract,
  hashStruct,
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
import { CrossChainAppMockArtifact } from '../../artifacts/CrossChainAppMock.js';
import { setup, cleanup, type Context } from '../helpers/setup.js';
import { createAndFundEOA } from '../helpers/accounts.js';
import { ERC7964_MAGIC, signCrossChainEnvelopes, toCrossChainSigner } from '../../signers/crosschain.js';
import { toSigner } from '../../signers/index.js';

const test = _test as TestFn<Context>;

test.before(setup);
test.after.always(cleanup);

const application = '0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd' as const;

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
    abi: CrossChainAppMockArtifact.abi,
    bytecode: CrossChainAppMockArtifact.bytecode.object as Hex,
    args: ['CrossChainAppMock', '1.0.0'],
    nonce: await deployer.getTransactionCount({ address: deployer.account.address }),
  });
  const receipt = await deployer.waitForTransactionReceipt({ hash });
  return getContract({
    abi: CrossChainAppMockArtifact.abi,
    address: receipt.contractAddress as Address,
    client: deployer,
  });
};

const makeChainMockOperation = (chainId: bigint, verifyingContract: Address, value: bigint): TypedDataDefinition => ({
  types: operationTypes as unknown as TypedDataDefinition['types'],
  primaryType: 'ChainOperation',
  domain: { name: 'CrossChainAppMock', version: '1.0.0' },
  message: { domain: { chainId, verifyingContract }, value },
});

test('envelope layout: magic, fields, structIndex, application, structsArray, signature', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n), makeOperation(42161n, application, 42n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 1,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelope = await wrapper.signTypedData(operations[1]!);

  const [header, structsArray, crossChainSignature] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    envelope,
  );

  t.is(slice(header, 0, 9), ERC7964_MAGIC, 'magic prefix');
  t.is(slice(header, 9, 10), '0x03', 'fields default');
  t.is(slice(header, 10, 12), '0x0001', 'structIndex = 1');
  t.is(slice(header, 12, 32).toLowerCase(), application.toLowerCase(), 'application');
  t.is(structsArray.length, 2);
  t.is(
    structsArray[1],
    hashStruct({
      data: operations[1]!.message as Record<string, unknown>,
      primaryType: 'ChainOperation',
      types: operationTypes as Record<string, readonly { name: string; type: string }[]>,
    }),
    'structsArray[1] matches local hashStruct',
  );

  // The inner signature recovers to the EOA against the chainId-free outer typed data,
  // where `operations` is the full ChainOperation[] (viem hashes it per EIP-712).
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

test('signTypedData with a mismatched payload throws', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  await t.throwsAsync(() => wrapper.signTypedData(makeOperation(1n, application, 999n)), {
    message: /do not match operations\[0\]/,
  });
});

test('domain.verifyingContract: envelope fields=0x0b, inner sig recovers against verifyingContract-included domain', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1', verifyingContract: application },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelope = await wrapper.signTypedData(operations[0]!);
  const [header, structsArray, crossChainSignature] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    envelope,
  );
  t.is(slice(header, 9, 10), '0x0b', 'fields = name | version | verifyingContract');

  const outerDigest = hashTypedData({
    domain: { name: 'CrossChainApp', version: '1', verifyingContract: application },
    primaryType: 'SetValue',
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'verifyingContract', type: 'address' },
      ],
      ...crossChainTypes,
    } as unknown as TypedDataDefinition['types'],
    message: { operations: operations.map(o => o.message) },
  });
  t.is(structsArray.length, 1);
  const recovered = await recoverAddress({ hash: outerDigest, signature: crossChainSignature });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('explicit fields=0x0b without domain.verifyingContract: verifyingContract defaults to application', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 1n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations,
    fields: '0x0b',
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelope = await wrapper.signTypedData(operations[0]!);
  const [header, , crossChainSignature] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    envelope,
  );
  t.is(slice(header, 9, 10), '0x0b');

  // The outer signed digest must include verifyingContract === application.
  const outerDigest = hashTypedData({
    domain: { name: 'CrossChainApp', version: '1', verifyingContract: application },
    primaryType: 'SetValue',
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'verifyingContract', type: 'address' },
      ],
      ...crossChainTypes,
    } as unknown as TypedDataDefinition['types'],
    message: { operations: operations.map(o => o.message) },
  });
  const recovered = await recoverAddress({ hash: outerDigest, signature: crossChainSignature });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('explicit fields=0x03 with domain.verifyingContract set: throws (bit disagrees with domain)', t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 1n)];

  t.throws(
    () =>
      toCrossChainSigner(inner, {
        application,
        currentChainIndex: 0,
        operations,
        fields: '0x03',
        domain: { name: 'CrossChainApp', version: '1', verifyingContract: application },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
    { message: /disagree/ },
  );
});

test('fields byte with unsupported bits (chainId 0x04, salt 0x10) throws', t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 1n)];

  // 0x07 = name | version | chainId — chainId is forbidden by ERC-7964 outer domain.
  t.throws(
    () =>
      toCrossChainSigner(inner, {
        application,
        currentChainIndex: 0,
        operations,
        fields: '0x07',
        domain: { name: 'CrossChainApp', version: '1' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
    { message: /bits outside/ },
  );

  // 0x13 = name | version | salt — salt is not emitted by the SDK.
  t.throws(
    () =>
      toCrossChainSigner(inner, {
        application,
        currentChainIndex: 0,
        operations,
        fields: '0x13',
        domain: { name: 'CrossChainApp', version: '1' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
    { message: /bits outside/ },
  );
});

test('config.operations mutation after construction does not affect the envelope', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 100n), makeOperation(42161n, application, 100n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  // Mutate the caller's array after construction — the wrapper must ignore it.
  operations.push(makeOperation(10n, application, 999n));
  operations[0] = makeOperation(1n, application, 555n);

  const envelope = await wrapper.signTypedData(makeOperation(1n, application, 100n));
  const [, structsArray] = decodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']), envelope);
  t.is(structsArray.length, 2, 'operations count frozen at construction');
});

test('mismatch error surface includes both expected and incoming primaryType + hashStruct', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const wrong: TypedDataDefinition = {
    types: { Other: [{ name: 'x', type: 'uint256' }] },
    primaryType: 'Other',
    domain: { name: 'CrossChainApp', version: '1' },
    message: { x: 1n },
  };

  await t.throwsAsync(() => wrapper.signTypedData(wrong), {
    message: /expected primaryType "ChainOperation".*got primaryType "Other"/s,
  });
});

test('signMessage on a cross-chain signer throws', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations: [makeOperation(1n, application, 1n)],
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  await t.throwsAsync(() => wrapper.signMessage({ message: 'nope' }), { message: /EIP-712 only/ });
});

test('signCrossChainEnvelopes returns N envelopes from a single inner signature', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [
    makeOperation(1n, application, 7n),
    makeOperation(42161n, application, 7n),
    makeOperation(10n, application, 7n),
  ];

  const envelopes = await signCrossChainEnvelopes(inner, {
    application,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  t.is(envelopes.length, 3);

  // Each envelope shares the same inner signature; only structIndex differs.
  const innerSigs = envelopes.map(
    e => decodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']), e)[2],
  );
  t.is(innerSigs[0], innerSigs[1]);
  t.is(innerSigs[1], innerSigs[2]);

  // Each envelope advertises its own structIndex.
  const indices = envelopes.map(e => {
    const [header] = decodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']), e);
    return Number(BigInt(slice(header, 10, 12)));
  });
  t.deepEqual(indices, [0, 1, 2]);
});

test('out-of-bounds currentChainIndex throws on signTypedData', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 1n)];
  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 5,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  await t.throwsAsync(() => wrapper.signTypedData(operations[0]!), { message: /out of bounds/ });
});

test('resolves currentChainIndex from explicit chainId', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [
    makeOperation(1n, application, 42n),
    makeOperation(42161n, application, 42n),
    makeOperation(10n, application, 42n),
  ];

  const wrapper = toCrossChainSigner(inner, {
    application,
    chainId: 42161n,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelope = await wrapper.signTypedData(operations[1]!);
  const [header] = decodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']), envelope);
  t.is(slice(header, 10, 12), '0x0001', 'structIndex = 1 (Arbitrum)');
});

test('selector precedence: currentChainIndex wins over chainId', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n), makeOperation(42161n, application, 42n)];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    chainId: 42161n,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  const [header] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    await wrapper.signTypedData(operations[0]!),
  );
  t.is(slice(header, 10, 12), '0x0000', 'currentChainIndex wins');
});

test('no selector throws on signTypedData', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n)];
  const wrapper = toCrossChainSigner(inner, {
    application,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  await t.throwsAsync(() => wrapper.signTypedData(operations[0]!), {
    message: /currentChainIndex or chainId/,
  });
});

test('chainId not matching any operation throws', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 42n), makeOperation(42161n, application, 42n)];
  const wrapper = toCrossChainSigner(inner, {
    application,
    chainId: 999n,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  await t.throwsAsync(() => wrapper.signTypedData(operations[0]!), {
    message: /no operation matches chainId 999/,
  });
});

test('chainId lookup finds field at any nesting depth', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);

  // Operations with chainId at different nesting depths — top-level, one-nested, two-nested.
  const topLevelOp: TypedDataDefinition = {
    types: {
      Op: [
        { name: 'chainId', type: 'uint256' },
        { name: 'value', type: 'uint256' },
      ],
    } as unknown as TypedDataDefinition['types'],
    primaryType: 'Op',
    domain: { name: 'X', version: '1' },
    message: { chainId: 7n, value: 1n },
  };
  const oneNestedOp: TypedDataDefinition = makeOperation(11n, application, 1n); // chainId inside .domain
  const twoNestedOp: TypedDataDefinition = {
    types: {
      Outer: [{ name: 'inner', type: 'Middle' }],
      Middle: [{ name: 'deep', type: 'Deep' }],
      Deep: [{ name: 'chainId', type: 'uint256' }],
    } as unknown as TypedDataDefinition['types'],
    primaryType: 'Outer',
    domain: { name: 'X', version: '1' },
    message: { inner: { deep: { chainId: 22n } } },
  };

  const operations = [topLevelOp, oneNestedOp, twoNestedOp];

  for (const [chainId, expectedIdx] of [
    [7n, 0],
    [11n, 1],
    [22n, 2],
  ] as const) {
    const wrapper = toCrossChainSigner(inner, {
      application,
      chainId,
      operations,
      domain: { name: 'X', version: '1' },
      primaryType: 'SetValue',
      types: {
        SetValue: [{ name: 'operations', type: 'string[]' }], // types don't matter for the resolve path
      } as unknown as TypedDataDefinition['types'],
    });
    const envelope = await wrapper.signTypedData(operations[expectedIdx]!);
    const [header] = decodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']), envelope);
    t.is(Number(BigInt(slice(header, 10, 12))), expectedIdx, `chainId ${chainId} → index ${expectedIdx}`);
  }
});

test('wrapper.signCrossChainEnvelopes matches standalone signCrossChainEnvelopes', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [
    makeOperation(1n, application, 3n),
    makeOperation(42161n, application, 3n),
    makeOperation(10n, application, 3n),
  ];
  const baseConfig = {
    application,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  } as const;

  const wrapper = toCrossChainSigner(inner, baseConfig);
  const fromMethod = await wrapper.signCrossChainEnvelopes();
  const fromStandalone = await signCrossChainEnvelopes(inner, baseConfig);

  t.deepEqual(fromMethod, fromStandalone);
});

test('CrossChainSigner is structurally assignable to Signer', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const operations = [makeOperation(1n, application, 1n)];
  const wrapper = toCrossChainSigner(toSigner(eoa), {
    application,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  // Compile-time assignability: passes if it type-checks.
  const asSigner: import('../../signers/index.js').Signer = wrapper;
  t.is(typeof asSigner.signTypedData, 'function');
  t.is(typeof wrapper.signCrossChainEnvelopes, 'function');
});

test('on-chain: ValueSet emitted by every deployed CrossChainAppMock for the correct chain index', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);

  const appCount = 3;
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < appCount; i++) {
    apps.push(await deployApp(deployer));
  }

  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 1234n;
  const operations = apps.map(app => makeChainMockOperation(chainId, app.address as Address, value));

  const signers = apps.map((_, i) =>
    toCrossChainSigner(toSigner(eoa), {
      application: apps[i]!.address as Address,
      currentChainIndex: i,
      operations,
      domain: { name: 'CrossChainAppMock', version: '1.0.0' },
      primaryType: 'SetValue',
      types: crossChainTypes as unknown as TypedDataDefinition['types'],
    }),
  );

  for (let i = 0; i < apps.length; i++) {
    const envelope = await signers[i]!.signTypedData(operations[i]!);
    const callData = encodeFunctionData({
      abi: CrossChainAppMockArtifact.abi,
      functionName: 'setValueCalldata',
      args: [eoa.address, value, envelope],
    });
    const txHash = await deployer.sendTransaction({ to: apps[i]!.address as Address, data: callData });
    const receipt = await deployer.waitForTransactionReceipt({ hash: txHash });
    t.is(receipt.status, 'success', `setValueCalldata succeeded on app ${i}`);
    t.is((await apps[i]!.read.value!([eoa.address])) as bigint, value, `value persisted on app ${i}`);
  }
});

test('on-chain: wrapper.signCrossChainEnvelopes() — one inner signature, N envelopes accepted on every app', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < 3; i++) apps.push(await deployApp(deployer));

  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 5555n;
  const operations = apps.map(app => makeChainMockOperation(chainId, app.address as Address, value));

  const wrapper = toCrossChainSigner(toSigner(eoa), {
    application: apps[0]!.address as Address,
    operations,
    domain: { name: 'CrossChainAppMock', version: '1.0.0' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelopes = await wrapper.signCrossChainEnvelopes();
  t.is(envelopes.length, apps.length);

  for (let i = 0; i < apps.length; i++) {
    const txHash = await deployer.sendTransaction({
      to: apps[i]!.address as Address,
      data: encodeFunctionData({
        abi: CrossChainAppMockArtifact.abi,
        functionName: 'setValueCalldata',
        args: [eoa.address, value, envelopes[i]!],
      }),
    });
    const receipt = await deployer.waitForTransactionReceipt({ hash: txHash });
    t.is(receipt.status, 'success', `envelope ${i} accepted by app ${i}`);
    t.is((await apps[i]!.read.value!([eoa.address])) as bigint, value);
  }
});

test('on-chain: signing with the wrong structIndex reverts', async t => {
  const deployer = await createAndFundEOA(t.context.anvilPort, t.context.testClient);
  const apps: Awaited<ReturnType<typeof deployApp>>[] = [];
  for (let i = 0; i < 2; i++) {
    apps.push(await deployApp(deployer));
  }
  const eoa = privateKeyToAccount(generatePrivateKey());
  const chainId = BigInt((await deployer.extend(publicActions).getChainId()) as number);
  const value = 7n;
  const operations = apps.map(app => makeChainMockOperation(chainId, app.address as Address, value));

  const signer = toCrossChainSigner(toSigner(eoa), {
    application: apps[0]!.address as Address,
    currentChainIndex: 0,
    operations,
    domain: { name: 'CrossChainAppMock', version: '1.0.0' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });
  const envelope = await signer.signTypedData(operations[0]!);

  await t.throwsAsync(() =>
    deployer.sendTransaction({
      to: apps[1]!.address as Address,
      data: encodeFunctionData({
        abi: CrossChainAppMockArtifact.abi,
        functionName: 'setValueCalldata',
        args: [eoa.address, value, envelope],
      }),
    }),
  );
  t.is((await apps[1]!.read.value!([eoa.address])) as bigint, 0n);
  t.assert(bytesToHex(new Uint8Array(0)) === '0x'); // smoke
});
