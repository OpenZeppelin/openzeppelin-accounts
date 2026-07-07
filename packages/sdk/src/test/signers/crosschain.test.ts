import test from 'ava';
import {
  decodeAbiParameters,
  hashStruct,
  hashTypedData,
  parseAbiParameters,
  recoverAddress,
  slice,
  TypedDataDefinition,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { ERC7964_MAGIC, signCrossChainEnvelopes, toCrossChainSigner } from '../../signers/crosschain.js';
import { toSigner } from '../../signers/index.js';

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

test('explicit fields byte disagreeing with domain.verifyingContract throws at construction', t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [makeOperation(1n, application, 1n)];

  // fields says verifyingContract is set (0x0b), but domain omits it.
  t.throws(
    () =>
      toCrossChainSigner(inner, {
        application,
        currentChainIndex: 0,
        operations,
        fields: '0x0b',
        domain: { name: 'CrossChainApp', version: '1' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
    { message: /disagree/ },
  );

  // fields says verifyingContract is unset (0x03), but domain sets it.
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
