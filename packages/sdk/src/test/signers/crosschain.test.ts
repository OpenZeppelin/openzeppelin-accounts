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
  const operations = [
    { operation: makeOperation(1n, application, 42n) },
    { operation: makeOperation(42161n, application, 42n) },
  ];

  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 1,
    operations,
    domain: { name: 'CrossChainApp', version: '1' },
    primaryType: 'SetValue',
    types: crossChainTypes as unknown as TypedDataDefinition['types'],
  });

  const envelope = await wrapper.signTypedData(operations[1]!.operation);

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
      data: operations[1]!.operation.message as Record<string, unknown>,
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
    message: { operations: operations.map(o => o.operation.message) },
  });
  const recovered = await recoverAddress({ hash: outerDigest, signature: crossChainSignature });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('signTypedData with a mismatched payload throws', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const operations = [{ operation: makeOperation(1n, application, 42n) }];

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

test('signMessage on a cross-chain signer throws', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  const wrapper = toCrossChainSigner(inner, {
    application,
    currentChainIndex: 0,
    operations: [{ operation: makeOperation(1n, application, 1n) }],
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
    { operation: makeOperation(1n, application, 7n) },
    { operation: makeOperation(42161n, application, 7n) },
    { operation: makeOperation(10n, application, 7n) },
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

test('out-of-bounds currentChainIndex throws', t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const inner = toSigner(eoa);
  t.throws(
    () =>
      toCrossChainSigner(inner, {
        application,
        currentChainIndex: 5,
        operations: [{ operation: makeOperation(1n, application, 1n) }],
        domain: { name: 'CrossChainApp', version: '1' },
        primaryType: 'SetValue',
        types: crossChainTypes as unknown as TypedDataDefinition['types'],
      }),
    { message: /out of bounds/ },
  );
});
