import test from 'ava';
import {
  decodeAbiParameters,
  hashTypedData,
  parseAbiParameters,
  recoverAddress,
  slice,
  TypedDataDefinition,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { ERC7964_MAGIC, toCrossChainSigner } from '../../signers/to-cross-chain-signer.js';
import { toERC7913Signer } from '../../signers/to-erc7913-signer.js';
import { toSigner } from '../../signers/to-signer.js';

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

test('toERC7913Signer(toCrossChainSigner(eoa)): unwraps in two passes to recover the EOA', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const operations = [
    { operation: makeOperation(1n, application, 100n) },
    { operation: makeOperation(42161n, application, 100n) },
  ];

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
  const composedSig = await composed.signTypedData(operations[0]!.operation);

  // Pass 1: strip ERC-7913 envelope.
  const [signerBytes, crossChainEnvelope] = decodeAbiParameters(parseAbiParameters(['bytes', 'bytes']), composedSig);
  t.is(signerBytes.toLowerCase(), eoa.address.toLowerCase());

  // Pass 2: strip ERC-7964 envelope.
  const [header, structsArray, crossChainSignature] = decodeAbiParameters(
    parseAbiParameters(['bytes32', 'bytes32[]', 'bytes']),
    crossChainEnvelope,
  );
  t.is(slice(header, 0, 9), ERC7964_MAGIC);
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
    message: { operations: operations.map(o => o.operation.message) },
  });
  const recovered = await recoverAddress({ hash: outerDigest, signature: crossChainSignature });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});
