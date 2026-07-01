import test from 'ava';
import {
  decodeAbiParameters,
  encodePacked,
  hashMessage,
  hashTypedData,
  parseAbiParameters,
  recoverAddress,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { toERC7913Signer } from '../../signers/erc7913.js';
import { toSigner } from '../../signers/index.js';

test('verifier-less shortcut: signerBytes equals 20-byte address', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const signer = toERC7913Signer(toSigner(eoa), { address: eoa.address });

  t.is(signer.signerBytes.toLowerCase(), eoa.address.toLowerCase());
});

test('verifier + key: signerBytes is verifier || key', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const verifier = '0xcafecafecafecafecafecafecafecafecafecafe' as const;
  const key = '0xdeadbeef';
  const signer = toERC7913Signer(toSigner(eoa), { verifier, key });

  t.is(signer.signerBytes.toLowerCase(), encodePacked(['address', 'bytes'], [verifier, key]).toLowerCase());
});

test('signMessage emits abi.encode(signer, rawSig) and the rawSig recovers to the EOA', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const signer = toERC7913Signer(toSigner(eoa), { address: eoa.address });
  const message = 'hello erc7913';

  const wrapped = await signer.signMessage({ message });
  const [decodedSignerBytes, rawSig] = decodeAbiParameters(parseAbiParameters(['bytes', 'bytes']), wrapped);

  t.is(decodedSignerBytes.toLowerCase(), signer.signerBytes.toLowerCase());
  const recovered = await recoverAddress({ hash: hashMessage(message), signature: rawSig });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('signTypedData emits abi.encode(signer, rawSig)', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const signer = toERC7913Signer(toSigner(eoa), { address: eoa.address });
  const typedData = {
    domain: { name: 'Test', version: '1' },
    types: { Msg: [{ name: 'value', type: 'uint256' }] },
    primaryType: 'Msg' as const,
    message: { value: 42n },
  } as const;

  const wrapped = await signer.signTypedData(typedData);
  const [, rawSig] = decodeAbiParameters(parseAbiParameters(['bytes', 'bytes']), wrapped);
  const recovered = await recoverAddress({ hash: hashTypedData(typedData), signature: rawSig });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});

test('signMessageRaw / signTypedDataRaw produce the raw inner signature only', async t => {
  const eoa = privateKeyToAccount(generatePrivateKey());
  const signer = toERC7913Signer(toSigner(eoa), { address: eoa.address });

  const raw = await signer.signMessageRaw({ message: 'no envelope' });
  // raw sig length is 65 bytes for ECDSA = 0x + 130 hex chars
  t.is(raw.length, 132);
  const recovered = await recoverAddress({ hash: hashMessage('no envelope'), signature: raw });
  t.is(recovered.toLowerCase(), eoa.address.toLowerCase());
});
