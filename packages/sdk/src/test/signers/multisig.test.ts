import test from 'ava';
import { decodeAbiParameters, hashMessage, keccak256, parseAbiParameters, recoverAddress } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { toERC7913Signer } from '../../signers/erc7913.js';
import { toMultisigSigner } from '../../signers/multisig.js';
import { toSigner } from '../../signers/index.js';

test('produces abi.encode(bytes[] signers, bytes[] sigs), sorted by keccak256(signerBytes)', async t => {
  const eoaA = privateKeyToAccount(generatePrivateKey());
  const eoaB = privateKeyToAccount(generatePrivateKey());
  const message = 'multisig hello';

  const multisig = toMultisigSigner([
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
  const multisig = toMultisigSigner([sA, sB]);

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
  const multisig = toMultisigSigner([
    sWrapped,
    { signer: toSigner(eoaB), signerBytes: eoaB.address.toLowerCase() as `0x${string}` },
  ]);

  const envelope = await multisig.signMessage({ message: 'mixed' });
  const [signers] = decodeAbiParameters(parseAbiParameters(['bytes[]', 'bytes[]']), envelope);
  t.is(signers.length, 2);
});

test('empty inputs throws', t => {
  t.throws(() => toMultisigSigner([]), { message: /at least one signer/ });
});
