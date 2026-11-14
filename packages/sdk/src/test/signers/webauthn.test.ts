import test from 'ava';
import { p256 } from '@noble/curves/nist.js';
import { Base64 } from 'ox';
import {
  bytesToHex,
  concat,
  decodeAbiParameters,
  encodePacked,
  hashMessage,
  hashTypedData,
  type Hex,
  parseAbiParameters,
  sha256,
  size,
  slice,
  stringToBytes,
  toBytes,
  zeroHash,
} from 'viem';
import { toWebAuthnAccount } from 'viem/account-abstraction';
import { toSigner } from '../../signers/index.js';
import { toWebAuthnSigner } from '../helpers/signers.js';

const WEBAUTHN_AUTH_PARAMS = parseAbiParameters(['bytes32', 'bytes32', 'uint256', 'uint256', 'bytes', 'string']);

const assertValidWebAuthnEncoding = (
  t: Parameters<Parameters<typeof test>[1]>[0],
  encoded: Hex,
  expectedHash: Hex,
  publicKey: Uint8Array,
) => {
  // WebAuthn.tryDecodeAuth requires at least 6 words (0xc0 bytes) and flat head words
  // (no outer tuple offset word at 0x00; authenticatorData offset at 0x80 must be 0xc0).
  t.true(size(encoded) >= 0xc0);
  t.is(BigInt(slice(encoded, 0x80, 0xa0)), 0xc0n);

  const [r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON] = decodeAbiParameters(
    WEBAUTHN_AUTH_PARAMS,
    encoded,
  );

  const expectedChallenge = Base64.fromHex(expectedHash).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  t.is(
    clientDataJSON.slice(Number(challengeIndex)),
    `"challenge":"${expectedChallenge}"` +
      clientDataJSON.slice(Number(challengeIndex) + `"challenge":"${expectedChallenge}"`.length),
  );
  t.true(clientDataJSON.slice(Number(typeIndex)).startsWith('"type":"webauthn.get"'));

  const signingHash = sha256(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))]));
  const rawSig = toBytes(concat([r, s]));
  t.true(p256.verify(rawSig, toBytes(signingHash), publicKey, { lowS: true, prehash: false }));
};

test('toWebAuthnSigner returns 64-byte r||s in signature and metadata in webauthn', async t => {
  const passkey = toWebAuthnSigner();
  const res = await passkey.signMessage({ message: 'shape check' });

  t.is(size(res.signature), 64);
  t.truthy(res.webauthn.authenticatorData);
  t.truthy(res.webauthn.clientDataJSON);
});

test('toSigner(WebAuthnAccount) encodes six WebAuthnAuth values on signMessage', async t => {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey, false);
  const signer = toSigner(toWebAuthnSigner(privateKey));
  const message = 'hello webauthn';

  const encoded = await signer.signMessage({ message });
  t.is(signer.address, undefined);
  assertValidWebAuthnEncoding(t, encoded, hashMessage(message), publicKey);
});

test('toSigner(WebAuthnAccount) encodes six WebAuthnAuth values on signTypedData', async t => {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey, false);
  const signer = toSigner(toWebAuthnSigner(privateKey));
  const typedData = {
    domain: { name: 'OpenAccount', version: '1', chainId: 1 },
    types: { Mail: [{ name: 'contents', type: 'string' }] },
    primaryType: 'Mail' as const,
    message: { contents: 'hello typed webauthn' },
  } as const;

  const encoded = await signer.signTypedData(typedData);
  assertValidWebAuthnEncoding(t, encoded, hashTypedData(typedData), publicKey);
});

test('toSigner encodes output from viem toWebAuthnAccount', async t => {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey, false);
  const account = toWebAuthnAccount({
    credential: {
      id: 'test-credential',
      publicKey: bytesToHex(publicKey),
    },
    rpId: 'localhost',
    async getFn(options) {
      const publicKeyOpts = options?.publicKey;
      const challengeBytes = new Uint8Array(publicKeyOpts!.challenge as BufferSource as ArrayBuffer);
      const challenge = Base64.fromBytes(challengeBytes, { url: true, pad: false });
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge,
        origin: 'https://localhost',
      });
      const authenticatorData = encodePacked(['bytes32', 'bytes1', 'bytes4'], [zeroHash, '0x05', '0x00000000']);
      const digest = sha256(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))]));
      const sigCompact = p256.sign(toBytes(digest), privateKey, { lowS: true, prehash: false });
      const derSig = p256.Signature.fromBytes(sigCompact).toBytes('der');
      const authBytes = toBytes(authenticatorData);
      const clientBytes = stringToBytes(clientDataJSON);
      return {
        id: 'test-credential',
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          authenticatorData: authBytes.buffer.slice(authBytes.byteOffset, authBytes.byteOffset + authBytes.byteLength),
          clientDataJSON: clientBytes.buffer.slice(
            clientBytes.byteOffset,
            clientBytes.byteOffset + clientBytes.byteLength,
          ),
          signature: derSig.buffer.slice(derSig.byteOffset, derSig.byteOffset + derSig.byteLength),
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
      } as unknown as Credential;
    },
  });

  const signer = toSigner(account);
  const message = 'viem toWebAuthnAccount integration';
  const encoded = await signer.signMessage({ message });
  assertValidWebAuthnEncoding(t, encoded, hashMessage(message), publicKey);
});
