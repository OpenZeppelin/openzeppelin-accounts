import {
  hashMessage,
  hashTypedData,
  size,
  Hex,
  toBytes,
  sha256,
  concat,
  encodePacked,
  zeroHash,
  toHex,
  encodeAbiParameters,
  parseAbiParameters,
  stringToBytes,
  bytesToHex,
} from 'viem';
import { WebAuthnAccount } from 'viem/account-abstraction';
import { Base64 } from 'ox';
import { p256 } from '@noble/curves/nist.js';

const webAuthnStubSignature = (): Promise<Hex> =>
  Promise.resolve(
    bytesToHex(
      crypto.getRandomValues(
        new Uint8Array(
          6 * 32 + // offsets
            2 * 32 + // lengths
            37 + // authenticator data
            81, // clientDataJSON
        ),
      ),
    ),
  );

const toWebAuthnSigner = (privateKey = p256.utils.randomSecretKey()): WebAuthnAccount => {
  const pubKey = p256.getPublicKey(privateKey, false);
  return {
    id: 'webauthn',
    publicKey: bytesToHex(pubKey),
    async sign({ hash }) {
      if (size(hash) !== 32) {
        throw new Error('invalid hash length');
      }
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: Base64.fromHex(hash).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
      });
      // Flags 0x05 = AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV
      const authenticatorData = encodePacked(['bytes32', 'bytes1', 'bytes4'], [zeroHash, '0x05', '0x00000000']);
      const hashToSign = sha256(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))]));
      const challengeIndex = clientDataJSON.indexOf('"challenge"');
      const typeIndex = clientDataJSON.indexOf('"type"');
      const sig = p256.sign(toBytes(hashToSign), privateKey, {
        lowS: true,
        prehash: false,
      });
      const { r, s } = p256.Signature.fromBytes(sig);
      return {
        webauthn: {
          authenticatorData,
          clientDataJSON,
          challengeIndex,
          typeIndex,
          userVerificationRequired: true,
        },
        raw: {
          id: 'webauthn',
          type: 'public-key',
          authenticatorAttachment: 'platform',
          rawId: pubKey.buffer as ArrayBuffer,
          response: {
            authenticatorData: toBytes(authenticatorData),
            clientDataJSON: stringToBytes(clientDataJSON).buffer as ArrayBuffer,
            signature: sig,
          },
          getClientExtensionResults: () => ({}),
        },
        signature: encodeAbiParameters(
          parseAbiParameters(['bytes32', 'bytes32', 'uint256', 'uint256', 'bytes', 'string']),
          [
            toHex(r, { size: 32 }),
            toHex(s, { size: 32 }),
            BigInt(challengeIndex),
            BigInt(typeIndex),
            authenticatorData,
            clientDataJSON,
          ],
        ),
      };
    },
    async signMessage({ message }) {
      return this.sign({ hash: hashMessage(message) });
    },
    async signTypedData(typedData) {
      return this.sign({ hash: hashTypedData(typedData) });
    },
    type: 'webAuthn',
  };
};

export { webAuthnStubSignature, toWebAuthnSigner };
