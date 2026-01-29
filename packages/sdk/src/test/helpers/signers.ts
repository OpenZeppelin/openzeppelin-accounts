import {
  zeroAddress,
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
  LocalAccount,
  bytesToHex,
} from 'viem';
import { Base64 } from 'ox';
import { toAccount } from 'viem/accounts';
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

const toWebAuthnSigner = (privateKey = p256.utils.randomSecretKey()): LocalAccount => {
  const sign = (hash: Hex) => {
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
    const sig = p256.sign(toBytes(hashToSign), privateKey, {
      lowS: true,
      prehash: false,
    });
    const { r, s } = p256.Signature.fromBytes(sig);
    return encodeAbiParameters(parseAbiParameters(['bytes32', 'bytes32', 'uint256', 'uint256', 'bytes', 'string']), [
      toHex(r, { size: 32 }),
      toHex(s, { size: 32 }),
      BigInt(clientDataJSON.indexOf('"challenge"')),
      BigInt(clientDataJSON.indexOf('"type"')),
      authenticatorData,
      clientDataJSON,
    ]);
  };

  return toAccount({
    address: zeroAddress,
    async signTransaction() {
      throw new Error('signTransaction not supported');
    },
    async signMessage({ message }) {
      return sign(hashMessage(message));
    },
    async signTypedData(typedData) {
      return sign(hashTypedData(typedData));
    },
  });
};

export { webAuthnStubSignature, toWebAuthnSigner };
