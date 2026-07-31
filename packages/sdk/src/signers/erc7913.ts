import { encodeAbiParameters, encodePacked } from 'viem';
import type { Address, Hex, OneOf } from 'viem';
import type { Signer } from './index.js';

/**
 * Configuration for {@link toERC7913Signer}.
 *
 * Either supply an ERC-7913 verifier + key pair (general case for non-EOA signers like
 * passkeys or RSA), or use the verifier-less shortcut where `signerBytes` collapses to
 * `abi.encodePacked(address)` and on-chain validation falls into the EOA / ERC-1271 path.
 */
type ERC7913SignerConfig = OneOf<
  | {
      /** Address of an `IERC7913SignatureVerifier`. Combined with `key` to produce `signerBytes`. */
      verifier: Address;
      /** Algorithm-specific public key material (e.g. WebAuthn `(qx, qy)`, RSA `(n, e)`). */
      key: Hex;
    }
  | {
      /** Shortcut for the verifier-less case: `signerBytes = abi.encodePacked(address)`. */
      address: Address;
    }
>;

/**
 * Signer returned by {@link toERC7913Signer}. Exposes the pre-wrap `signerBytes` and an
 * `unwrap()` accessor that returns the original inner signer at construction time —
 * consumers that need the raw (unwrapped) signature bytes for another wire format (e.g.
 * {@link toMultisigner}) should call `.unwrap()` and drive the inner signer directly.
 *
 * This is a deliberate design choice: exposing `signMessageRaw`/`signTypedDataRaw` on the
 * wrapper would have meant "one layer down", not "raw ECDSA/WebAuthn". Composing
 * `toERC7913Signer(toCrossChainSigner(inner, ...), ...)` and then feeding a `Raw` method
 * into a multisig would silently produce an invalid envelope. `.unwrap()` returns the
 * signer passed to the wrapper at construction, so the caller knows exactly what shape
 * they're getting and can wrap or unwrap further as needed.
 */
type ERC7913Signer = Signer & {
  signerBytes: Hex;
  /** Returns the inner {@link Signer} that was wrapped. */
  unwrap: () => Signer;
};

/**
 * Wraps `innerSigner` so its output matches the ERC-7913 wire format
 * (`abi.encode(bytes signer, bytes rawSig)`) that `SignatureChecker.isValidSignatureNow`
 * decodes when the signer length differs from 20.
 *
 * For verifier-less EOAs (`{ address }`), `signerBytes` is the 20-byte address itself; on
 * the verifier side this routes through the standard EOA / ERC-1271 path. For non-EOA
 * signers (`{ verifier, key }`), `signerBytes` is `verifier(20) || key(rest)` and the
 * verifier contract decides how to validate the inner signature against the `key`.
 */
const toERC7913Signer = (innerSigner: Signer, config: ERC7913SignerConfig): ERC7913Signer => {
  const signerBytes: Hex =
    config.verifier !== undefined
      ? encodePacked(['address', 'bytes'], [config.verifier, config.key])
      : encodePacked(['address'], [config.address]);

  const wrap = (rawSig: Hex): Hex => encodeAbiParameters([{ type: 'bytes' }, { type: 'bytes' }], [signerBytes, rawSig]);

  return {
    ...innerSigner,
    signerBytes,
    unwrap: () => innerSigner,
    signMessage: async parameters => innerSigner.signMessage(parameters).then(wrap),
    signTypedData: async parameters => innerSigner.signTypedData(parameters).then(wrap),
  };
};

export { toERC7913Signer, type ERC7913SignerConfig, type ERC7913Signer };
