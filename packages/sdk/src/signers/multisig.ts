import { encodeAbiParameters, keccak256, parseAbiParameters } from 'viem';
import type { Hex, SignableMessage, TypedDataDefinition } from 'viem';
import type { ERC7913Signer } from './erc7913.js';
import type { Signer } from './index.js';

/**
 * One signer slot for {@link toMultisigner}. Either an explicit `{ signer, signerBytes }`
 * pair where `signer` produces the raw inner signature, or an already-ERC-7913-wrapped
 * signer whose `signMessageRaw`/`signTypedDataRaw` methods supply the raw signature
 * paired with its `signerBytes`.
 */
type MultisigSigner = { signer: Signer; signerBytes: Hex } | ERC7913Signer;

const isWrapped = (signer: MultisigSigner): signer is ERC7913Signer =>
  'signMessageRaw' in signer && 'signTypedDataRaw' in signer;

const signRawMessage = (signer: MultisigSigner, message: SignableMessage): Promise<Hex> =>
  isWrapped(signer) ? signer.signMessageRaw({ message }) : signer.signer.signMessage({ message });

const signRawTypedData = (signer: MultisigSigner, parameters: TypedDataDefinition): Promise<Hex> =>
  isWrapped(signer) ? signer.signTypedDataRaw(parameters) : signer.signer.signTypedData(parameters);

/**
 * Wraps a set of inner signers into a single signer whose output matches the encoding
 * consumed by `Multisig.tryDecodeMultisignatureCalldata` and `ERC7579MultisigValidator`:
 * `abi.encode(bytes[] signers, bytes[] signatures)`.
 *
 * Each input is either an `{ signer, signerBytes }` pair or an already-wrapped
 * {@link ERC7913Signer}; both forms compose, so callers can mix verifier-less EOAs with
 * ERC-7913-wrapped passkeys in the same multisig.
 *
 * Sorts the (signer, signature) pairs by `keccak256(signerBytes)` so the on-chain
 * validator's lookups remain efficient (per `ERC7579Multisig._validateSignatures` note).
 */
const toMultisigner = (signers: MultisigSigner[]): Signer => {
  if (signers.length === 0) {
    throw new Error('At least one signer is required');
  }

  const pack = (signatures: Hex[]): Hex => {
    const pairs = signers.map((signer, i) => {
      const signerBytes = signer.signerBytes;
      return { signerBytes, signature: signatures[i]!, sortKey: keccak256(signerBytes) };
    });
    pairs.sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0));
    return encodeAbiParameters(parseAbiParameters(['bytes[] signers', 'bytes[] signatures']), [
      pairs.map(p => p.signerBytes),
      pairs.map(p => p.signature),
    ]);
  };

  return {
    signMessage: async ({ message }) => Promise.all(signers.map(signer => signRawMessage(signer, message))).then(pack),
    signTypedData: async parameters =>
      Promise.all(signers.map(signer => signRawTypedData(signer, parameters))).then(pack),
  };
};

export { toMultisigner, type MultisigSigner };
