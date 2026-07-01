import { encodeAbiParameters, keccak256, parseAbiParameters } from 'viem';
import type { Hex, SignableMessage, TypedDataDefinition } from 'viem';
import type { ERC7913Signer } from './erc7913.js';
import type { Signer } from './index.js';

/**
 * One signer slot for {@link toMultisigSigner}. Either an explicit `{ signer, signerBytes }`
 * pair where `signer` produces the raw inner signature, or an already-ERC-7913-wrapped
 * signer whose `signMessageRaw`/`signTypedDataRaw` methods supply the raw signature
 * paired with its `signerBytes`.
 */
type MultisigSignerInput = { signer: Signer; signerBytes: Hex } | ERC7913Signer;

const isWrapped = (input: MultisigSignerInput): input is ERC7913Signer =>
  'signMessageRaw' in input && 'signTypedDataRaw' in input;

const signerBytesOf = (input: MultisigSignerInput): Hex => (isWrapped(input) ? input.signerBytes : input.signerBytes);

const signRawMessage = (input: MultisigSignerInput, message: SignableMessage): Promise<Hex> =>
  isWrapped(input) ? input.signMessageRaw({ message }) : input.signer.signMessage({ message });

const signRawTypedData = (input: MultisigSignerInput, parameters: TypedDataDefinition): Promise<Hex> =>
  isWrapped(input) ? input.signTypedDataRaw(parameters) : input.signer.signTypedData(parameters);

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
const toMultisigSigner = (inputs: MultisigSignerInput[]): Signer => {
  if (inputs.length === 0) {
    throw new Error('toMultisigSigner: at least one signer is required');
  }

  const pack = (signatures: Hex[]): Hex => {
    const pairs = inputs.map((input, i) => {
      const signer = signerBytesOf(input);
      return { signer, signature: signatures[i]!, sortKey: keccak256(signer) };
    });
    pairs.sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0));
    return encodeAbiParameters(parseAbiParameters(['bytes[] signers', 'bytes[] signatures']), [
      pairs.map(p => p.signer),
      pairs.map(p => p.signature),
    ]);
  };

  return {
    async signMessage({ message }) {
      const signatures = await Promise.all(inputs.map(input => signRawMessage(input, message)));
      return pack(signatures);
    },
    async signTypedData(parameters) {
      const signatures = await Promise.all(inputs.map(input => signRawTypedData(input, parameters)));
      return pack(signatures);
    },
  };
};

export { toMultisigSigner, type MultisigSignerInput };
