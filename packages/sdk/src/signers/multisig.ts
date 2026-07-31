import { encodeAbiParameters, keccak256, parseAbiParameters } from 'viem';
import type { Hex, SignableMessage, TypedDataDefinition } from 'viem';
import type { ERC7913Signer } from './erc7913.js';
import type { Signer } from './index.js';

/**
 * One signer slot for {@link toMultisigner}. Either an explicit `{ signer, signerBytes }`
 * pair, or an already-ERC-7913-wrapped signer — in which case the multisig wrapper calls
 * `.unwrap()` to reach the pre-ERC-7913 signature material and pairs it with the wrapper's
 * `signerBytes`.
 *
 * Composition rule: if the "already-wrapped" signer nests further wrappers, `unwrap()`
 * only strips the outermost ERC-7913 layer. Feeding e.g. `toERC7913Signer(toCrossChainSigner(...))`
 * into a multisig will unwrap the ERC-7913 layer but leave the ERC-7964 envelope inside,
 * which is not what the on-chain multisig verifier expects. Prefer flat compositions
 * (raw signer → ERC-7913 → multisig) unless you know the on-chain validator can decode
 * whatever layered envelope you're producing.
 */
type MultisigSigner = { signer: Signer; signerBytes: Hex } | ERC7913Signer;

const isWrapped = (signer: MultisigSigner): signer is ERC7913Signer =>
  typeof (signer as ERC7913Signer).unwrap === 'function';

const innerSignerOf = (signer: MultisigSigner): Signer => (isWrapped(signer) ? signer.unwrap() : signer.signer);

const signRawMessage = (signer: MultisigSigner, message: SignableMessage): Promise<Hex> =>
  innerSignerOf(signer).signMessage({ message });

const signRawTypedData = (signer: MultisigSigner, parameters: TypedDataDefinition): Promise<Hex> =>
  innerSignerOf(signer).signTypedData(parameters);

const withSignerContext = <T>(i: number, promise: Promise<T>): Promise<T> =>
  promise.catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`multisig signer[${i}] failed: ${message}`);
  });

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
 *
 * NOTE: a single-signer multisig (`signers.length === 1`) is legal on-chain but usually
 * indicates that the caller should have used the underlying `Signer` directly. The
 * wrapper does not reject it — the extra ABI encoding still produces a valid envelope,
 * it just isn't buying anything.
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
    signMessage: async ({ message }) =>
      Promise.all(signers.map((signer, i) => withSignerContext(i, signRawMessage(signer, message)))).then(pack),
    signTypedData: async parameters =>
      Promise.all(signers.map((signer, i) => withSignerContext(i, signRawTypedData(signer, parameters)))).then(pack),
  };
};

export { toMultisigner, type MultisigSigner };
