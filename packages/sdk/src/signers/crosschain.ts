import { concat, encodeAbiParameters, hashStruct, toHex } from 'viem';
import type { Address, Hex, TypedData, TypedDataDefinition } from 'viem';
import type { Signer } from './index.js';

const ERC7964_MAGIC: Hex = '0x796479647964796479';
const ERC7964_ENVELOPE_ABI = [{ type: 'bytes32' }, { type: 'bytes32[]' }, { type: 'bytes' }] as const;

/**
 * One chain-specific operation in an ERC-7964 cross-chain signature.
 *
 * `operation` is the EIP-712 typed data for this chain — including a `domain` field of
 * type `EIP712ChainDomain` carrying the per-chain `chainId` and `verifyingContract`.
 * Its struct hash becomes one element of the on-chain `structsArray` that the verifier
 * checks against the locally reconstructed hash.
 */
type ChainOperation = {
  operation: TypedDataDefinition;
};

/**
 * Configuration for {@link toCrossChainSigner}.
 *
 * @property application ERC-5267 address whose `eip712Domain()` the verifier reads.
 *   Packed into the signature header (bytes 12..31).
 * @property currentChainIndex Index in `operations` of this chain's leg. Packed into
 *   the header as `structIndex`.
 * @property operations All chain-specific operations being authorized. Each entry's
 *   `operation.message` is hashed via EIP-712 `hashStruct` to populate the on-chain
 *   `structsArray`.
 * @property fields ERC-5267 fields byte (default `0x03` — name + version, chainId omitted).
 * @property domain Outer-envelope domain (`name`, `version`); `chainId` is omitted per
 *   ERC-7964.
 * @property primaryType Primary type of the outer cross-chain envelope (e.g. `SetValue`).
 * @property types Full type map for the cross-chain typed data; the wrapper injects an
 *   `EIP712Domain` entry containing only `name` and `version`.
 * @property message Optional extra top-level fields (e.g. `nonce`, `deadline`) alongside
 *   the `operations` field in the outer message.
 */
type CrossChainSignerConfig = {
  application: Address;
  currentChainIndex: number;
  operations: ChainOperation[];
  fields?: Hex;
  domain: { name: string; version: string };
  primaryType: string;
  types: TypedData;
  message?: Record<string, unknown>;
};

const hashOperation = (op: ChainOperation): Hex =>
  hashStruct({
    data: op.operation.message as Record<string, unknown>,
    primaryType: op.operation.primaryType as string,
    types: op.operation.types as TypedData,
  });

const buildHeader = ({
  fields,
  currentChainIndex,
  application,
}: {
  fields: Hex;
  currentChainIndex: number;
  application: Address;
}): Hex => concat([ERC7964_MAGIC, fields, toHex(currentChainIndex, { size: 2 }), application]);

const buildOuterTypedData = (config: CrossChainSignerConfig): TypedDataDefinition => {
  const types = {
    ...(config.types as Record<string, readonly { name: string; type: string }[]>),
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
    ],
  };
  return {
    domain: { name: config.domain.name, version: config.domain.version },
    primaryType: config.primaryType,
    types,
    message: {
      operations: config.operations.map(op => op.operation.message),
      ...(config.message ?? {}),
    },
  } as TypedDataDefinition;
};

const packEnvelope = ({
  fields,
  currentChainIndex,
  application,
  structHashes,
  crossChainSignature,
}: {
  fields: Hex;
  currentChainIndex: number;
  application: Address;
  structHashes: Hex[];
  crossChainSignature: Hex;
}): Hex =>
  encodeAbiParameters(ERC7964_ENVELOPE_ABI, [
    buildHeader({ fields, currentChainIndex, application }) as `0x${string}`,
    structHashes as `0x${string}`[],
    crossChainSignature,
  ]);

/**
 * Wraps `innerSigner` so it produces ERC-7964-encoded cross-chain signatures.
 *
 * The wrapper hashes each `config.operations[i]` to its EIP-712 struct hash, asks the
 * inner signer to sign the chainId-free outer typed data, and packs the result into the
 * canonical ERC-7964 envelope. `signMessage` is intentionally unsupported because the
 * spec is EIP-712-only.
 *
 * When `signTypedData(parameters)` is called, the wrapper asserts that the incoming
 * `parameters` hash matches `operations[currentChainIndex].operation`. This catches the
 * common foot-gun where the caller's `operations` array drifts from the per-chain typed
 * data that `toERC7579Account` is asking the signer to authorize.
 */
const toCrossChainSigner = (innerSigner: Signer, config: CrossChainSignerConfig): Signer => {
  const fields: Hex = config.fields ?? '0x03';
  const structHashes = config.operations.map(hashOperation);
  const expectedCurrentHash = structHashes[config.currentChainIndex];

  if (expectedCurrentHash === undefined) {
    throw new Error(
      `toCrossChainSigner: currentChainIndex ${config.currentChainIndex} is out of bounds for operations of length ${config.operations.length}`,
    );
  }

  const signInner = async (): Promise<Hex> => innerSigner.signTypedData(buildOuterTypedData(config));

  return {
    ...innerSigner,
    address: innerSigner.address,
    signerBytes: innerSigner.signerBytes,
    async signMessage() {
      throw new Error('toCrossChainSigner: signMessage is not supported (ERC-7964 is EIP-712 only)');
    },
    async signTypedData(parameters) {
      const incoming = hashStruct({
        data: parameters.message as Record<string, unknown>,
        primaryType: parameters.primaryType as string,
        types: parameters.types as TypedData,
      });
      if (incoming !== expectedCurrentHash) {
        throw new Error(
          `toCrossChainSigner: signTypedData parameters do not match operations[${config.currentChainIndex}]; ` +
            `incoming hashStruct ${incoming} !== expected ${expectedCurrentHash}`,
        );
      }
      const crossChainSignature = await signInner();
      return packEnvelope({
        fields,
        currentChainIndex: config.currentChainIndex,
        application: config.application,
        structHashes,
        crossChainSignature,
      });
    },
  };
};

/**
 * Produces one ERC-7964 envelope per chain in `config.operations` while asking the inner
 * signer for the cross-chain signature exactly once.
 *
 * Use this when a single user signature should be dispatched to many chains: passkey or
 * hardware-wallet flows that prompt for each `signTypedData` call would otherwise prompt
 * `N` times. The envelopes returned share the same inner signature; only the header's
 * `structIndex` differs.
 */
const signCrossChainEnvelopes = async (
  innerSigner: Signer,
  config: Omit<CrossChainSignerConfig, 'currentChainIndex'>,
): Promise<Hex[]> => {
  const fields: Hex = config.fields ?? '0x03';
  const structHashes = config.operations.map(hashOperation);
  const crossChainSignature = await innerSigner.signTypedData(buildOuterTypedData({ ...config, currentChainIndex: 0 }));
  return config.operations.map((_, currentChainIndex) =>
    packEnvelope({
      fields,
      currentChainIndex,
      application: config.application,
      structHashes,
      crossChainSignature,
    }),
  );
};

export { toCrossChainSigner, signCrossChainEnvelopes, ERC7964_MAGIC, type ChainOperation, type CrossChainSignerConfig };
