import { concat, encodeAbiParameters, hashStruct, size, toHex } from 'viem';
import type { Address, Hex, TypedData, TypedDataDefinition } from 'viem';
import type { Signer } from './index.js';

const ERC7964_MAGIC = '0x796479647964796479' as const satisfies Hex;

// ERC-5267 domain-field bit flags.
const FIELD_NAME = 0x01;
const FIELD_VERSION = 0x02;
const FIELD_VERIFYING_CONTRACT = 0x08;
// Bits the SDK's outer domain supports. `chainId` (0x04) is forbidden by ERC-7964 and
// `salt` (0x10) is not emitted by {@link buildOuterTypedData}; setting either would make
// the on-chain domain separator diverge from the SDK-signed one.
const SUPPORTED_FIELDS = FIELD_NAME | FIELD_VERSION | FIELD_VERIFYING_CONTRACT;

/**
 * One chain-specific operation in an ERC-7964 cross-chain signature.
 *
 * A `ChainOperation` is the EIP-712 typed data for this chain — including its own `domain`
 * (typically an `EIP712ChainDomain` carrying the per-chain `chainId` and `verifyingContract`).
 * Its struct hash becomes one element of the on-chain `structsArray` that the verifier
 * checks against the locally reconstructed hash.
 *
 * Per ERC-7964, each operation MUST include the target chainId under a field named
 * exactly `chainId` (at any depth within the struct). {@link toCrossChainSigner} relies
 * on this convention to look up the operation matching the current chain.
 */
type ChainOperation = TypedDataDefinition;

/**
 * Configuration for {@link toCrossChainSigner}.
 *
 * The wrapper needs to know which operation corresponds to the current chain. Two
 * selectors are accepted; the first non-`undefined` one wins:
 *
 * 1. `currentChainIndex` — explicit array index.
 * 2. `chainId` — scans `operations` for the entry whose message includes a matching
 *    `chainId` field (per the ERC-7964 canonical naming convention). First match wins
 *    in DFS order.
 *
 * @property application ERC-5267 address whose `eip712Domain()` the verifier reads.
 *   Packed into the signature header (bytes 12..31).
 * @property operations All chain-specific operations being authorized. Each entry's
 *   `message` is hashed via EIP-712 `hashStruct` to populate the on-chain `structsArray`.
 * @property fields ERC-5267 fields byte. When omitted, defaults to `0x03` (name + version)
 *   or `0x0b` (name + version + verifyingContract) depending on `domain.verifyingContract`.
 *   Only bits in `SUPPORTED_FIELDS` (0x0b) are accepted — `chainId` (0x04) is forbidden by
 *   ERC-7964 and `salt` (0x10) is not emitted by the SDK; either would silently break
 *   verification.
 * @property domain Outer-envelope domain. `chainId` is always omitted per ERC-7964; a
 *   `verifyingContract` may be included when the application is deployed deterministically
 *   at the same address on every target chain. When bit `0x08` is set in `fields` but
 *   `verifyingContract` is omitted, it defaults to `application`.
 * @property primaryType Primary type of the outer cross-chain envelope (e.g. `SetValue`).
 * @property types Full type map for the cross-chain typed data; the wrapper injects an
 *   `EIP712Domain` entry containing the domain fields it uses.
 * @property message Optional extra top-level fields (e.g. `nonce`, `deadline`) alongside
 *   the `operations` field in the outer message.
 * @property currentChainIndex Explicit index into `operations`; highest-precedence selector.
 * @property chainId Target chainId; the wrapper scans `operations` for a message field
 *   named `chainId` matching this value.
 */
type CrossChainSignerConfig = {
  application: Address;
  operations: ChainOperation[];
  fields?: Hex;
  domain: { name: string; version: string; verifyingContract?: Address };
  primaryType: string;
  types: TypedData;
  message?: Record<string, unknown>;
  currentChainIndex?: number;
  chainId?: bigint;
};

/**
 * Signer returned by {@link toCrossChainSigner}. `signCrossChainEnvelopes` produces one
 * ERC-7964 envelope per operation in the wrapper's config, reusing the closed-over inner
 * signer — equivalent to calling the standalone {@link signCrossChainEnvelopes} with the
 * same `(inner, config)` pair.
 *
 * NOTE: A `CrossChainSigner` is not a valid top-level signer for {@link toERC7579Account}
 * or {@link toOpenAccount} — `signMessage` throws unconditionally and `signTypedData`
 * asserts the incoming payload against `operations[currentChainIndex]`, which won't match
 * a `PackedUserOperation`. Use it at the application boundary (e.g. an app contract's
 * `setValue(..., signature)` call), not at the smart-account boundary.
 */
type CrossChainSigner = Signer & {
  signCrossChainEnvelopes: () => Promise<Hex[]>;
};

const hashOperation = (op: ChainOperation): Hex =>
  hashStruct({
    data: op.message,
    primaryType: op.primaryType,
    types: op.types,
  });

const computeFields = (domain: CrossChainSignerConfig['domain']): Hex => {
  let bits = FIELD_NAME | FIELD_VERSION;
  if (domain.verifyingContract !== undefined) bits |= FIELD_VERIFYING_CONTRACT;
  return toHex(bits, { size: 1 });
};

const resolveFields = (config: Pick<CrossChainSignerConfig, 'domain' | 'fields'>): Hex => {
  if (config.fields === undefined) return computeFields(config.domain);
  const provided = Number(BigInt(config.fields)) & 0xff;
  const unsupported = provided & ~SUPPORTED_FIELDS;
  if (unsupported !== 0) {
    throw new Error(
      `fields byte ${config.fields} has bits outside SUPPORTED_FIELDS (0x${SUPPORTED_FIELDS.toString(16)}); ` +
        `ERC-7964 outer domain only supports name/version/verifyingContract`,
    );
  }
  const fieldsBit = provided & FIELD_VERIFYING_CONTRACT;
  const hasVC = config.domain.verifyingContract !== undefined;
  if (Boolean(fieldsBit) !== hasVC) {
    throw new Error(
      `fields byte ${config.fields} and domain.verifyingContract disagree: bit ${FIELD_VERIFYING_CONTRACT} is ${
        fieldsBit ? 'set' : 'unset'
      } but verifyingContract is ${hasVC ? 'set' : 'unset'}`,
    );
  }
  return config.fields;
};

/**
 * Depth-first scan for a field named exactly `chainId`. Returns the first match's value
 * (coerced to `bigint`), or `undefined` if none found. Iteration order matches
 * `Object.entries`, which is insertion order for string keys.
 *
 * Relies on ERC-7964 §Message Array Encoding, which mandates the canonical field name.
 * If an application struct embeds more than one `chainId` field for its own reasons, the
 * outermost one in insertion order wins — resolve the ambiguity by passing an explicit
 * `currentChainIndex` instead.
 */
const findChainId = (value: unknown): bigint | undefined => {
  if (typeof value !== 'object' || value === null) return undefined;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === 'chainId') {
      if (typeof v === 'bigint') return v;
      if (typeof v === 'number' || typeof v === 'string') return BigInt(v);
    }
    const nested = findChainId(v);
    if (nested !== undefined) return nested;
  }
  return undefined;
};

const findOperationIndex = (operations: ChainOperation[], chainId: bigint): number => {
  const idx = operations.findIndex(op => findChainId(op.message) === chainId);
  if (idx === -1) {
    throw new Error(`no operation matches chainId ${chainId}`);
  }
  return idx;
};

const resolveCurrentChainIndex = (config: CrossChainSignerConfig): number => {
  if (config.currentChainIndex !== undefined) return config.currentChainIndex;
  if (config.chainId !== undefined) return findOperationIndex(config.operations, config.chainId);
  throw new Error('signTypedData requires currentChainIndex or chainId to identify the current chain');
};

const buildHeader = ({
  fields,
  currentChainIndex,
  application,
}: {
  fields: Hex;
  currentChainIndex: number;
  application: Address;
}): Hex => {
  const header = concat([ERC7964_MAGIC, fields, toHex(currentChainIndex, { size: 2 }), application]);
  // 9 (magic) + 1 (fields) + 2 (structIndex) + 20 (application) = 32.
  if (size(header) !== 32) throw new Error(`buildHeader produced ${size(header)} bytes; expected 32`);
  return header;
};

const buildOuterTypedData = (config: CrossChainSignerConfig): TypedDataDefinition => {
  const eip712Domain: { name: string; type: string }[] = [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
  ];
  if (config.domain.verifyingContract !== undefined) {
    eip712Domain.push({ name: 'verifyingContract', type: 'address' });
  }

  const types = {
    ...(config.types as Record<string, readonly { name: string; type: string }[]>),
    EIP712Domain: eip712Domain,
  };
  const domain: Record<string, unknown> = {
    name: config.domain.name,
    version: config.domain.version,
  };
  if (config.domain.verifyingContract !== undefined) domain.verifyingContract = config.domain.verifyingContract;

  return {
    domain,
    primaryType: config.primaryType,
    types,
    message: {
      operations: config.operations.map(op => op.message),
      ...(config.message ?? {}),
    },
  };
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
  encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'bytes32[]' }, { type: 'bytes' }],
    [buildHeader({ fields, currentChainIndex, application }), structHashes, crossChainSignature],
  );

/**
 * Snapshots a caller-supplied config so subsequent mutations of `operations` / `domain` /
 * `message` don't desync the frozen `structHashes` from the outer signature payload.
 */
const snapshotConfig = (config: CrossChainSignerConfig): CrossChainSignerConfig => ({
  application: config.application,
  operations: [...config.operations],
  fields: config.fields,
  domain: { ...config.domain },
  primaryType: config.primaryType,
  types: config.types,
  message: config.message === undefined ? undefined : { ...config.message },
  currentChainIndex: config.currentChainIndex,
  chainId: config.chainId,
});

/**
 * Applies defensive defaults to `config.domain.verifyingContract`. When the resolved
 * `fields` byte has bit `0x08` set but the caller omitted `verifyingContract`, we default
 * it to `application` — the on-chain verifier reads `verifyingContract` from
 * `IERC5267(application).eip712Domain()`, so `application` is the natural (and usually
 * correct) value.
 */
const applyVerifyingContractDefault = (config: CrossChainSignerConfig): CrossChainSignerConfig => {
  if (config.fields === undefined) return config;
  const hasVCBit = (Number(BigInt(config.fields)) & FIELD_VERIFYING_CONTRACT) !== 0;
  if (hasVCBit && config.domain.verifyingContract === undefined) {
    return { ...config, domain: { ...config.domain, verifyingContract: config.application } };
  }
  return config;
};

/**
 * Wraps `innerSigner` so it produces ERC-7964-encoded cross-chain signatures.
 *
 * The wrapper hashes each `config.operations[i]` to its EIP-712 struct hash, asks the
 * inner signer to sign the chainId-free outer typed data, and packs the result into the
 * canonical ERC-7964 envelope. `signMessage` is intentionally unsupported because the
 * spec is EIP-712-only.
 *
 * When `signTypedData(parameters)` is called, the wrapper asserts that the incoming
 * `parameters` hash matches the current chain's operation (selected via
 * `currentChainIndex` or `chainId`). Mismatches throw so a caller whose per-chain
 * payload drifts from the `operations` array is caught immediately rather than
 * producing an envelope that silently fails on-chain.
 *
 * The returned {@link CrossChainSigner} also exposes `signCrossChainEnvelopes()`, which
 * produces one envelope per chain in the config while asking the inner signer for a
 * cross-chain signature exactly once. Use it for the "one user signature → N chains"
 * dispatch pattern.
 *
 * NOTE: A `CrossChainSigner` is not a valid top-level signer for {@link toERC7579Account}
 * or {@link toOpenAccount}. Its `signTypedData` will reject any payload that isn't one of
 * the pre-configured operations, so UserOp signing always fails.
 */
const toCrossChainSigner = (innerSigner: Signer, config: CrossChainSignerConfig): CrossChainSigner => {
  const snapshot = applyVerifyingContractDefault(snapshotConfig(config));
  const fields = resolveFields(snapshot);
  const structHashes = snapshot.operations.map(hashOperation);

  return {
    ...innerSigner,
    address: innerSigner.address,
    signerBytes: innerSigner.signerBytes,
    async signMessage() {
      throw new Error('signMessage is not supported (ERC-7964 is EIP-712 only)');
    },
    async signTypedData(parameters) {
      const currentChainIndex = resolveCurrentChainIndex(snapshot);
      const expectedCurrentHash = structHashes[currentChainIndex];
      if (expectedCurrentHash === undefined) {
        throw new Error(
          `currentChainIndex ${currentChainIndex} is out of bounds for operations of length ${snapshot.operations.length}`,
        );
      }
      const incoming = hashStruct({
        data: parameters.message,
        primaryType: parameters.primaryType,
        types: parameters.types,
      });
      if (incoming !== expectedCurrentHash) {
        throw new Error(
          `signTypedData parameters do not match operations[${currentChainIndex}]; ` +
            `expected primaryType ${JSON.stringify(snapshot.operations[currentChainIndex]!.primaryType)} ` +
            `hashStruct ${expectedCurrentHash}, got primaryType ${JSON.stringify(parameters.primaryType)} ` +
            `hashStruct ${incoming}`,
        );
      }
      return innerSigner.signTypedData(buildOuterTypedData(snapshot)).then(signature =>
        packEnvelope({
          fields,
          currentChainIndex,
          application: snapshot.application,
          structHashes,
          crossChainSignature: signature,
        }),
      );
    },
    signCrossChainEnvelopes: () => signCrossChainEnvelopes(innerSigner, snapshot),
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
 *
 * Also available as a method on the {@link CrossChainSigner} returned by
 * {@link toCrossChainSigner}, which closes over its own config.
 */
const signCrossChainEnvelopes = async (
  innerSigner: Signer,
  config: Omit<CrossChainSignerConfig, 'currentChainIndex' | 'chainId'>,
): Promise<Hex[]> => {
  const withDefaults = applyVerifyingContractDefault({
    ...config,
    operations: [...config.operations],
    domain: { ...config.domain },
  });
  const fields = resolveFields(withDefaults);
  const structHashes = withDefaults.operations.map(hashOperation);
  const crossChainSignature = await innerSigner.signTypedData(buildOuterTypedData(withDefaults));
  return withDefaults.operations.map((_, currentChainIndex) =>
    packEnvelope({
      fields,
      currentChainIndex,
      application: withDefaults.application,
      structHashes,
      crossChainSignature,
    }),
  );
};

export {
  toCrossChainSigner,
  signCrossChainEnvelopes,
  ERC7964_MAGIC,
  type ChainOperation,
  type CrossChainSignerConfig,
  type CrossChainSigner,
};
