import {
  type Address,
  type Hex,
  type LocalAccount,
  type OneOf,
  type SignableMessage,
  type TypedDataDefinition,
} from 'viem';
import type { WebAuthnAccount, WebAuthnSignReturnType } from 'viem/account-abstraction';

export { toERC7913Signer, type ERC7913SignerConfig, type ERC7913Signer } from './erc7913.js';
export {
  toCrossChainSigner,
  signCrossChainEnvelopes,
  ERC7964_MAGIC,
  type ChainOperation,
  type CrossChainSignerConfig,
  type CrossChainSigner,
} from './crosschain.js';
export { toMultisigner, type MultisigSigner } from './multisig.js';

/**
 * Minimal signer surface consumed by {@link toERC7579Account}, {@link toOpenAccount},
 * and the wrapper functions in this directory.
 *
 * Designed to overlap structurally with viem's `LocalAccount` so that any `LocalAccount`
 * is a `Signer` without an explicit adapter. `WebAuthnAccount` and other signer shapes
 * are normalized into this interface via {@link toSigner}.
 *
 * `signTypedData` takes a structural `TypedDataDefinition` rather than a constrained
 * generic so wrappers can forward arbitrary typed-data payloads without per-call
 * inference clashing with viem's narrower account types.
 *
 * @property signMessage Signs a plain or hashed message; returns the raw signature bytes.
 * @property signTypedData Signs an EIP-712 typed data payload; returns the raw signature bytes.
 * @property address Address of the underlying EOA or smart account, when one exists.
 * @property signerBytes ERC-7913 signer bytes: `verifier(20) || key(rest)`, present on
 *   wrappers that change the on-chain identity of the signer.
 */
type Signer = {
  signMessage: (parameters: { message: SignableMessage }) => Promise<Hex>;
  signTypedData: (parameters: TypedDataDefinition) => Promise<Hex>;
  address?: Address;
  signerBytes?: Hex;
};

/**
 * Normalizes viem's signer types into the SDK's {@link Signer} interface.
 *
 * `LocalAccount.signMessage` and `signTypedData` already return `Hex`. `WebAuthnAccount`
 * returns a discriminated object whose `.signature` field carries the bytes the on-chain
 * verifier consumes; this adapter unwraps it so downstream code only sees `Hex`.
 */
const toSigner = (account: OneOf<LocalAccount | WebAuthnAccount>): Signer => {
  return {
    address: 'address' in account ? account.address : undefined,
    async signMessage({ message }) {
      const result = await account.signMessage({ message });
      return typeof result === 'object' ? (result as WebAuthnSignReturnType).signature : (result as Hex);
    },
    async signTypedData(parameters) {
      const result = await (account as LocalAccount).signTypedData(parameters);
      return typeof result === 'object' ? (result as WebAuthnSignReturnType).signature : (result as Hex);
    },
  };
};

export { toSigner, type Signer };
