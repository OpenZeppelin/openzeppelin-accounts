import type { Address, Hex, SignableMessage, TypedDataDefinition } from 'viem';

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
export type Signer = {
  signMessage: (parameters: { message: SignableMessage }) => Promise<Hex>;
  signTypedData: (parameters: TypedDataDefinition) => Promise<Hex>;
  address?: Address;
  signerBytes?: Hex;
};
