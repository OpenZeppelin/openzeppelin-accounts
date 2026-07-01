import type { Hex, LocalAccount, OneOf } from 'viem';
import type { WebAuthnAccount, WebAuthnSignReturnType } from 'viem/account-abstraction';
import type { Signer } from './types.js';

/**
 * Normalizes viem's signer types into the SDK's {@link Signer} interface.
 *
 * `LocalAccount.signMessage` and `signTypedData` already return `Hex`. `WebAuthnAccount`
 * returns a discriminated object whose `.signature` field carries the bytes the on-chain
 * verifier consumes; this adapter unwraps it so downstream code only sees `Hex`.
 */
const toSigner = (account: OneOf<LocalAccount | WebAuthnAccount>): Signer => {
  const inner = account as LocalAccount;
  return {
    address: 'address' in account ? account.address : undefined,
    async signMessage({ message }) {
      const result = await inner.signMessage({ message });
      return typeof result === 'object' ? (result as WebAuthnSignReturnType).signature : (result as Hex);
    },
    async signTypedData(parameters) {
      const result = await inner.signTypedData(parameters);
      return typeof result === 'object' ? (result as WebAuthnSignReturnType).signature : (result as Hex);
    },
  };
};

export { toSigner };
