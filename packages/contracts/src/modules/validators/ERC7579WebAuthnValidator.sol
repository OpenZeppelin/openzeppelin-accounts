// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579P256Validator} from "./ERC7579P256Validator.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/**
 * @dev Implementation of an {ERC7579P256Validator} that uses WebAuthn signatures for validation.
 *
 * This module extends the P256 validator to provide WebAuthn signature validation for ERC-7579 accounts.
 * It supports both WebAuthn authentication assertions and raw P256 signatures, providing compatibility
 * with both signature types.
 *
 * Each account can have a single authorized WebAuthn credential (P256 public key) that can approve
 * operations through WebAuthn authentication assertions or raw P256 signatures.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with P256 public key coordinates
 * bytes memory initData = abi.encodePacked(qx, qy);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
contract ERC7579WebAuthnValidator is ERC7579P256Validator {
    /**
     * @dev Validates a signature against the configured signer for the account.
     *
     * This function first attempts to decode the signature as a WebAuthn authentication assertion
     * and verifies it against the P256 public key stored for the given account. If WebAuthn
     * decoding fails, it falls back to raw P256 signature validation.
     *
     * For WebAuthn signatures, the signature is expected to be an abi-encoded WebAuthnAuth struct
     * containing the authentication assertion data. For raw P256 signatures, the signature should
     * contain the r and s components as 32-byte values.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bool decodeSuccess, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
        if (!decodeSuccess) return super._rawERC7579Validation(account, hash, signature);
        (bytes32 qx, bytes32 qy) = signer(account);
        return WebAuthn.verify(abi.encodePacked(hash), auth, qx, qy);
    }
}
