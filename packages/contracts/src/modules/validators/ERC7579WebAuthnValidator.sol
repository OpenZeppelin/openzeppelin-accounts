// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579P256Validator} from "./ERC7579P256Validator.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/**
 * @dev Implementation of an {ERC7579P256Validator} that uses WebAuthn signatures for validation.
 *
 * This module extends the P256 validator to provide WebAuthn signature validation for ERC-7579 accounts.
 *
 * Each account can have a single authorized WebAuthn credential (P256 public key) that can approve
 * operations through WebAuthn authentication assertions.
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
     * @dev Validates a WebAuthn authentication assertion against the configured signer for the account.
     *
     * Returns `false` if the signature is not a valid WebAuthn authentication assertion.
     *
     * The signature is expected to be an abi-encoded {WebAuthn-WebAuthnAuth} struct.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bool decodeSuccess, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
        if (!decodeSuccess) return false;
        (bytes32 qx, bytes32 qy) = signer(account);
        return WebAuthn.verify(abi.encodePacked(hash), auth, qx, qy);
    }
}
