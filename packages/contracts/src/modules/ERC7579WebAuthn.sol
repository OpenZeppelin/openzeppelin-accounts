// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579P256} from "./ERC7579P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/**
 * @dev Implementation of an {IERC7579Module} that uses a WebAuthn credential for signature
 * validation.
 *
 * This module provides a base implementation for WebAuthn signature validation that can be
 * attached to any function through the {_validateWebAuthn} internal function.
 *
 * > [!NOTE]
 * > As in the {WebAuthn} library, `clientDataJSON.origin` and `authenticatorData.rpIdHash` are not
 * > checked. Register credentials under an RP ID you fully control.
 */
abstract contract ERC7579WebAuthn is ERC7579P256 {
    /**
     * @dev Validates a WebAuthn authentication assertion against the configured signer for the account.
     *
     * Returns `false` if the signature is not a valid WebAuthn authentication assertion.
     *
     * The signature is expected to be an abi-encoded {WebAuthn-WebAuthnAuth} struct.
     */
    function _validateWebAuthn(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        (bool decodeSuccess, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
        if (!decodeSuccess) return false;
        (bytes32 qx, bytes32 qy) = signer(account);
        return WebAuthn.verify(abi.encodePacked(hash), auth, qx, qy);
    }
}
