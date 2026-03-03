// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579P256Validator} from "./ERC7579P256Validator.sol";
import {ERC7579WebAuthn} from "../ERC7579WebAuthn.sol";

/**
 * @dev Implementation of an {ERC7579WebAuthn} as an {ERC7579P256Validator}.
 *
 * This module provides WebAuthn signature validation for ERC-7579 accounts. Each account
 * can have a single authorized WebAuthn credential (P256 public key) that can approve
 * operations through WebAuthn authentication assertions.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with WebAuthn public key coordinates
 * bytes memory initData = abi.encodePacked(qx, qy);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
contract ERC7579WebAuthnValidator is ERC7579WebAuthn, ERC7579P256Validator {
    /// @dev See {_validateWebAuthn}.
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return _validateWebAuthn(account, hash, signature);
    }
}
