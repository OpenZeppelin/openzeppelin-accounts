// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579P256} from "../ERC7579P256.sol";

/**
 * @dev Implementation of an {ERC7579P256} as an {ERC7579Validator}.
 *
 * This module provides P256 signature validation for ERC-7579 accounts. Each account
 * can have a single authorized P256 signer (public key coordinates) that can approve
 * operations through P256 signatures.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with P256 public key coordinates
 * bytes memory initData = abi.encodePacked(qx, qy);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
contract ERC7579P256Validator is ERC7579P256, ERC7579Validator {
    /// @dev See {_validateP256}.
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return _validateP256(account, hash, signature);
    }
}
