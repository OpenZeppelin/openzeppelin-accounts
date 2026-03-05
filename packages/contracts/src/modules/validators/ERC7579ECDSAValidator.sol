// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579ECDSA} from "../ERC7579ECDSA.sol";

/**
 * @dev Implementation of an {ERC7579ECDSA} as an {ERC7579Validator}.
 *
 * This module provides ECDSA signature validation for ERC-7579 accounts. Each account
 * can have a single authorized signer (EOA address) that can approve operations through
 * ECDSA signatures.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with a signer address
 * bytes memory initData = abi.encodePacked(signerAddress);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
contract ERC7579ECDSAValidator is ERC7579ECDSA, ERC7579Validator {
    /// @dev See {_validateECDSA}.
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return _validateECDSA(account, hash, signature);
    }
}
