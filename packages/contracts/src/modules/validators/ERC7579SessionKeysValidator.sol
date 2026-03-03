// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {ERC7579SessionKeys} from "../ERC7579SessionKeys.sol";
import {ERC7579Validator} from "./ERC7579Validator.sol";

/**
 * @dev Implementation of {ERC7579SessionKeys} as an {ERC7579Validator}.
 *
 * This module provides session key validation for ERC-7579 accounts. Each account can have
 * multiple registered ERC-7913 session keys, each with a configurable validity range. A
 * session key is only authorized to validate operations within its `from` to `until` timepoints.
 *
 * IMPORTANT: By default, any registered key within its validity range can validate any user
 * operation and sign any ERC-1271 message on behalf of the account. Derived contracts
 * should restrict the scope of what a session key is authorized to do.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with session keys
 * bytes memory initData = abi.encode(keys, starts, ends);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
abstract contract ERC7579SessionKeysValidator is ERC7579SessionKeys, ERC7579Validator {
    /**
     * @dev See {IERC7579Validator-isValidSignatureWithSender}.
     *
     * Enforces the validity range of the session key manually since the EntryPoint is not
     * involved in ERC-1271 signature validation. See {_tryDecodeSignature} for the encoding details.
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) public view virtual override returns (bytes4) {
        bytes calldata key;
        (, key, ) = _tryDecodeSignature(signature); // `success` is checked further down in `super.isValidSignatureWithSender` -> `_rawERC7579Validation`
        return
            isValid(msg.sender, key) ? super.isValidSignatureWithSender(sender, hash, signature) : bytes4(0xffffffff);
    }

    /**
     * @dev See {ERC7579Validator-_validateUserOp}.
     *
     * Decodes the session key from `userOp.signature` and reads its validity range. The range
     * is packed into the returned `validationData` so the EntryPoint enforces it without
     * requiring an explicit timestamp check in the validator.
     * See {_tryDecodeSignature} for the signature encoding details.
     *
     * NOTE: Returns {ERC4337Utils.SIG_VALIDATION_FAILED} immediately if {clock} returns a value
     * that is neither the current block timestamp nor the current block number, as the EntryPoint
     * does not support other validity range formats.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256) {
        uint48 timepoint = clock();
        bool blockRange = timepoint == Time.blockNumber();
        bool timestampRange = timepoint == Time.timestamp();
        if (!blockRange && !timestampRange) {
            return ERC4337Utils.SIG_VALIDATION_FAILED; // Unrecognized validity range.
        }
        bytes calldata key;
        (, key, ) = _tryDecodeSignature(userOp.signature); // `success` is checked further down in `super._validateUserOp` -> `_rawERC7579Validation`
        (uint48 from, uint48 until) = validity(userOp.sender, key);
        ERC4337Utils.ValidationRange range = blockRange
            ? ERC4337Utils.ValidationRange.BLOCK
            : ERC4337Utils.ValidationRange.TIMESTAMP;
        // We know from the resolution order that `super._validateUserOp` calls `ERC7579Validator._rawERC7579Validation`
        // which only returns SIG_VALIDATION_FAILED or SIG_VALIDATION_SUCCESS. Casting to address(uint160) is safe.
        return address(uint160(super._validateUserOp(userOp, userOpHash))).packValidationData(from, until, range);
    }

    /// @dev See {_validateSessionKey}.
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return _validateSessionKey(account, hash, signature);
    }
}
