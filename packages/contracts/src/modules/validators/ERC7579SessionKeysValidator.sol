// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579SessionKeys} from "../ERC7579SessionKeys.sol";
import {ERC7579Validator} from "./ERC7579Validator.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @dev Implementation of {ERC7579SessionKeys} as an {ERC7579Validator}.
 *
 * This module provides session key validation for ERC-7579 accounts. Each account can have
 * multiple registered ERC-7913 session keys, each with a configurable validity range. A
 * session key is only authorized to validate operations within its `from` to `until` timepoints.
 *
 * Each key also has a gas budget, in wei, set by the account at install time or through {setGasBudget}.
 * Validating a user operation deducts its maximum gas cost (see {_maxGasCost}) from the budget of the
 * key that signed it, and fails when the budget is insufficient. User operations with a paymaster are
 * charged as well. A key without a budget cannot validate user operations.
 *
 * > [!IMPORTANT]
 * > By default, any registered key within its validity range can validate any user
 * > operation and sign any ERC-1271 message on behalf of the account. Derived contracts
 * > should restrict the scope of what a session key is authorized to do.
 *
 * > [!NOTE]
 * > All session keys of an account share the account's ERC-4337 nonce streams, so one key can
 * > use a nonce that invalidates another key's pending user operations. Derived contracts that
 * > need per-key isolation can override {_validateUserOp} to require a nonce key bound to the session key.
 *
 * > [!NOTE]
 * > The gas budget is charged with the maximum cost of each user operation, as prefunded to the EntryPoint.
 * > Unused gas is refunded to the account but not credited back to the budget.
 *
 * > [!NOTE]
 * > Accounts supporting ERC-8043 init mode authorize the `installationSignature` through ERC-1271
 * > (see {AccountERC8043Upgradeable-_validateUserOp}). Derived contracts that restrict the user
 * > operation scope of a key should restrict {isValidSignatureWithSender} as well.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with session keys
 * bytes memory initData = abi.encode(keys, starts, ends, gasBudgets);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
abstract contract ERC7579SessionKeysValidator is ERC7579SessionKeys, ERC7579Validator {
    using Strings for string;

    /// @dev The `keys` and `gasBudgets` arrays passed to {onInstall} have different lengths.
    error ERC7579SessionKeysValidatorMismatchedGasBudgetsLength(uint256 keys, uint256 gasBudgets);

    /// @dev Emitted when the gas budget of a `key` is set for an `account`.
    event ERC7579SessionKeysValidatorGasBudgetSet(address indexed account, bytes indexed key, uint256 gasBudget);

    // The account is the innermost key so that the slot is associated with the account (ERC-7562), which allows
    // writing it during validation.
    mapping(uint256 installation => mapping(bytes32 keyId => mapping(address account => uint256))) private _gasBudgets;

    /// @dev Returns the remaining gas budget, in wei, of a `key` on an `account`.
    function gasBudget(address account, bytes calldata key) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _gasBudget(account, installation_, _keyId(account, installation_, key));
    }

    /**
     * @dev See {ERC7579SessionKeys-onInstall}. Also sets the gas budget of each key.
     *
     * The `initData` must be ABI-encoded as `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends,
     * uint256[] gasBudgets)` where each array has the same length.
     *
     * Requirements:
     *
     * * Those from {ERC7579SessionKeys-onInstall}.
     * * Those from {_decodeGasBudgetsInitData} for the decoding requirements.
     * * `gasBudgets` must have the same length as `keys`. Reverts with
     *   {ERC7579SessionKeysValidatorMismatchedGasBudgetsLength} otherwise.
     *
     * Emits an {ERC7579SessionKeysValidatorGasBudgetSet} event for each key.
     */
    function onInstall(bytes calldata initData) public virtual override(ERC7579SessionKeys, IERC7579Module) {
        super.onInstall(initData);
        (bytes[] calldata keys_, , ) = _decodeKeysInitData(initData);
        uint256[] calldata gasBudgets = _decodeGasBudgetsInitData(initData);
        require(
            keys_.length == gasBudgets.length,
            ERC7579SessionKeysValidatorMismatchedGasBudgetsLength(keys_.length, gasBudgets.length)
        );
        uint256 installation_ = installation(msg.sender);
        for (uint256 i = 0; i < keys_.length; ++i) {
            _setGasBudget(msg.sender, installation_, keys_[i], gasBudgets[i]);
        }
    }

    /**
     * @dev Sets the remaining gas budget, in wei, of a `key` for the calling account. Can only be called by the
     * account itself.
     *
     * Requirements:
     *
     * * `key` must be registered. Reverts with {ERC7579SessionKeysNonexistentKey} otherwise.
     *
     * Emits an {ERC7579SessionKeysValidatorGasBudgetSet} event.
     *
     * > [!WARNING]
     * > A session key that can make the account call this function can raise its own budget. Derived contracts
     * > that restrict the scope of a key should not allow it.
     */
    function setGasBudget(bytes calldata key, uint256 newGasBudget) public virtual {
        uint256 installation_ = installation(msg.sender);
        require(_isKey(msg.sender, installation_, key), ERC7579SessionKeysNonexistentKey(key));
        _setGasBudget(msg.sender, installation_, key, newGasBudget);
    }

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
     * If the signature is valid, deducts the maximum gas cost of `userOp` (see {_maxGasCost}) from the key's
     * {gasBudget}. Returns {ERC4337Utils.SIG_VALIDATION_FAILED} if the budget is insufficient, or if the caller
     * is not `userOp.sender`, so that only the account can spend its keys' budgets.
     *
     * > [!NOTE]
     * > The key's `from` is inclusive while the ERC-4337 `validAfter` is exclusive, so `from - 1` is
     * > packed as `validAfter`. The key is usable by the EntryPoint at `from` itself.
     *
     * > [!NOTE]
     * > Returns {ERC4337Utils.SIG_VALIDATION_FAILED} immediately if {CLOCK_MODE} returns a mode
     * > other than timestamp or blocknumber from the same chain (default), as the EntryPoint does not support
     * > other validity range formats.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256) {
        string memory clockMode = CLOCK_MODE();
        bool blockRange = clockMode.equal("mode=blocknumber&from=default");
        bool timestampRange = clockMode.equal("mode=timestamp");
        if (!blockRange && !timestampRange) {
            return ERC4337Utils.SIG_VALIDATION_FAILED; // Unrecognized validity range.
        }
        bytes calldata key;
        (, key, ) = _tryDecodeSignature(userOp.signature); // `success` is checked further down in `super._validateUserOp` -> `_rawERC7579Validation`
        uint256 installation_ = installation(userOp.sender);
        bytes32 keyId = _keyId(userOp.sender, installation_, key);
        // We know from the resolution order that `super._validateUserOp` calls `ERC7579Validator._rawERC7579Validation`
        // which only returns SIG_VALIDATION_FAILED or SIG_VALIDATION_SUCCESS.
        uint256 sigResult = super._validateUserOp(userOp, userOpHash);
        if (sigResult == ERC4337Utils.SIG_VALIDATION_SUCCESS) {
            if (msg.sender != userOp.sender) return ERC4337Utils.SIG_VALIDATION_FAILED; // Only the account spends the budget.
            uint256 budget = _gasBudget(userOp.sender, installation_, keyId);
            uint256 cost = _maxGasCost(userOp);
            if (cost > budget) return ERC4337Utils.SIG_VALIDATION_FAILED; // Insufficient gas budget.
            _gasBudgets[installation_][keyId][userOp.sender] = budget - cost; // Cannot underflow given the check above.
        }
        (uint48 from, uint48 until) = _validity(userOp.sender, installation_, keyId);
        ERC4337Utils.ValidationRange range = blockRange
            ? ERC4337Utils.ValidationRange.BLOCK
            : ERC4337Utils.ValidationRange.TIMESTAMP;
        return
            ERC4337Utils.packValidationData(
                address(uint160(sigResult)), // Safe cast. Either SIG_VALIDATION_FAILED or SIG_VALIDATION_SUCCESS.
                uint48(Math.saturatingSub(from, 1)), // Safe cast. Result is at most `from`.
                until,
                range
            );
    }

    /// @dev Internal version of {gasBudget} that receives an `installation_` nonce.
    function _gasBudget(address account, uint256 installation_, bytes32 keyId) internal view virtual returns (uint256) {
        return _gasBudgets[installation_][keyId][account];
    }

    /**
     * @dev Internal function to set the remaining gas budget of a `key` for an `account`. Does not check
     * whether `key` is registered.
     *
     * Emits an {ERC7579SessionKeysValidatorGasBudgetSet} event.
     */
    function _setGasBudget(
        address account,
        uint256 installation_,
        bytes calldata key,
        uint256 newGasBudget
    ) internal virtual {
        _gasBudgets[installation_][_keyId(account, installation_, key)][account] = newGasBudget;
        emit ERC7579SessionKeysValidatorGasBudgetSet(account, key, newGasBudget);
    }

    /**
     * @dev Returns the maximum gas cost, in wei, of `userOp`.
     *
     * This is the prefund the EntryPoint requires: `requiredGas * maxFeePerGas`, where `requiredGas` is the sum of
     * `preVerificationGas`, `verificationGasLimit`, `callGasLimit`, `paymasterVerificationGasLimit` and
     * `paymasterPostOpGasLimit` (the last two are zero when `paymasterAndData` is empty). The fee paid to the
     * bundler's beneficiary never exceeds it.
     *
     * > [!NOTE]
     * > `maxFeePerGas` is used instead of the effective gas price because ERC-7562 bans the `BASEFEE` opcode during
     * > validation.
     */
    function _maxGasCost(PackedUserOperation calldata userOp) internal pure virtual returns (uint256) {
        // The four gas limits and `maxFeePerGas` are unpacked from 128-bit fields, so the sum of the limits fits
        // in 130 bits. `preVerificationGas` is a full uint256, so the saturating operations bound the result to
        // `type(uint256).max`.
        uint256 gasLimits = ERC4337Utils.verificationGasLimit(userOp) +
            ERC4337Utils.callGasLimit(userOp) +
            ERC4337Utils.paymasterVerificationGasLimit(userOp) +
            ERC4337Utils.paymasterPostOpGasLimit(userOp);
        return
            Math.saturatingMul(
                Math.saturatingAdd(userOp.preVerificationGas, gasLimits),
                ERC4337Utils.maxFeePerGas(userOp)
            );
    }

    /**
     * @dev Decodes the `gasBudgets` array from the initialization data. See {onInstall}.
     *
     * Requirements:
     *
     * * `initData` must be at least 256 bytes (8 × 32 bytes for the 4 ABI offsets and 4 array lengths).
     * * The `gasBudgets` offset must point past the 4-word head, and its data must be within the `initData` bounds.
     *
     * Reverts with {ERC7579SessionKeysInvalidInitData} if the encoding is invalid.
     */
    function _decodeGasBudgetsInitData(
        bytes calldata initData
    ) internal pure virtual returns (uint256[] calldata gasBudgets) {
        require(initData.length > 0xff, ERC7579SessionKeysInvalidInitData());
        uint256 gasBudgetsOffset = uint256(bytes32(initData[0x60:0x80]));
        // The offset must point past the 4-word head, which rejects 3-array encodings whose 4th word is not an offset.
        require(
            gasBudgetsOffset > 0x7f && gasBudgetsOffset < initData.length - 0x1f,
            ERC7579SessionKeysInvalidInitData()
        );
        uint256 gasBudgetsDataOffset = gasBudgetsOffset + 0x20; // Cannot overflow given the check above.
        uint256 gasBudgetsLength = uint256(bytes32(initData[gasBudgetsOffset:gasBudgetsDataOffset]));
        require(
            gasBudgetsLength <= (initData.length - gasBudgetsDataOffset) / 0x20,
            ERC7579SessionKeysInvalidInitData()
        );
        assembly ("memory-safe") {
            gasBudgets.offset := add(initData.offset, gasBudgetsDataOffset)
            gasBudgets.length := gasBudgetsLength
        }
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
