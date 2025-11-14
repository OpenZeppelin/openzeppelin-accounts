// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";
import {ERC7579DelayedExecutor} from "./ERC7579DelayedExecutor.sol";
import {ERC7579SocialRecoveryExecutor} from "./ERC7579SocialRecoveryExecutor.sol";
import {ERC7579Multisig} from "../ERC7579Multisig.sol";
import {Multisig} from "../../utils/Multisig.sol";

/**
 * @dev Extension of {ERC7579SocialRecoveryExecutor} that adds scheduling and expiration capabilities
 * through {ERC7579DelayedExecutor}.
 *
 * This module combines the guardian-based social recovery mechanism with time-delayed execution,
 * providing enhanced security for account recovery operations. It requires guardians to collectively
 * schedule recovery operations, which then must wait for a delay period before they can be executed.
 *
 * ==== Installation and Configuration
 *
 * The module requires configuration for both the delayed executor and multisig components:
 *
 * * Executor configuration: delay period, expiration window
 * * Multisig configuration: guardian addresses, threshold
 *
 * Example usage:
 *
 * ```solidity
 * contract MyDelayedSocialRecoveryExecutor is ERC7579DelayedSocialRecoveryExecutor {
 *     constructor() EIP712("MyDelayedSocialRecovery", "1") {}
 *
 *     function onInstall(bytes calldata data) public override {
 *         // Data format: [executorArgsLength, executorArgs, multisigArgsLength, multisigArgs]
 *         super.onInstall(data);
 *     }
 * }
 * ```
 */
abstract contract ERC7579DelayedSocialRecoveryExecutor is
    EIP712,
    ERC7579SocialRecoveryExecutor,
    ERC7579DelayedExecutor
{
    /// @dev The caller is not authorized to cancel the operation.
    error ERC7579SocialRecoveryExecutorInvalidCancel();

    /**
     * @dev Installs the delayed social recovery executor module on an account.
     *
     * This function configures both the delayed executor and multisig components required
     * for the social recovery mechanism. The installation data must contain configuration
     * for both components in a specific encoding format.
     *
     * Data encoding format: `[uint16(executorArgsLength), executorArgs, uint16(multisigArgsLength), multisigArgs]`
     */
    function onInstall(
        bytes calldata data
    ) public virtual override(ERC7579DelayedExecutor, ERC7579Multisig, IERC7579Module) {
        uint16 executorArgsLength = uint16(bytes2(data[0:2])); // First 2 bytes are the length
        bytes calldata executorArgs = data[2:2 + executorArgsLength]; // Next bytes are the args
        uint16 multisigArgsLength = uint16(bytes2(data[2 + executorArgsLength:4 + executorArgsLength])); // Next 2 bytes are the length
        bytes calldata multisigArgs = data[4 + executorArgsLength:4 + executorArgsLength + multisigArgsLength]; // Next bytes are the args

        ERC7579DelayedExecutor.onInstall(executorArgs);
        ERC7579Multisig.onInstall(multisigArgs);
    }

    /**
     * @dev Uninstalls the delayed social recovery executor module from an account.
     * See {ERC7579DelayedExecutor-onUninstall}.
     *
     * NOTE: Uninstalling this module will remove all social recovery capabilities.
     * Ensure alternative recovery mechanisms are in place before uninstalling.
     */
    function onUninstall(
        bytes calldata
    ) public virtual override(ERC7579DelayedExecutor, ERC7579Multisig, IERC7579Module) {
        ERC7579DelayedExecutor.onUninstall(Calldata.emptyBytes());
        ERC7579Multisig.onUninstall(Calldata.emptyBytes());
    }

    /// @inheritdoc ERC7579DelayedExecutor
    function _execute(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata
    ) internal virtual override(ERC7579DelayedExecutor, ERC7579Executor) returns (bytes[] memory returnData) {
        return super._execute(account, salt, mode, executionCalldata);
    }

    /// @inheritdoc ERC7579SocialRecoveryExecutor
    function _validateExecution(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata data
    ) internal virtual override(ERC7579DelayedExecutor, ERC7579SocialRecoveryExecutor) returns (bytes calldata) {
        return super._validateExecution(account, salt, mode, data);
    }

    /**
     * @dev Validates a schedule request for a delayed social recovery operation.
     * See {ERC7579DelayedExecutor-_validateSchedule}.
     *
     * This function validates that guardians have properly authorized the scheduling of
     * a recovery operation. It extracts the execution calldata and guardian signatures,
     * then verifies that the multisignature threshold is met for the EIP-712 structured
     * recovery data.
     *
     * Data encoding format: `[uint16(executionCalldataLength), executionCalldata, signature]`
     */
    function _validateSchedule(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata data
    ) internal virtual override {
        uint16 executionCalldataLength = uint16(bytes2(data[0:2])); // First 2 bytes are the length
        bytes calldata executionCalldata = data[2:2 + executionCalldataLength]; // Next bytes are the calldata
        bytes calldata signature = data[2 + executionCalldataLength:]; // Remaining bytes are the signature
        (bytes[] calldata signingSigners, bytes[] calldata signatures) = Multisig.decodeMultisignatureCalldata(
            signature
        );
        require(
            _validateMultisig(
                account,
                _getRecoverTypeHash(account, salt, mode, executionCalldata),
                signingSigners,
                signatures
            ),
            ERC7579SocialRecoveryExecutorInvalidMultisig()
        );
    }

    /**
     * @dev Validates a cancel request for a scheduled social recovery operation.
     *
     * This function ensures that only the account itself can cancel scheduled recovery
     * operations. This provides a security mechanism where the legitimate account owner
     * can cancel malicious or unwanted recovery attempts during the delay period.
     */
    function _validateCancel(
        address account,
        bytes32 /* salt */,
        bytes32 /* mode */,
        bytes calldata /* data */
    ) internal view virtual override {
        require(msg.sender == account, ERC7579SocialRecoveryExecutorInvalidCancel());
    }
}
