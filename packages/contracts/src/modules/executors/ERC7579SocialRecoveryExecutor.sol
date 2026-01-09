// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {ERC7579DelayedExecutor} from "./ERC7579DelayedExecutor.sol";
import {Multisig} from "../../utils/Multisig.sol";
import {ERC7579MultisigWeighted} from "../ERC7579MultisigWeighted.sol";

/**
 * @dev Social recovery executor module for ERC-7579 accounts.
 *
 * This module combines weighted multisignature validation with time-delayed execution to provide
 * a secure and flexible social recovery mechanism. Trusted guardians can collectively schedule
 * recovery operations, which execute after a security delay, giving the legitimate account owner
 * time to detect and cancel malicious recovery attempts.
 *
 * To schedule operations, guardians must sign an EIP-712 typed data hash of the operation using
 * the account's domain separator and provide it to the {startRecovery} function. Once scheduled,
 * operations must wait for the configured delay period before becoming executable via {executeRecovery}.
 *
 * Operations can be canceled by either the account itself or by guardians via {cancelRecovery}
 * with a valid multisignature.
 *
 * See {ERC7579DelayedExecutor} and {ERC7579MultisigWeighted} for more details.
 *
 * NOTE: This module does not restrict execution by default once the social recovery operation
 * is ready. Anyone can call {executeRecovery} once the delay period has elapsed.
 */
contract ERC7579SocialRecoveryExecutor is ERC7579DelayedExecutor, ERC7579MultisigWeighted {
    using MessageHashUtils for *;

    bytes32 public constant SCHEDULE_RECOVER_TYPEHASH =
        keccak256("ScheduleRecover(bytes32 salt,bytes32 mode,bytes recoveryCalldata)");
    bytes32 public constant CANCEL_RECOVER_TYPEHASH =
        keccak256("CancelRecover(bytes32 salt,bytes32 mode,bytes recoveryCalldata)");

    /// @dev The multisignature validation failed.
    error ERC7579SocialRecoveryExecutorInvalidSchedule();

    /// @dev The caller is not authorized to cancel the operation.
    error ERC7579SocialRecoveryExecutorInvalidCancel();

    /**
     * @dev Installs the social recovery executor module on an account.
     *
     * This function configures both the delayed executor and weighted multisig components
     * required for the social recovery mechanism. The installation data must contain
     * configuration for both components in the specified encoding format.
     *
     * Data encoding format: `[uint16(executorArgsLength), executorArgs, uint16(multisigArgsLength), multisigArgs]`
     *
     * Requirements:
     *
     * * See {ERC7579DelayedExecutor-onInstall} for delay/expiration requirements
     * * See {ERC7579MultisigWeighted-onInstall} for guardian configuration requirements
     */
    function onInstall(bytes calldata data) public virtual override(ERC7579DelayedExecutor, ERC7579MultisigWeighted) {
        uint16 executorArgsLength = uint16(bytes2(data[0:2])); // First 2 bytes are the length
        bytes calldata executorArgs = data[2:2 + executorArgsLength]; // Next bytes are the args
        uint16 multisigArgsLength = uint16(bytes2(data[2 + executorArgsLength:4 + executorArgsLength])); // Next 2 bytes are the length
        bytes calldata multisigArgs = data[4 + executorArgsLength:4 + executorArgsLength + multisigArgsLength]; // Next bytes are the args

        ERC7579DelayedExecutor.onInstall(executorArgs);
        ERC7579MultisigWeighted.onInstall(multisigArgs);
    }

    /**
     * @dev Uninstalls the social recovery executor module from an account.
     *
     * This cleans up both the delayed executor configuration and all guardian-related state.
     * After uninstallation, all social recovery capabilities are removed.
     *
     * IMPORTANT: Ensure alternative recovery mechanisms or access methods are in place
     * before uninstalling this module. Uninstalling social recovery without a backup
     * access method could result in account lockout if primary credentials are lost.
     *
     * See {ERC7579DelayedExecutor-onUninstall} and {ERC7579MultisigWeighted-onUninstall}.
     */
    function onUninstall(bytes calldata) public virtual override(ERC7579DelayedExecutor, ERC7579MultisigWeighted) {
        ERC7579DelayedExecutor.onUninstall(Calldata.emptyBytes());
        ERC7579MultisigWeighted.onUninstall(Calldata.emptyBytes());
    }

    /// @dev Returns a slice of the set of guardians for the specified account. See {getSigners}.
    function getGuardians(address account, uint64 start, uint64 end) public view returns (bytes[] memory) {
        return getSigners(account, start, end);
    }

    /// @dev Returns the number of guardians for the specified account. See {getSignerCount}.
    function getGuardianCount(address account) public view returns (uint256) {
        return getSignerCount(account);
    }

    /// @dev Returns whether the `guardian` is an authorized guardian for the specified account. See {isSigner}.
    function isGuardian(address account, bytes memory guardian) public view returns (bool) {
        return isSigner(account, guardian);
    }

    /// @dev Adds new guardians to the authorized set for the calling account. See {addSigners}.
    function addGuardians(bytes[] memory newGuardians) public {
        addSigners(newGuardians);
    }

    /// @dev Removes guardians from the authorized set for the calling account. See {removeSigners}.
    function removeGuardians(bytes[] memory oldGuardians) public {
        removeSigners(oldGuardians);
    }

    /**
     * @dev Schedules a social recovery operation for the specified account.
     *
     * The `recoveryData` is the encoded execution that will be sent to the account, and it
     * follows the ERC-7579 standard encoding. The `multisignature` is a valid authorization
     * from the guardians to schedule the operation and must be signed over the
     * {SCHEDULE_RECOVER_TYPEHASH} typed data hash of the operation using the account's domain
     * separator.
     *
     * Requirements:
     *
     * * The multisignature must be valid and meet the threshold requirements.
     *   Reverts with {ERC7579SocialRecoveryExecutorInvalidSchedule} if not.
     * * The signature must be encoded properly. See {ERC7579MultisigWeighted-_validateMultisig}.
     * * See {ERC7579DelayedExecutor-_schedule} for scheduling requirements.
     * * The `account` must implement {IERC5267}.
     */
    function startRecovery(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata recoveryData,
        bytes calldata multisignature
    ) public virtual {
        (bool success, bytes[] calldata signers, bytes[] calldata signatures) = Multisig
            .tryDecodeMultisignatureCalldata(multisignature);

        require(
            success &&
                _validateMultisig(
                    account,
                    _getTypedHash(SCHEDULE_RECOVER_TYPEHASH, account, salt, mode, recoveryData),
                    signers,
                    signatures
                ),
            ERC7579SocialRecoveryExecutorInvalidSchedule()
        );
        _schedule(account, salt, mode, recoveryData);
    }

    /**
     * @dev Executes a social recovery operation for the specified account.
     *
     * This function can be called by any account once the operation is ready (i.e., the delay
     * period has elapsed). The operation must be in the `Ready` state to be executed.
     *
     * Requirements:
     *
     * * See {ERC7579DelayedExecutor-_execute} for execution requirements.
     */
    function executeRecovery(address account, bytes32 salt, bytes32 mode, bytes calldata recoveryData) public virtual {
        _execute(account, salt, mode, recoveryData);
    }

    /**
     * @dev Cancels a social recovery operation.
     *
     * This function allows either the account itself or guardians with valid multisignature
     * authorization to cancel a scheduled recovery operation. If the caller is not the account,
     * the `multisignature` must contain valid guardian signatures over the {CANCEL_RECOVER_TYPEHASH}
     * typed data hash using the account's domain separator.
     *
     * Requirements:
     *
     * * The caller must be the account or a valid `multisignature` must be provided.
     * * See {ERC7579DelayedExecutor-_cancel} for cancellation requirements.
     * * The `account` must implement {IERC5267}.
     */
    function cancelRecovery(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata recoveryData,
        bytes calldata multisignature
    ) public virtual {
        bool valid = msg.sender == account;
        if (!valid) {
            (bool success, bytes[] calldata signers, bytes[] calldata signatures) = Multisig
                .tryDecodeMultisignatureCalldata(multisignature);
            valid =
                success &&
                _validateMultisig(
                    account,
                    _getTypedHash(CANCEL_RECOVER_TYPEHASH, account, salt, mode, recoveryData),
                    signers,
                    signatures
                );
        }
        require(valid, ERC7579SocialRecoveryExecutorInvalidCancel());
        _cancel(account, salt, mode, recoveryData);
    }

    /// @dev Same as {cancelRecovery}, but without a `multisignature`.
    function cancelRecovery(address account, bytes32 salt, bytes32 mode, bytes calldata recoveryData) public virtual {
        cancelRecovery(account, salt, mode, recoveryData, Calldata.emptyBytes());
    }

    /**
     * @dev Generates the EIP-712 typed data hash for an operation using the `typehash` and the
     * `account`'s domain separator.
     *
     * The typed data structure includes:
     *
     * * `salt`: Unique salt for this operation
     * * `mode`: Execution mode as defined in ERC-7579
     * * `recoveryCalldata`: The exact calldata to be executed during recovery
     *
     * Requirements:
     *
     * * The `account` must implement {IERC5267}.
     */
    function _getTypedHash(
        bytes32 typehash,
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata recoveryCalldata
    ) private view returns (bytes32) {
        bytes1 fields;
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;
        bytes32 domainSalt;
        (fields, name, version, chainId, verifyingContract, domainSalt, ) = IERC5267(account).eip712Domain();
        return
            fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt).toTypedDataHash(
                keccak256(abi.encode(typehash, salt, mode, keccak256(recoveryCalldata)))
            );
    }
}
