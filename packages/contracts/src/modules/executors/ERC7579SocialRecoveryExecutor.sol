// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";
import {ERC7579Multisig} from "../ERC7579Multisig.sol";
import {Multisig} from "../../utils/Multisig.sol";

/**
 * @dev Social recovery executor module for ERC-7579 accounts.
 *
 * This module enables social recovery mechanisms where a set of trusted guardians can collectively
 * recover access to a smart account. It inherits multisignature functionality from {ERC7579Multisig},
 * where signers are interpreted as guardians who can authorize recovery operations.
 *
 * ==== Guardian-Based Recovery
 *
 * The module leverages the multisignature pattern where guardians (signers) can collectively authorize
 * recovery operations. The threshold mechanism ensures that a minimum number of guardians must agree
 * before any recovery operation can be executed.
 *
 * ==== EIP-712 Structured Data
 *
 * Recovery operations use EIP-712 structured data signing to ensure guardians are signing the exact
 * recovery operation details including the target account, operation salt, execution mode, and calldata.
 * This prevents signature replay attacks and ensures guardians understand what they're authorizing.
 *
 * TIP: For time-delayed social recovery with additional security features, consider using
 * {ERC7579DelayedSocialRecoveryExecutor} which adds scheduling and expiration mechanisms.
 */
abstract contract ERC7579SocialRecoveryExecutor is EIP712, ERC7579Executor, ERC7579Multisig, Nonces {
    bytes32 private constant RECOVER_TYPEHASH =
        keccak256("Recover(address account,bytes32 salt,uint256 nonce,bytes32 mode,bytes executionCalldata)");

    /// @dev The multisignature is invalid.
    error ERC7579SocialRecoveryExecutorInvalidMultisig();

    /**
     * @dev Validates a recovery execution by verifying guardian signatures. See {ERC7579Executor-_validateExecution}.
     *
     * This function extracts the execution calldata and guardian signatures from the provided data,
     * then validates that the required threshold of guardians have signed the recovery operation.
     * The validation uses EIP-712 structured data to ensure guardians are signing the exact
     * recovery parameters.
     *
     * Data encoding format: `[uint16(executionCalldataLength), executionCalldata, signature]`
     *
     * * First 2 bytes: Length of the execution calldata
     * * Next N bytes: The actual execution calldata to be executed
     * * Remaining bytes: Guardian signatures in the format expected by {ERC7579Multisig-_rawERC7579Validation}
     */
    function _validateExecution(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata data
    ) internal virtual override returns (bytes calldata) {
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
        return executionCalldata;
    }

    /**
     * @dev Generates the EIP-712 typed data hash for a recovery operation.
     *
     * This function creates a structured data hash that guardians must sign to authorize
     * a recovery operation. The hash includes all critical parameters of the recovery
     * operation to ensure guardians are signing the exact operation details.
     *
     * The typed data structure includes:
     *
     * * `account`: The smart account address being recovered
     * * `salt`: Unique salt for this recovery operation
     * * `nonce`: Account nonce to prevent replay attacks (consumed during this call)
     * * `mode`: Execution mode as defined in ERC-7579
     * * `executionCalldata`: The exact calldata to be executed during recovery
     */
    function _getRecoverTypeHash(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata
    ) internal virtual returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(RECOVER_TYPEHASH, account, salt, _useNonce(account), mode, executionCalldata))
            );
    }
}
