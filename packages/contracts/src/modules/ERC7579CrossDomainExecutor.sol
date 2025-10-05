// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "../utils/MessageHashUtils.sol";

/**
 * @dev Cross-chain executor module that enables the same operation to be executed on accounts
 * deterministically deployed across multiple chains using cross-chain signatures.
 *
 * This module implements a signature-based approach where a single signature can authorize
 * the same operation across multiple chains. It uses EIP-712 domain separation with the
 * chainId field ignored, allowing signatures to be valid across all chains where the account
 * is deployed.
 *
 * Cross-domain signatures execute **identical operations** across all chains. The same
 * calldata, mode, and salt are used everywhere. This enables coordination but limits
 * flexibility compared to chain-specific operations. **Operations include expiration deadlines**
 * to prevent replay attacks on newly deployed accounts. Some use cases include:
 *
 * - **Module Management**: Install/uninstall the same module across all account instances
 * - **Configuration Sync**: Update account settings (spending limits, timeouts) uniformly
 * - **Permission Updates**: Grant/revoke the same permissions across all chains
 * - **Emergency Actions**: Pause/unpause functionality across the entire multichain setup
 *
 * #### Usage pattern:
 *
 * 1. Generate signature with cross-chain domain (chainId ignored) including expiration deadline
 * 2. Submit operation with signature to any chain before deadline
 * 3. Module validates signature, checks expiration, and executes if not already processed (see `_validateExecution`)
 * 4. Same signature can be used on other chains for identical operations (until deadline)
 */
abstract contract ERC7579CrossDomainExecutor is ERC7579Executor {
    /// @dev Thrown when attempting to execute an operation that has already been executed
    error OperationAlreadyExecuted(bytes32 operationId);

    /// @dev Thrown when the provided signature is invalid for the operation
    error InvalidOperationSignature(bytes32 operationId);

    /// @dev Thrown when the operation has expired
    error OperationExpired(bytes32 operationId, uint48 deadline);

    mapping(bytes32 operationId => bool) private _executed;

    bytes32 private constant EXECUTE_OPERATION =
        keccak256(
            "ExecuteCrossDomainOperation(address account,bytes32 mode,bytes executionCalldata,bytes32 salt,uint48 deadline)"
        );

    /**
     * @dev Validates execution by verifying cross-chain signature and checking
     * whether the operation has already been executed and is not expired.
     *
     * The expected format of `data` is (packed):
     * `[uint16(signatureLength), signature, uint48(deadline), executionCalldata]`
     *
     * Requirements:
     *
     * - The `account` must implement the IERC5267 interface.
     * - The operation must not have been executed before.
     * - The operation must not be expired (deadline > block.timestamp).
     * - The signature must be valid over the operation's EIP-712 struct hash using the cross-chain domain separator.
     * - The `data` field must be in the expected format.
     *
     * IMPORTANT: Providing a deadline that's too high may result in the operation being eventually
     * executed on a chain where the account is not deployed yet.
     */
    function _validateExecution(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata data
    ) internal view override returns (bytes calldata) {
        // Fetch account's domain separator following ERC-5267
        (
            ,
            string memory name,
            string memory version,
            ,
            address verifyingContract,
            bytes32 domainSalt,

        ) = IERC5267(account).eip712Domain();

        // Extract the signature from the data (first 2 bytes are the length)
        uint16 signatureLength = uint16(bytes2(data[0:2]));

        // Extract the deadline (next 6 bytes after signature)
        uint48 deadline = uint48(
            bytes6(data[2 + signatureLength:2 + signatureLength + 6])
        );

        // Compute the operation's EIP-712 struct hash
        bytes32 operationStructHash = _operationStructHash(
            account,
            salt,
            mode,
            deadline,
            data[2 + signatureLength + 6:] // executionCalldata after deadline
        );

        require(
            !_executed[operationStructHash],
            OperationAlreadyExecuted(operationStructHash)
        );

        // Check if operation has expired
        require(
            deadline > block.timestamp,
            OperationExpired(operationStructHash, deadline)
        );

        // Compute the typed data hash using the cross-chain domain separator and the operation's EIP-712 struct hash
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            MessageHashUtils.toDomainSeparator(
                bytes1(0x1b), // 0b11011 Ignore chainId
                name,
                version,
                0, // Ignored
                verifyingContract,
                domainSalt
            ),
            operationStructHash
        );

        // Verify the signature
        require(
            SignatureChecker.isValidSignatureNow(
                account,
                typedDataHash,
                data[:signatureLength] // Actual signature
            ),
            InvalidOperationSignature(operationStructHash)
        );

        return data[2 + signatureLength:]; // Return execution calldata and deadline after signature
    }

    /// @dev Internal execution function that marks operations as executed and delegates to parent.
    function _execute(
        address account,
        bytes32 mode,
        bytes32 salt,
        bytes calldata executionCalldata
    ) internal override returns (bytes[] memory returnData) {
        uint48 deadline = uint48(bytes6(executionCalldata[:6]));
        bytes calldata executionCalldataWithoutDeadline = executionCalldata[6:];
        _executed[
            _operationStructHash(
                account,
                salt,
                mode,
                deadline,
                executionCalldataWithoutDeadline
            )
        ] = true; // Mark the operation as executed
        return
            super._execute(
                account,
                mode,
                salt,
                executionCalldataWithoutDeadline
            );
    }

    /// @dev Computes the EIP-712 struct hash for a cross-domain execute operation with deadline.
    function _operationStructHash(
        address account,
        bytes32 salt,
        bytes32 mode,
        uint48 deadline,
        bytes calldata executionCalldata
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    EXECUTE_OPERATION,
                    account,
                    salt,
                    mode,
                    executionCalldata,
                    deadline
                )
            );
    }
}
