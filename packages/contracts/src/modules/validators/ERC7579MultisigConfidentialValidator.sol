// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579MultisigConfidential} from "../ERC7579MultisigConfidential.sol";
import {FHE, euint256, ebool} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @dev Implementation of {ERC7579Validator} that uses {ERC7579MultisigConfidential}
 * for confidential multisignature validation.
 *
 * The validation process requires a two-phase approach due to FHE's asynchronous
 * decryption model:
 *
 * 1. A relayer calls `requestDiscloseUserOperation` to validate the multisig and
 *    make the encrypted result publicly decryptable so that a decryption proof
 *    can be included in the user operation signature.
 * 2. The user operation is sent through the entrypoint and the validator calls
 *    `_rawERC7579Validation` to verify the decryption proof for the user operation.
 *
 * NOTE: By definition, the user operation is public in the bundler mempool the moment it's
 * submitted. Users must not assume that the user operation is confidential, and should consider
 * front running risks associated with the user operation payload.
 */
contract ERC7579MultisigConfidentialValidator is ERC7579MultisigConfidential, ERC7579Validator {
    /// @dev Emitted when a disclosure request is made for a user operation.
    event UserOperationDiscloseRequested(address indexed account, bytes32 indexed hash, ebool valid);

    /// @dev Emitted when a user operation is disclosed with its decryption proof verified.
    event UserOperationDisclosed(address indexed account, bytes32 indexed hash, ebool valid, bool cleartextBool);

    mapping(bytes32 userOpHash => ebool encryptedResult) private _pendingDisclosures;
    mapping(bytes32 userOpHash => bool) private _disclosed;

    /**
     * @dev Requests disclosure of the multisignature validation result for a user operation.
     *
     * This function validates the multisignature using encrypted values and makes the
     * result publicly decryptable. This must be called off-chain before sending the
     * user operation to enable the decryption proof to be included in the signature.
     *
     * NOTE: This function does not perform any access control. Anyone can request disclosure
     * of the multisignature validation result for any user operation.
     *
     * Emits a {UserOperationDiscloseRequested} event.
     */
    function requestDiscloseUserOperation(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        euint256[] calldata signerIdHandles,
        bytes[] calldata signatures
    ) public {
        ebool valid = _validateMultisig(account, hash, signingSigners, signerIdHandles, signatures);
        FHE.makePubliclyDecryptable(valid);
        _pendingDisclosures[hash] = valid;
        emit UserOperationDiscloseRequested(account, hash, valid);
    }

    /**
     * @dev Verifies the decryption proof for a disclosed user operation.
     *
     * Requirements:
     *
     * * The decryption proof must be cryptographically valid. Reverts if invalid.
     *
     * Emits a {UserOperationDisclosed} event.
     */
    function discloseUserOperation(bytes32 hash, bytes calldata decryptionProof) public {
        ebool valid = _pendingDisclosures[hash];

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = ebool.unwrap(valid);
        bool cleartextBool = true; // Must be true by design
        bytes memory cleartextMemory = abi.encode(cleartextBool);
        FHE.checkSignatures(handles, cleartextMemory, decryptionProof);

        _pendingDisclosures[hash] = ebool.wrap(0);
        _disclosed[hash] = true;

        emit UserOperationDisclosed(msg.sender, hash, valid, cleartextBool);
    }

    /**
     * @dev Returns whether the decryption proof is valid and the multisig validation passed.
     *
     * The signature must be encoded as:
     *
     * `encryptedBool (32 bytes) || decryptionProofOffset (32 bytes) || decryptionProofLength (32 bytes) || decryptionProof (variable)`
     *
     * NOTE: The cleartext value is expected to be `true` for valid multisigs. Invalid
     * multisigs should not have disclosure requests made.
     */
    function _rawERC7579Validation(
        address /* account */,
        bytes32 hash,
        bytes calldata /* signature */
    ) internal view virtual override returns (bool) {
        return _disclosed[hash];
    }
}
