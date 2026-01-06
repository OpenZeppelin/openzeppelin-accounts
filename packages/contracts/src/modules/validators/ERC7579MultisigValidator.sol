// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579Multisig} from "../ERC7579Multisig.sol";

/**
 * @dev Implementation of {ERC7579Validator} that uses {ERC7579Multisig} for multisignature validation.
 */
contract ERC7579MultisigValidator is ERC7579Multisig, ERC7579Validator {
    /// @dev The signature format for the signature provided to `_rawERC7579Validation` is invalid.
    error ERC7579MultisigInvalidMultisignature();

    /**
     * @dev Returns whether the number of valid signatures meets or exceeds the
     * threshold set for the target account.
     *
     * See {_decodeValidationSignature} for the encoding details.
     *
     * Where `signingSigners` are the authorized signers and signatures are their corresponding
     * signatures of the operation `hash`.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bytes[] calldata signingSigners, bytes[] calldata signatures) = _decodeValidationSignature(signature);
        return _validateMultisig(account, hash, signingSigners, signatures);
    }

    /**
     * @dev Decodes validation signature data from calldata without memory allocation.
     *
     * The signature should be encoded as:
     * `abi.encode(bytes[] signingSigners, bytes[] signatures)`
     *
     * Where `signingSigners` are the authorized signers and `signatures` are their corresponding
     * signatures of the operation hash. This function is equivalent to
     * `abi.decode(signature, (bytes[], bytes[]))` but operates directly on calldata to avoid
     * memory allocation, improving gas efficiency during signature validation.
     *
     * Requirements:
     *
     * * The `signature` must be at least 128 bytes long to contain the minimum ABI-encoded structure.
     * * Both array offsets must be properly aligned and within bounds.
     * * Both array length fields must be accessible within the provided data.
     * * The arrays should have the same length for proper signature validation.
     */
    function _decodeValidationSignature(
        bytes calldata signature
    ) internal pure virtual returns (bytes[] calldata signingSigners, bytes[] calldata signatures) {
        // Minimum length: offset1(32) + offset2(32) + array1_length(32) + array2_length(32) = 128 bytes
        require(signature.length > 0x7f, ERC7579MultisigInvalidMultisignature());

        // Get offset to the first array (signingSigners)
        uint256 signersOffset = uint256(bytes32(signature[:0x20]));

        // Get offset to the second array (signatures)
        uint256 signaturesOffset = uint256(bytes32(signature[0x20:0x40]));

        // Validate offsets are within bounds and properly aligned
        require(
            signersOffset > 0x3f &&
                signersOffset + 0x1f < signature.length &&
                signaturesOffset > 0x3f &&
                signaturesOffset + 0x1f < signature.length,
            ERC7579MultisigInvalidMultisignature()
        );

        // Get the signers array length
        uint256 signersLength = uint256(bytes32(signature[signersOffset:signersOffset + 0x20]));

        // Get the signatures array length
        uint256 signaturesLength = uint256(bytes32(signature[signaturesOffset:signaturesOffset + 0x20]));

        // The array data starts after the length field
        uint256 signersDataOffset = signersOffset + 0x20;
        uint256 signaturesDataOffset = signaturesOffset + 0x20;

        // Validate data offsets are within bounds
        require(
            signersDataOffset <= signature.length && signaturesDataOffset <= signature.length,
            ERC7579MultisigInvalidMultisignature()
        );

        // Set up the calldata slices for both arrays
        assembly ("memory-safe") {
            signingSigners.offset := add(signature.offset, signersDataOffset)
            signingSigners.length := signersLength
            signatures.offset := add(signature.offset, signaturesDataOffset)
            signatures.length := signaturesLength
        }

        return (signingSigners, signatures);
    }
}
