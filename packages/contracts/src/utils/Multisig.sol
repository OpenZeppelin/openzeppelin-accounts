// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @dev Utilities for multisignature operations.
 */
library Multisig {
    /// @dev The `multisignature` format is invalid.
    error MultisigInvalidFormat();

    /**
     * @dev Decodes a multisignature data from calldata without memory allocation.
     *
     * The multisignature should be encoded as:
     * `abi.encode(bytes[] signingSigners, bytes[] signatures)`
     *
     * Where `signingSigners` are the authorized signers and `signatures` are their corresponding
     * signatures of the operation hash. This function is equivalent to
     * `abi.decode(multisignature, (bytes[], bytes[]))` but operates directly on calldata to avoid
     * memory allocation, improving gas efficiency during multisignature validation.
     *
     * NOTE: This function does not validate the returned signers and signatures have the same length.
     */
    function tryDecodeMultisignatureCalldata(
        bytes calldata multisignature
    ) internal pure returns (bool success, bytes[] calldata signingSigners, bytes[] calldata signatures) {
        // Minimum length: offset1(32) + offset2(32) + array1_length(32) + array2_length(32) = 128 bytes
        if (multisignature.length < 0x80) {
            return (false, _emptyBytesArray(), _emptyBytesArray());
        }

        // Get offset to the first array (signingSigners)
        uint256 signersOffset = uint256(bytes32(multisignature[:0x20]));

        // Get offset to the second array (signatures)
        uint256 signaturesOffset = uint256(bytes32(multisignature[0x20:0x40]));

        // The array data starts after the length field
        uint256 signersDataOffset = signersOffset + 0x20;
        uint256 signaturesDataOffset = signaturesOffset + 0x20;

        // Validate offsets are within bounds and properly aligned
        if (
            signersOffset < 0x40 ||
            signersDataOffset > multisignature.length ||
            signaturesOffset < 0x40 ||
            signaturesDataOffset > multisignature.length
        ) {
            return (false, _emptyBytesArray(), _emptyBytesArray());
        }

        // Get the signers array length
        uint256 signersLength = uint256(bytes32(multisignature[signersOffset:signersDataOffset]));

        // Get the signatures array length
        uint256 signaturesLength = uint256(bytes32(multisignature[signaturesOffset:signaturesDataOffset]));

        // Validate array lengths are within bounds
        if (
            signersOffset + signersLength * 0x20 > multisignature.length ||
            signaturesOffset + signaturesLength * 0x20 > multisignature.length
        ) {
            return (false, _emptyBytesArray(), _emptyBytesArray());
        }

        // Set up the calldata slices for both arrays
        assembly ("memory-safe") {
            signingSigners.offset := add(multisignature.offset, signersDataOffset)
            signingSigners.length := signersLength
            signatures.offset := add(multisignature.offset, signaturesDataOffset)
            signatures.length := signaturesLength
        }

        return (true, signingSigners, signatures);
    }

    /**
     * @dev Same as {tryDecodeMultisignatureCalldata}, but reverts if the multisignature is invalid.
     *
     * Requirements:
     *
     * * The `multisignature` must be at least 128 bytes long to contain the minimum ABI-encoded structure.
     * * Both array offsets must be properly aligned and within bounds.
     * * Both array length fields must be accessible within the provided data.
     * * The arrays should have the same length for proper signature validation.
     */
    function decodeMultisignatureCalldata(
        bytes calldata multisignature
    ) internal pure returns (bytes[] calldata signingSigners, bytes[] calldata signatures) {
        bool success;
        (success, signingSigners, signatures) = tryDecodeMultisignatureCalldata(multisignature);
        require(success, MultisigInvalidFormat());
        return (signingSigners, signatures);
    }

    /// @dev Returns empty bytes[] array.
    function _emptyBytesArray() private pure returns (bytes[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }
}
