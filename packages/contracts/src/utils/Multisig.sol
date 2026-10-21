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
     * > [!NOTE]
     * > This function does not validate the returned signers and signatures have the same length.
     */
    function tryDecodeMultisignatureCalldata(
        bytes calldata multisignature
    ) internal pure returns (bool success, bytes[] calldata signingSigners, bytes[] calldata signatures) {
        unchecked {
            uint256 bufferLength = multisignature.length;

            // Check #1: Theoretical minimum length of a valid multisignature encoding is 0x40 bytes.
            // 64 bytes of zero is a valid encoding for two empty arrays.
            if (bufferLength < 0x40) return (false, _emptyBytesArray(), _emptyBytesArray());

            // Read the offset pointers to the signers and signatures arrays
            // Read is done in assembly to avoid the cost of creating calldata slices.
            uint256 signersOffset;
            uint256 signaturesOffset;
            assembly ("memory-safe") {
                signersOffset := calldataload(multisignature.offset)
                signaturesOffset := calldataload(add(multisignature.offset, 0x20))
            }

            // Check #2: The length fields that the offset pointers point to must be within the bounds of the buffer.
            if (signersOffset > bufferLength - 0x20 || signaturesOffset > bufferLength - 0x20)
                return (false, _emptyBytesArray(), _emptyBytesArray());

            // Read the length fields
            // Read is done in assembly to avoid the cost of creating calldata slices.
            uint256 signersLength;
            uint256 signaturesLength;
            assembly ("memory-safe") {
                signersLength := calldataload(add(multisignature.offset, signersOffset))
                signaturesLength := calldataload(add(multisignature.offset, signaturesOffset))
            }

            // Data is just after the length fields
            uint256 signersDataOffset = signersOffset + 0x20;
            uint256 signaturesDataOffset = signaturesOffset + 0x20;

            // Check #3 & #4:
            // - Cap lengths at 2**64-1 (Solidity's own dynamic-array limit) so `length * 0x20` cannot overflow.
            // - The data for each array must fit within the bounds of the buffer.
            if (
                signersLength > type(uint64).max ||
                signaturesLength > type(uint64).max ||
                0x20 * signersLength > bufferLength - signersDataOffset ||
                0x20 * signaturesLength > bufferLength - signaturesDataOffset
            ) return (false, _emptyBytesArray(), _emptyBytesArray());

            // Assembly cast
            assembly ("memory-safe") {
                success := 1 // true
                signingSigners.offset := add(multisignature.offset, signersDataOffset)
                signingSigners.length := signersLength
                signatures.offset := add(multisignature.offset, signaturesDataOffset)
                signatures.length := signaturesLength
            }
        }
    }

    /**
     * @dev Same as {tryDecodeMultisignatureCalldata}, but reverts if the multisignature is invalid.
     *
     * Requirements:
     *
     * * The `multisignature` must be at least 64 bytes long to contain the two offset words.
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
