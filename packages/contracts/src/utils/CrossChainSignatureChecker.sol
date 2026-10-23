// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Memory} from "@openzeppelin/contracts/utils/Memory.sol";

/**
 * @dev Crosschain signature verification helper for ERC-7964 compliant signatures.
 *
 * [ERC-7964](https://eips.ethereum.org/EIPS/eip-7964) enables a single signature to
 * be valid across multiple chains by omitting the `chainId` from the EIP-712 domain
 * and encoding chain-specific operations as an array of struct hashes. This helper
 * provides functions to parse and verify such crosschain signatures.
 *
 * The signature encoding includes metadata that allows contracts to:
 * * Detect crosschain signatures via a magic prefix
 * * Identify which operation in the array corresponds to the current chain
 * * Reconstruct the full EIP-712 hash for verification
 * * Validate the signature using standard ECDSA or ERC-1271
 */
library CrossChainSignatureChecker {
    using Memory for *;
    using MessageHashUtils for *;
    using SignatureChecker for address;

    bytes10 internal constant ERC7964_MAGIC = 0x79647964796479647964;

    /**
     * @dev Verifies an ERC-7964 crosschain signature for a given `signer`, `hash` and `erc7964Signature`.
     * Uses the provided `structHash` function to compute the main struct hash from the array of
     * chain-specific struct hashes.
     *
     * The `chainFields` argument is the ERC-5267 bitmap of the EIP-712 domain fields bound in each chain-specific
     * struct (e.g. `0x0c` for an `EIP712ChainDomain(uint256 chainId,address verifyingContract)`). It must include
     * the `chainId` bit (`0x04`).
     *
     * This function:
     *
     * 1. Parses the ERC-7964 signature encoding to extract metadata
     * 2. Verifies that the provided `hash` matches the struct at `structIndex` in the array
     * 3. Queries the application contract for EIP-712 domain information
     * 4. Builds the main domain from the application fields that are not in `chainFields`
     * 5. Reconstructs the full typed hash using the main domain and array of struct hashes
     * 6. Validates the signature against the reconstructed hash
     *
     * > [!NOTE]
     * > Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * > change through time. It could return true at block N and false at block N+1 (or the opposite).
     *
     * Returns false if the signature is malformed, if `structIndex` is out of bounds, or if the main domain fields
     * set any bit beyond the ones defined in ERC-5267.
     *
     * > [!IMPORTANT]
     * > Make sure the `structHash` function pointer manages memory correctly. Otherwise,
     * > this function may behave unexpectedly.
     *
     * Requirements:
     *
     * * The `application` encoded in `erc7964Signature` must implement {IERC5267-eip712Domain}.
     */
    function isValidCrossChainSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory erc7964Signature,
        bytes1 chainFields,
        function(bytes32) internal view returns (bytes32) structHash
    ) internal view returns (bool) {
        (
            address application,
            bytes memory crossChainSignature,
            bytes32 structHash_
        ) = _tryParseCrosschainSignatureForValidation(hash, erc7964Signature, structHash);
        bytes32 typedHash = structHash_ == bytes32(0)
            ? bytes32(0)
            : _tryToTypedDataHash(application, chainFields, structHash_);
        return typedHash != bytes32(0) && signer.isValidSignatureNow(typedHash, crossChainSignature);
    }

    /// @dev Variant of {isValidCrossChainSignatureNow} that takes the signature in calldata.
    function isValidCrossChainSignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata erc7964Signature,
        bytes1 chainFields,
        function(bytes32) internal view returns (bytes32) structHash
    ) internal view returns (bool) {
        (
            address application,
            bytes calldata crossChainSignature,
            bytes32 structHash_
        ) = _tryParseCrosschainSignatureForValidationCalldata(hash, erc7964Signature, structHash);
        bytes32 typedHash = structHash_ == bytes32(0)
            ? bytes32(0)
            : _tryToTypedDataHash(application, chainFields, structHash_);
        return typedHash != bytes32(0) && signer.isValidSignatureNowCalldata(typedHash, crossChainSignature);
    }

    /**
     * @dev Parses an ERC-7964 encoded crosschain signature into its components:
     *
     * * `structIndex` The index of the current chain's operation in the array
     * * `application` The address of the contract providing EIP-712 domain info
     * * `structsArray` The array of struct hashes for all chains
     * * `crossChainSignature` The actual signature bytes
     *
     * If the magic value is incorrect or the signature is malformed, all the return values are empty.
     */
    function tryParseCrossChainSignature(
        bytes memory erc7964Signature
    )
        internal
        pure
        returns (
            uint16 structIndex,
            address application,
            bytes32[] memory structsArray,
            bytes memory crossChainSignature
        )
    {
        Memory.Slice erc7964SignatureSlice = erc7964Signature.asSlice();
        // magic (10 bytes) + structIndex (2 bytes) + application (20 bytes) + structsArrayOffset (32 bytes) +
        // structsArrayLength (32 bytes) + crossChainSignatureOffset (32 bytes) + crossChainSignatureLength (32 bytes)
        if (erc7964Signature.length < 0xa0 || bytes10(erc7964SignatureSlice.load(0)) != ERC7964_MAGIC) {
            return (0, address(0), new bytes32[](0), new bytes(0));
        }
        structIndex = uint16(bytes2(erc7964SignatureSlice.load(10)));
        application = address(bytes20(erc7964SignatureSlice.load(12)));

        // Offsets and lengths are arbitrary values, so each bound is checked before it is used to avoid overflows
        uint256 structsArrayOffset = uint256(bytes32(erc7964SignatureSlice.load(0x20)));
        if (structsArrayOffset < 0x60 || structsArrayOffset > erc7964Signature.length - 32) {
            return (0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 structsArrayDataOffset = structsArrayOffset + 32;
        uint256 structsArrayLength = uint256(erc7964SignatureSlice.slice(structsArrayOffset).load(0));
        if (structsArrayLength > (erc7964Signature.length - structsArrayDataOffset) / 32) {
            return (0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 crossChainSignatureOffset = uint256(bytes32(erc7964SignatureSlice.load(0x40)));
        if (
            crossChainSignatureOffset < structsArrayDataOffset + structsArrayLength * 32 ||
            crossChainSignatureOffset > erc7964Signature.length - 32
        ) {
            return (0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 crossChainSignatureDataOffset = crossChainSignatureOffset + 32;
        uint256 crossChainSignatureLength = uint256(erc7964SignatureSlice.slice(crossChainSignatureOffset).load(0));
        if (crossChainSignatureLength > erc7964Signature.length - crossChainSignatureDataOffset) {
            return (0, address(0), new bytes32[](0), new bytes(0));
        }

        assembly ("memory-safe") {
            structsArray := add(erc7964Signature, structsArrayDataOffset)
            crossChainSignature := add(erc7964Signature, crossChainSignatureDataOffset)
        }

        return (structIndex, application, structsArray, crossChainSignature);
    }

    /// @dev Variant of {tryParseCrossChainSignature} that takes the signature in calldata.
    function tryParseCrossChainSignatureCalldata(
        bytes calldata erc7964Signature
    )
        internal
        pure
        returns (
            uint16 structIndex,
            address application,
            bytes32[] calldata structsArray,
            bytes calldata crossChainSignature
        )
    {
        // magic (10 bytes) + structIndex (2 bytes) + application (20 bytes) + structsArrayOffset (32 bytes) +
        // structsArrayLength (32 bytes) + crossChainSignatureOffset (32 bytes) + crossChainSignatureLength (32 bytes)
        if (erc7964Signature.length < 0xa0 || bytes10(erc7964Signature[0:10]) != ERC7964_MAGIC) {
            return (0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        structIndex = uint16(bytes2(erc7964Signature[10:]));
        application = address(bytes20(erc7964Signature[12:]));

        // Offsets and lengths are arbitrary values, so each bound is checked before it is used to avoid overflows
        uint256 structsArrayOffset = uint256(bytes32(erc7964Signature[0x20:]));
        if (structsArrayOffset < 0x60 || structsArrayOffset > erc7964Signature.length - 32) {
            return (0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 structsArrayDataOffset = structsArrayOffset + 32;
        uint256 structsArrayLength = uint256(bytes32(erc7964Signature[structsArrayOffset:]));
        if (structsArrayLength > (erc7964Signature.length - structsArrayDataOffset) / 32) {
            return (0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 crossChainSignatureOffset = uint256(bytes32(erc7964Signature[0x40:]));
        if (
            crossChainSignatureOffset < structsArrayDataOffset + structsArrayLength * 32 ||
            crossChainSignatureOffset > erc7964Signature.length - 32
        ) {
            return (0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 crossChainSignatureDataOffset = crossChainSignatureOffset + 32;
        uint256 crossChainSignatureLength = uint256(bytes32(erc7964Signature[crossChainSignatureOffset:]));
        if (crossChainSignatureLength > erc7964Signature.length - crossChainSignatureDataOffset) {
            return (0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }

        assembly ("memory-safe") {
            structsArray.offset := add(erc7964Signature.offset, structsArrayDataOffset)
            structsArray.length := structsArrayLength
        }
        crossChainSignature = erc7964Signature[
            crossChainSignatureDataOffset:crossChainSignatureDataOffset + crossChainSignatureLength
        ];
        return (structIndex, application, structsArray, crossChainSignature);
    }

    function _tryParseCrosschainSignatureForValidation(
        bytes32 hash,
        bytes memory erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    ) private view returns (address application, bytes memory crossChainSignature, bytes32 structHash_) {
        uint16 structIndex;
        bytes32[] memory structsArray;
        (structIndex, application, structsArray, crossChainSignature) = tryParseCrossChainSignature(erc7964Signature);
        if (crossChainSignature.length == 0 || structIndex >= structsArray.length || structsArray[structIndex] != hash)
            return (address(0), new bytes(0), 0);
        structHash_ = structHash(keccak256(abi.encodePacked(structsArray)));
    }

    function _tryParseCrosschainSignatureForValidationCalldata(
        bytes32 hash,
        bytes calldata erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    ) private view returns (address application, bytes calldata crossChainSignature, bytes32 structHash_) {
        uint16 structIndex;
        bytes32[] calldata structsArray;
        (structIndex, application, structsArray, crossChainSignature) = tryParseCrossChainSignatureCalldata(
            erc7964Signature
        );
        if (crossChainSignature.length == 0 || structIndex >= structsArray.length || structsArray[structIndex] != hash)
            return (address(0), Calldata.emptyBytes(), 0);
        structHash_ = structHash(keccak256(abi.encodePacked(structsArray)));
    }

    /// @dev Returns the typed data hash of `structHash_` under the main domain, or 0 if the main domain fields are unsupported.
    function _tryToTypedDataHash(
        address application,
        bytes1 chainFields,
        bytes32 structHash_
    ) private view returns (bytes32) {
        (
            bytes1 applicationFields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 domainSalt,

        ) = IERC5267(application).eip712Domain();
        bytes1 fields = applicationFields & ~chainFields;
        if (uint8(fields) > 0x1f) return bytes32(0);
        return
            fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt).toTypedDataHash(
                structHash_
            );
    }

    function _empty32BytesArrayCalldata() private pure returns (bytes32[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }
}
