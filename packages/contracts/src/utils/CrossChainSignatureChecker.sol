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
 * https://eips.ethereum.org/EIPS/eip-7964[ERC-7964] enables a single signature to
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

    bytes9 internal constant ERC7964_MAGIC = 0x796479647964796479;

    /**
     * @dev Verifies an ERC-7964 crosschain signature for a given `signer`, `hash` and `erc7964Signature`.
     * Uses the provided `structHash` function to compute the main struct hash from the array of
     * chain-specific struct hashes.
     *
     * This function:
     *
     * 1. Parses the ERC-7964 signature encoding to extract metadata
     * 2. Verifies that the provided `hash` matches the struct at `structIndex` in the array
     * 3. Queries the application contract for EIP-712 domain information
     * 4. Reconstructs the full typed hash using the domain and array of struct hashes
     * 5. Validates the signature against the reconstructed hash
     *
     * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * change through time. It could return true at block N and false at block N+1 (or the opposite).
     *
     * IMPORTANT: Make sure the `structHash` function pointer manages memory correctly. Otherwise,
     * this function may behave unexpectedly.
     */
    function isValidCrossChainSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    ) internal view returns (bool) {
        (
            bytes1 fields,
            address application,
            bytes memory crossChainSignature,
            bytes32 structHash_
        ) = _tryParseCrosschainSignatureForValidation(hash, erc7964Signature, structHash);
        if (structHash_ == bytes32(0)) return false;

        return
            signer.isValidSignatureNow(
                _fetchDomainSeparator(application, fields).toTypedDataHash(structHash_),
                crossChainSignature
            );
    }

    /// @dev Variant of {isValidCrossChainSignatureNow} that takes the signature in calldata.
    function isValidCrossChainSignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    ) internal view returns (bool) {
        (
            bytes1 fields,
            address application,
            bytes calldata crossChainSignature,
            bytes32 structHash_
        ) = _tryParseCrosschainSignatureForValidationCalldata(hash, erc7964Signature, structHash);
        if (structHash_ == bytes32(0)) return false;

        return
            signer.isValidSignatureNowCalldata(
                _fetchDomainSeparator(application, fields).toTypedDataHash(structHash_),
                crossChainSignature
            );
    }

    /**
     * @dev Parses an ERC-7964 encoded crosschain signature into its components:
     *
     * * `success` True if parsing succeeded, false if the signature is malformed or the magic value is incorrect
     * * `fields` The EIP-712 domain fields byte from ERC-5267
     * * `structIndex` The index of the current chain's operation in the array
     * * `application` The address of the contract providing EIP-712 domain info
     * * `structsArray` The array of struct hashes for all chains
     * * `crossChainSignature` The actual signature bytes
     */
    function tryParseCrossChainSignature(
        bytes memory erc7964Signature
    )
        internal
        pure
        returns (
            bytes1 fields,
            uint16 structIndex,
            address application,
            bytes32[] memory structsArray,
            bytes memory crossChainSignature
        )
    {
        Memory.Slice erc7964SignatureSlice = erc7964Signature.asSlice();
        // magic (9 bytes) + fields (1 byte) + structIndex (2 bytes) + application (20 bytes) + structsArrayOffset (32 bytes) +
        // structsArrayLength (32 bytes) + crossChainSignatureOffset (32 bytes) + crossChainSignatureLength (32 bytes)
        if (erc7964Signature.length < 0xa0 || bytes9(erc7964SignatureSlice.load(0)) != ERC7964_MAGIC) {
            return (0, 0, address(0), new bytes32[](0), new bytes(0));
        }
        fields = bytes1(erc7964SignatureSlice.load(9));
        structIndex = uint16(bytes2(erc7964SignatureSlice.load(10)));
        application = address(bytes20(erc7964SignatureSlice.load(12)));

        uint256 structsArrayOffset = uint256(bytes32(erc7964SignatureSlice.load(0x20)));
        uint256 structsArrayDataOffset = structsArrayOffset + 32;
        if (structsArrayOffset < 0x60 || structsArrayDataOffset > erc7964Signature.length) {
            return (0, 0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 structsArrayLength = uint256(erc7964SignatureSlice.slice(structsArrayOffset).load(0));
        if (structsArrayDataOffset + structsArrayLength * 32 > erc7964Signature.length) {
            return (0, 0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 crossChainSignatureOffset = uint256(bytes32(erc7964SignatureSlice.load(0x40)));
        uint256 crossChainSignatureDataOffset = crossChainSignatureOffset + 32;
        if (
            crossChainSignatureOffset < structsArrayDataOffset + structsArrayLength * 32 ||
            crossChainSignatureDataOffset > erc7964Signature.length
        ) {
            return (0, 0, address(0), new bytes32[](0), new bytes(0));
        }
        uint256 crossChainSignatureLength = uint256(erc7964SignatureSlice.slice(crossChainSignatureOffset).load(0));
        if (crossChainSignatureDataOffset + crossChainSignatureLength > erc7964Signature.length) {
            return (0, 0, address(0), new bytes32[](0), new bytes(0));
        }

        assembly ("memory-safe") {
            structsArray := add(erc7964Signature, structsArrayDataOffset)
            crossChainSignature := add(erc7964Signature, crossChainSignatureDataOffset)
        }

        return (fields, structIndex, application, structsArray, crossChainSignature);
    }

    /// @dev Variant of {parseCrossChainSignature} that takes the signature in calldata.
    function tryParseCrossChainSignatureCalldata(
        bytes calldata erc7964Signature
    )
        internal
        pure
        returns (
            bytes1 fields,
            uint16 structIndex,
            address application,
            bytes32[] calldata structsArray,
            bytes calldata crossChainSignature
        )
    {
        // magic (9 bytes) + fields (1 byte) + structIndex (2 bytes) + application (20 bytes) + structsArrayOffset (32 bytes) +
        // structsArrayLength (32 bytes) + crossChainSignatureOffset (32 bytes) + crossChainSignatureLength (32 bytes)
        if (erc7964Signature.length < 0xa0 || bytes9(erc7964Signature[0:9]) != ERC7964_MAGIC) {
            return (0, 0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        fields = erc7964Signature[9];
        structIndex = uint16(bytes2(erc7964Signature[10:]));
        application = address(bytes20(erc7964Signature[12:]));

        uint256 structsArrayOffset = uint256(bytes32(erc7964Signature[0x20:]));
        uint256 structsArrayDataOffset = structsArrayOffset + 32;
        if (structsArrayOffset < 0x60 || structsArrayDataOffset > erc7964Signature.length) {
            return (0, 0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 structsArrayLength = uint256(bytes32(erc7964Signature[structsArrayOffset:]));
        if (structsArrayDataOffset + structsArrayLength * 32 > erc7964Signature.length) {
            return (0, 0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 crossChainSignatureOffset = uint256(bytes32(erc7964Signature[0x40:]));
        uint256 crossChainSignatureDataOffset = crossChainSignatureOffset + 32;
        if (
            crossChainSignatureOffset < structsArrayDataOffset + structsArrayLength * 32 ||
            crossChainSignatureDataOffset > erc7964Signature.length
        ) {
            return (0, 0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }
        uint256 crossChainSignatureLength = uint256(bytes32(erc7964Signature[crossChainSignatureOffset:]));
        if (crossChainSignatureDataOffset + crossChainSignatureLength > erc7964Signature.length) {
            return (0, 0, address(0), _empty32BytesArrayCalldata(), Calldata.emptyBytes());
        }

        assembly ("memory-safe") {
            structsArray.offset := add(erc7964Signature.offset, structsArrayDataOffset)
            structsArray.length := structsArrayLength
        }
        crossChainSignature = erc7964Signature[
            crossChainSignatureDataOffset:crossChainSignatureDataOffset + crossChainSignatureLength
        ];
        return (fields, structIndex, application, structsArray, crossChainSignature);
    }

    function _tryParseCrosschainSignatureForValidation(
        bytes32 hash,
        bytes memory erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    ) private view returns (bytes1 fields, address application, bytes memory crossChainSignature, bytes32 structHash_) {
        uint16 structIndex;
        bytes32[] memory structsArray;
        (fields, structIndex, application, structsArray, crossChainSignature) = tryParseCrossChainSignature(
            erc7964Signature
        );
        if (crossChainSignature.length == 0 || structsArray[structIndex] != hash)
            return (0, address(0), new bytes(0), 0);
        structHash_ = structHash(keccak256(abi.encodePacked(structsArray)));
    }

    function _tryParseCrosschainSignatureForValidationCalldata(
        bytes32 hash,
        bytes calldata erc7964Signature,
        function(bytes32) internal view returns (bytes32) structHash
    )
        private
        view
        returns (bytes1 fields, address application, bytes calldata crossChainSignature, bytes32 structHash_)
    {
        uint16 structIndex;
        bytes32[] calldata structsArray;
        (fields, structIndex, application, structsArray, crossChainSignature) = tryParseCrossChainSignatureCalldata(
            erc7964Signature
        );
        if (crossChainSignature.length == 0 || structsArray[structIndex] != hash)
            return (0, address(0), Calldata.emptyBytes(), 0);
        structHash_ = structHash(keccak256(abi.encodePacked(structsArray)));
    }

    function _fetchDomainSeparator(address application, bytes1 fields) private view returns (bytes32) {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 domainSalt,

        ) = IERC5267(application).eip712Domain();
        return fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt);
    }

    function _empty32BytesArrayCalldata() private pure returns (bytes32[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }
}
