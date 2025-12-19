// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OpenAccount} from "../OpenAccount.sol";
import {IERC7579Validator, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Packing} from "@openzeppelin/contracts/utils/Packing.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";

/**
 * @dev Extension of `OpenAccount` that implements atomic module installation and usage through
 * _enable mode_.
 *
 * This extension allows installing and using one or more modules within the same user operation
 * by detecting a magic nonce prefix (`0x01`) and decoding module installation data from the
 * signature field. The account owner authorizes module installations through EIP-712 signatures.
 *
 * This pattern is particularly useful for session keys and other modules that need to be
 * installed and immediately used, improving user experience by reducing user operation count.
 * Multiple modules can be installed atomically in a single operation.
 */
abstract contract OpenAccountEnableMode is OpenAccount {
    using Packing for *;

    bytes1 private constant ENABLE_MODE_PREFIX = 0x01;
    bytes32 private constant ENABLE_MODULES_TYPEHASH =
        keccak256("EnableModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)");

    /**
     * @dev Validates a user operation, checking for enable mode pattern.
     *
     * If the nonce starts with the enable mode prefix (`0x01`), attempts to decode and install
     * a module from the signature before proceeding with normal validation. If prefixed, it:
     *
     * 1. Decodes module installation data from the signature
     * 2. Validates the EIP-712 signature for module installation
     * 3. Installs the module if validation succeeds
     * 4. Continues with normal user operation validation using the installed module
     *
     * Otherwise, falls back to OpenAccount's `_validateUserOp` function.
     * See `_validateEnableMode` for the validation of enable mode installation.
     *
     * NOTE: When enable mode is used, if successful and the module obtained with {_extractUserOpValidator}
     * is installed, this function doesn't call `super._validateUserOp`.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal virtual override returns (uint256) {
        if (bytes32(userOp.nonce).extract_32_1(0) != ENABLE_MODE_PREFIX)
            return super._validateUserOp(userOp, userOpHash, signature);

        (uint256 validationData, bytes calldata innerSignature) = _validateEnableMode(signature, userOp.nonce);
        if (validationData == ERC4337Utils.SIG_VALIDATION_FAILED) {
            return super._validateUserOp(userOp, userOpHash, signature);
        }
        address module = _extractUserOpValidator(userOp);
        if (!isModuleInstalled(MODULE_TYPE_VALIDATOR, module, Calldata.emptyBytes())) {
            return super._validateUserOp(userOp, userOpHash, signature);
        }
        PackedUserOperation memory userOpMemory = userOp;
        userOpMemory.signature = innerSignature;
        return IERC7579Validator(module).validateUserOp(userOpMemory, _signableUserOpHash(userOp, userOpHash));
    }

    /**
     * @dev Extracts the nonce validator from the user operation. Note
     * that the first non-zero byte is the enable mode prefix.
     *
     * To construct a nonce key, set nonce as follows:
     *
     * ```
     * <enable mode prefix (1 byte)> | <module address (20 bytes)> | <key (3 bytes)> | <nonce (8 bytes)>
     * ```
     */
    function _extractUserOpValidator(
        PackedUserOperation calldata userOp
    ) internal pure virtual override returns (address) {
        return address(bytes32(userOp.nonce).extract_32_20(1));
    }

    /**
     * @dev Validates and installs a module in enable mode during user operation validation.
     *
     * Decodes module installation data from the user operation signature, validates the
     * EIP-712 signature for module installation authorization, and installs the module
     * if validation succeeds.
     *
     * See `_tryDecodeInstallModules` for the signature format.
     */
    function _validateEnableMode(
        bytes calldata signature,
        uint256 nonce
    ) internal virtual returns (uint256, bytes calldata) {
        (
            bool success,
            uint256[] calldata moduleTypeIds,
            address[] calldata modules,
            bytes[] calldata initDatas,
            bytes calldata installationSignature,
            bytes calldata userOpSignature
        ) = _tryDecodeInstallModules(signature);

        if (!success) {
            return (ERC4337Utils.SIG_VALIDATION_FAILED, signature);
        }

        bytes32 structHash = _installModulesStructHash(moduleTypeIds, modules, initDatas, nonce);
        if (
            isValidSignature(_hashTypedDataV4(structHash), installationSignature) == IERC1271.isValidSignature.selector
        ) {
            // Install all modules
            for (uint256 i = 0; i < modules.length; i++) {
                _installModule(moduleTypeIds[i], modules[i], initDatas[i]);
            }
            return (ERC4337Utils.SIG_VALIDATION_SUCCESS, userOpSignature);
        }

        return (ERC4337Utils.SIG_VALIDATION_FAILED, signature);
    }

    /**
     * @dev Computes the struct hash for the EnableModules EIP-712 message.
     *
     * The struct hash is used as part of the EIP-712 signature verification process
     * to ensure the module installations are properly authorized by the account owner.
     */
    function _installModulesStructHash(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        uint256 nonce
    ) internal pure virtual returns (bytes32) {
        // Hash each initData element
        bytes32[] memory initDataHashes = new bytes32[](initDatas.length);
        for (uint256 i = 0; i < initDatas.length; i++) {
            initDataHashes[i] = keccak256(initDatas[i]);
        }

        return
            keccak256(
                abi.encode(
                    ENABLE_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            );
    }

    /**
     * @dev Attempts to decode module installation data from a signature.
     *
     * Uses calldata slicing to avoid memory allocation. Performs bounds checking
     * to ensure safe access to the signature data without reverting.
     *
     * The signature format for _enable mode_ module installation is:
     * `abi.encode(moduleTypeIds, modules, initDatas, installationSignature, userOpSignature)`
     *
     * Where:
     *
     * * `installationSignature` is an EIP-712 signature over the EnableModules struct
     * * `userOpSignature` is the signature for validating the user operation itself
     */
    function _tryDecodeInstallModules(
        bytes calldata signature
    )
        private
        pure
        returns (
            bool success,
            uint256[] calldata moduleTypeIds,
            address[] calldata modules,
            bytes[] calldata initDatas,
            bytes calldata installationSignature,
            bytes calldata userOpSignature
        )
    {
        // Minimum length to hold 5 offset pointers: 5 * 32 = 160 bytes (0xa0)
        if (signature.length < 0xa0) {
            return _emptyDecodeInstallModules();
        }

        uint256 moduleTypeIdsOffset = uint256(bytes32(signature[0x00:0x20]));
        uint256 modulesOffset = uint256(bytes32(signature[0x20:0x40]));
        uint256 initDatasOffset = uint256(bytes32(signature[0x40:0x60]));
        uint256 installationSignatureOffset = uint256(bytes32(signature[0x60:0x80]));
        uint256 userOpSignatureOffset = uint256(bytes32(signature[0x80:0xa0]));

        // Check all offsets are within bounds (need at least 32 bytes for length)
        if (
            signature.length < moduleTypeIdsOffset + 0x20 ||
            moduleTypeIdsOffset < 0xa0 ||
            signature.length < modulesOffset + 0x20 ||
            modulesOffset < 0xa0 ||
            signature.length < initDatasOffset + 0x20 ||
            initDatasOffset < 0xa0 ||
            signature.length < installationSignatureOffset + 0x20 ||
            installationSignatureOffset < 0xa0 ||
            signature.length < userOpSignatureOffset + 0x20 ||
            userOpSignatureOffset < 0xa0
        ) {
            return _emptyDecodeInstallModules();
        }

        // Get array lengths
        uint256 moduleTypeIdsLength = uint256(bytes32(signature[moduleTypeIdsOffset:moduleTypeIdsOffset + 0x20]));
        uint256 modulesLength = uint256(bytes32(signature[modulesOffset:modulesOffset + 0x20]));
        uint256 initDatasLength = uint256(bytes32(signature[initDatasOffset:initDatasOffset + 0x20]));

        if (moduleTypeIdsLength != modulesLength || modulesLength != initDatasLength) {
            return _emptyDecodeInstallModules();
        }

        // Check bounds for fixed-size arrays (uint256[] and address[])
        if (
            signature.length < moduleTypeIdsOffset + 0x20 + moduleTypeIdsLength * 0x20 ||
            signature.length < modulesOffset + 0x20 + modulesLength * 0x20
        ) {
            return _emptyDecodeInstallModules();
        }

        // Extract arrays directly from calldata
        assembly ("memory-safe") {
            moduleTypeIds.offset := add(signature.offset, add(moduleTypeIdsOffset, 0x20))
            moduleTypeIds.length := moduleTypeIdsLength // Length in elements
            modules.offset := add(signature.offset, add(modulesOffset, 0x20))
            modules.length := modulesLength // Length in elements
        }

        initDatas = _extractBytesArray(signature, initDatasOffset, initDatasLength);
        if (initDatas.length == 0 && initDatasLength > 0) {
            return _emptyDecodeInstallModules();
        }

        // Get lengths of the signature data
        uint256 installationSignatureLength = uint256(
            bytes32(signature[installationSignatureOffset:installationSignatureOffset + 0x20])
        );
        uint256 userOpSignatureLength = uint256(bytes32(signature[userOpSignatureOffset:userOpSignatureOffset + 0x20]));

        // Check bounds for signature data
        if (
            installationSignatureLength > signature.length ||
            userOpSignatureLength > signature.length ||
            signature.length < installationSignatureOffset + 0x20 + installationSignatureLength ||
            signature.length < userOpSignatureOffset + 0x20 + userOpSignatureLength
        ) {
            return _emptyDecodeInstallModules();
        }

        // Extract signature data (skip the 32-byte length prefix)
        installationSignature = signature[
            installationSignatureOffset + 0x20:installationSignatureOffset + 0x20 + installationSignatureLength
        ];
        userOpSignature = signature[userOpSignatureOffset + 0x20:userOpSignatureOffset + 0x20 + userOpSignatureLength];

        return (true, moduleTypeIds, modules, initDatas, installationSignature, userOpSignature);
    }

    /**
     * @dev Validates and determines the end offset of a bytes[] array structure.
     *
     * This function checks that:
     * 1. The array length is within bounds
     * 2. All offset pointers are valid
     * 3. All individual bytes elements are within bounds
     */
    function _extractBytesArray(
        bytes calldata data,
        uint256 arrayOffset,
        uint256 arrayLength
    ) private pure returns (bytes[] calldata result) {
        // Start after the array length (32 bytes)
        uint256 currentOffset = arrayOffset + 0x20;

        // Check if we have enough space for all offset pointers (arrayLength * 32 bytes)
        if (data.length < currentOffset + arrayLength * 0x20) return _emptyBytesArray();

        // Track the maximum end position we've seen
        uint256 maxEndOffset = currentOffset + arrayLength * 0x20;

        // Validate each bytes element
        for (uint256 i = 0; i < arrayLength; (i++, currentOffset += 0x20)) {
            // Get the offset for this bytes element
            uint256 elementOffset = uint256(bytes32(data[currentOffset:currentOffset + 0x20]));

            // Check if the element offset is within bounds (need at least 32 bytes for length)
            if (data.length < elementOffset + 0x20) return _emptyBytesArray();

            // Get the length of this bytes element
            uint256 elementLength = uint256(bytes32(data[elementOffset:elementOffset + 0x20]));

            // Check if the element data is within bounds
            uint256 elementEnd = elementOffset + 0x20 + elementLength;
            if (data.length < elementEnd) return _emptyBytesArray();

            // Update max end offset
            if (elementEnd > maxEndOffset) maxEndOffset = elementEnd;
        }

        // Extract bytes array directly from calldata
        assembly ("memory-safe") {
            result.offset := add(data.offset, add(arrayOffset, 0x20))
            result.length := arrayLength
        }

        return result;
    }

    /// @dev Returns empty arrays for module type ids, modules, init datas, installation signature, and user operation signature.
    function _emptyDecodeInstallModules()
        private
        pure
        returns (
            bool success,
            uint256[] calldata moduleTypeIds,
            address[] calldata modules,
            bytes[] calldata initDatas,
            bytes calldata installationSignature,
            bytes calldata userOpSignature
        )
    {
        return (
            false,
            _emptyUint256Array(),
            _emptyAddressArray(),
            _emptyBytesArray(),
            Calldata.emptyBytes(),
            Calldata.emptyBytes()
        );
    }

    /// @dev Returns empty bytes array.
    function _emptyBytesArray() private pure returns (bytes[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }

    /// @dev Returns empty address array.
    function _emptyAddressArray() private pure returns (address[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }

    /// @dev Returns empty uint256 array.
    function _emptyUint256Array() private pure returns (uint256[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }
}
