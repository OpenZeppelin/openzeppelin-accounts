// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";

/**
 * @dev Utility functions for the [ERC-8043](https://eip.tools/eip/8043) init mode.
 *
 * Init mode allows an ERC-4337 user operation to install one or more ERC-7579 modules
 * atomically alongside its regular execution. It is triggered by prefixing the user
 * operation's `initCode` with {INIT_MODE_MAGIC_VALUE}; the remaining bytes carry an
 * ABI-encoded installation payload followed by an EIP-712 signature over the
 * {InitModules} struct authorizing the installation.
 */
library ERC8043Utils {
    /// @dev 4-byte prefix marking a user operation's `initCode` as an ERC-8043 init mode payload.
    bytes4 internal constant INIT_MODE_MAGIC_VALUE = 0x80438043;

    /// @dev EIP-712 type hash of the `InitModules` struct signed by the account owner.
    bytes32 internal constant INIT_MODULES_TYPEHASH =
        keccak256("InitModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)");

    /**
     * @dev Computes the EIP-712 struct hash of the `InitModules` message.
     *
     * ```
     * InitModules(uint256[] moduleTypeIds, address[] modules, bytes[] initDatas, uint256 nonce)
     * ```
     *
     * `nonce` is the user operation's nonce; combining it into the signed payload binds
     * the installation authorization to a specific user operation. Callers must wrap the
     * returned struct hash with the account's EIP-712 domain separator (e.g.
     * `_hashTypedDataV4`) before verifying `installationSignature`.
     */
    function initModulesStructHash(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        uint256 nonce
    ) internal pure returns (bytes32) {
        bytes32[] memory initDataHashes = new bytes32[](initDatas.length);
        for (uint256 i = 0; i < initDatas.length; i++) {
            initDataHashes[i] = keccak256(initDatas[i]);
        }

        return
            keccak256(
                abi.encode(
                    INIT_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            );
    }

    /**
     * @dev Attempts to decode an ERC-8043 init mode payload from `data`.
     *
     * `data` must be the user operation's `initCode` with the {INIT_MODE_MAGIC_VALUE}
     * 4-byte prefix already stripped. Callers are expected to detect init mode
     * themselves — typically by comparing `initCode[:4]` against {INIT_MODE_MAGIC_VALUE}
     * — before invoking this function.
     *
     * `valid` is `true` when the payload decodes into four consistent, non-empty
     * arrays: `moduleTypeIds.length == modules.length == initDatas.length > 0`. When
     * `valid` is `false` the returned slices should not be relied on; individual
     * fields whose sub-decoder failed are returned as empty slices, but fields that
     * decoded before the inconsistency was detected may be populated. Callers that
     * want strict init-mode semantics should reject the user operation in that case.
     *
     * The decoding never reverts on malformed input: length and offset checks are
     * performed inline before any calldata slice is materialized.
     */
    function tryDecodeInitMode(
        bytes calldata data
    )
        internal
        pure
        returns (
            bool valid,
            uint256[] calldata moduleTypeIds,
            address[] calldata modules,
            bytes[] calldata initDatas,
            bytes calldata installationSignature
        )
    {
        // Minimum length to hold 4 offset pointers and 4 length words: 4 * 32 + 4 * 32 = 256 bytes (0x100)
        if (data.length < 0x100) {
            return (false, _emptyUint256Array(), _emptyAddressArray(), _emptyBytesArray(), Calldata.emptyBytes());
        }

        moduleTypeIds = _tryDecodeInstallModulesModuleTypeIds(data);
        modules = _tryDecodeInstallModulesModules(data);
        initDatas = _tryDecodeInstallModulesInitDatas(data);
        installationSignature = _tryDecodeInstallModulesInstallationSignature(data);

        return (
            moduleTypeIds.length == modules.length &&
                modules.length == initDatas.length &&
                moduleTypeIds.length > 0 &&
                modules.length > 0 &&
                initDatas.length > 0,
            moduleTypeIds,
            modules,
            initDatas,
            installationSignature
        );
    }

    /// @dev Attempts to decode module type ids from `userOp.initCode[4:]`. Returns an empty uint256[] calldata slice if the array is invalid.
    function _tryDecodeInstallModulesModuleTypeIds(
        bytes calldata data
    ) private pure returns (uint256[] calldata moduleTypeIds) {
        uint256 moduleTypeIdsOffset = uint256(bytes32(data[0x00:0x20]));
        if (moduleTypeIdsOffset < 0x80 || moduleTypeIdsOffset > data.length - 0x20) {
            return _emptyUint256Array();
        }
        uint256 moduleTypeIdsLength = uint256(bytes32(data[moduleTypeIdsOffset:moduleTypeIdsOffset + 0x20]));

        // Bounds check fixed-size array (uint256[])
        if (moduleTypeIdsLength > (data.length - moduleTypeIdsOffset - 0x20) / 0x20) {
            return _emptyUint256Array();
        }

        assembly ("memory-safe") {
            moduleTypeIds.offset := add(data.offset, add(moduleTypeIdsOffset, 0x20))
            moduleTypeIds.length := moduleTypeIdsLength
        }

        return moduleTypeIds;
    }

    /// @dev Attempts to decode modules from `userOp.initCode[4:]`. Returns an empty address[] calldata slice if the array is invalid.
    function _tryDecodeInstallModulesModules(bytes calldata data) private pure returns (address[] calldata modules) {
        uint256 modulesOffset = uint256(bytes32(data[0x20:0x40]));
        if (modulesOffset < 0x80 || modulesOffset > data.length - 0x20) {
            return _emptyAddressArray();
        }
        uint256 modulesLength = uint256(bytes32(data[modulesOffset:modulesOffset + 0x20]));

        // Bounds check fixed-size array (address[])
        if (modulesLength > (data.length - modulesOffset - 0x20) / 0x20) {
            return _emptyAddressArray();
        }

        assembly ("memory-safe") {
            modules.offset := add(data.offset, add(modulesOffset, 0x20))
            modules.length := modulesLength
        }
        return modules;
    }

    /// @dev Attempts to decode init datas from `userOp.initCode[4:]`. Returns an empty bytes[] calldata slice if the array is invalid.
    function _tryDecodeInstallModulesInitDatas(bytes calldata data) private pure returns (bytes[] calldata initDatas) {
        uint256 initDatasOffset = uint256(bytes32(data[0x40:0x60]));
        if (initDatasOffset < 0x80 || initDatasOffset > data.length - 0x20) {
            return _emptyBytesArray();
        }
        uint256 initDatasLength = uint256(bytes32(data[initDatasOffset:initDatasOffset + 0x20]));
        initDatas = _extractBytesArray(data, initDatasOffset, initDatasLength);
        if (initDatas.length == 0 && initDatasLength > 0) {
            return _emptyBytesArray();
        }
        return initDatas;
    }

    /// @dev Attempts to decode installation signature from `userOp.initCode[4:]`. Returns an empty bytes calldata slice if the signature is invalid.
    function _tryDecodeInstallModulesInstallationSignature(
        bytes calldata data
    ) private pure returns (bytes calldata installationSignature) {
        uint256 installationSigOffset = uint256(bytes32(data[0x60:0x80]));
        if (installationSigOffset < 0x80 || installationSigOffset > data.length - 0x20) {
            return Calldata.emptyBytes();
        }
        uint256 installationSigLength = uint256(bytes32(data[installationSigOffset:installationSigOffset + 0x20]));
        if (installationSigLength > data.length - installationSigOffset - 0x20) {
            return Calldata.emptyBytes();
        }
        return data[installationSigOffset + 0x20:installationSigOffset + 0x20 + installationSigLength];
    }

    /**
     * @dev Validates and determines the end offset of a bytes[] array structure.
     * Returns an empty bytes[] calldata slice if the array is invalid.
     *
     * This function checks that:
     * 1. The array length is within bounds
     * 2. All offset pointers are valid
     * 3. All individual bytes elements are within bounds
     *
     * Element offsets are relative to the start of the offset table (`arrayOffset + 0x20`), as in the
     * ABI encoding. Callers must ensure `arrayOffset + 0x20 <= data.length`.
     */
    function _extractBytesArray(
        bytes calldata data,
        uint256 arrayOffset,
        uint256 arrayLength
    ) private pure returns (bytes[] calldata result) {
        // Start after the array length (32 bytes). Element offsets are relative to this position.
        uint256 base = arrayOffset + 0x20;
        uint256 currentOffset = base;

        // Check if we have enough space for all offset pointers (arrayLength * 32 bytes)
        if (arrayLength > (data.length - base) / 0x20) return _emptyBytesArray();

        // Validate each bytes element
        for (uint256 i = 0; i < arrayLength; (i++, currentOffset += 0x20)) {
            // Get the offset for this bytes element, relative to `base`
            uint256 relativeOffset = uint256(bytes32(data[currentOffset:currentOffset + 0x20]));

            // Check if the element offset is within bounds (need at least 32 bytes for length).
            // `data.length - base >= 0x20` holds since the offset table has at least one entry.
            if (relativeOffset > data.length - base - 0x20) return _emptyBytesArray();
            uint256 elementOffset = base + relativeOffset;

            // Get the length of this bytes element
            uint256 elementLength = uint256(bytes32(data[elementOffset:elementOffset + 0x20]));

            // Check if the element data is within bounds
            if (elementLength > data.length - elementOffset - 0x20) return _emptyBytesArray();
        }

        // Extract bytes array directly from calldata
        assembly ("memory-safe") {
            result.offset := add(data.offset, add(arrayOffset, 0x20))
            result.length := arrayLength
        }

        return result;
    }

    /// @dev Returns an empty bytes[] calldata slice.
    function _emptyBytesArray() private pure returns (bytes[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }

    /// @dev Returns an empty address[] calldata slice.
    function _emptyAddressArray() private pure returns (address[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }

    /// @dev Returns an empty uint256[] calldata slice.
    function _emptyUint256Array() private pure returns (uint256[] calldata result) {
        assembly ("memory-safe") {
            result.offset := 0
            result.length := 0
        }
    }
}
