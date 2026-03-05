// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OpenAccount} from "../OpenAccount.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";

/**
 * @dev Extension of `OpenAccount` that implements atomic module installation and usage through
 * _init mode_ following https://eip.tools/eip/8043[ERC-8043].
 *
 * This extension allows installing and using one or more modules within the same user operation.
 * Init mode is triggered when `userOp.initCode` starts with the 4-byte magic value `0x80438043`.
 * The remaining bytes of `initCode` carry the ABI-encoded module installation payload and an
 * EIP-712 installation signature from the account owner.
 *
 * Because the {ERC-4337} EntryPoint v0.9 silently ignores `initCode` for already-deployed accounts,
 * and because `initCode` is included in the `userOpHash`, the module installation parameters are
 * both inert at the EntryPoint level and cryptographically committed to by the user operation signature.
 *
 * This pattern is particularly useful for session keys and other modules that need to be
 * installed and immediately used, reducing user operation count from N+1 to 1.
 *
 * NOTE: Requires EntryPoint v0.9 or later.
 */
abstract contract OpenAccountERC8043 is OpenAccount {
    bytes4 private constant INIT_MODE_MAGIC_VALUE = 0x80438043;
    bytes32 private constant INIT_MODULES_TYPEHASH =
        keccak256("InitModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)");

    /**
     * @dev Validates a user operation, checking for the init mode magic value in `initCode`.
     *
     * If `userOp.initCode` starts with `INIT_MODE_MAGIC_VALUE`, enters init mode:
     *
     * 1. Decodes module installation data from `userOp.initCode[4:]`
     * 2. Validates the EIP-712 `installationSignature` over the module installation parameters
     * 3. Installs the modules if validation succeeds
     * 4. Continues with normal user operation validation using `userOp.signature`
     *
     * Otherwise, falls back to `OpenAccount`'s `_validateUserOp`.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal virtual override returns (uint256) {
        if (userOp.initCode.length >= 4 && bytes4(userOp.initCode[:4]) == INIT_MODE_MAGIC_VALUE) {
            return _validateInitMode(userOp, userOpHash);
        }
        return super._validateUserOp(userOp, userOpHash, signature);
    }

    /**
     * @dev Validates and installs modules in init mode, then validates the user operation.
     *
     * Decodes `(moduleTypeIds, modules, initDatas, installationSignature)` from
     * `userOp.initCode[4:]`. Validates the EIP-712 `installationSignature` from the account
     * owner and installs all modules before delegating to normal user operation validation.
     *
     * The encoding format is:
     *
     * ```
     * abi.encode(uint256[] moduleTypeIds, address[] modules, bytes[] initDatas, bytes installationSignature)
     * ```
     *
     * Where `installationSignature` is an EIP-712 signature over the {InitModules} struct.
     */
    function _validateInitMode(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256) {
        // Minimum length to hold 4 offset pointers and 4 length words: 4 * 32 + 4 * 32 = 256 bytes (0x100)
        bytes calldata data = userOp.initCode[4:];
        if (data.length < 0x100) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        uint256[] calldata moduleTypeIds = _tryDecodeInstallModulesModuleTypeIds(data);
        address[] calldata modules = _tryDecodeInstallModulesModules(data);
        bytes[] calldata initDatas = _tryDecodeInstallModulesInitDatas(data);
        bytes calldata installationSignature = _tryDecodeInstallModulesInstallationSignature(data);

        if (
            moduleTypeIds.length != modules.length ||
            modules.length != initDatas.length ||
            moduleTypeIds.length == 0 ||
            modules.length == 0 ||
            initDatas.length == 0
        ) {
            return ERC4337Utils.SIG_VALIDATION_FAILED;
        }

        if (installationSignature.length > 0) {
            uint256 nonce = userOp.nonce;
            bytes32 structHash = _installModulesStructHash(moduleTypeIds, modules, initDatas, nonce);
            if (
                isValidSignature(_hashTypedDataV4(structHash), installationSignature) !=
                IERC1271.isValidSignature.selector
            ) {
                return ERC4337Utils.SIG_VALIDATION_FAILED;
            }
            for (uint256 i = 0; i < modules.length; i++) {
                _installModule(moduleTypeIds[i], modules[i], initDatas[i]);
            }
        }

        return super._validateUserOp(userOp, userOpHash, userOp.signature);
    }

    /**
     * @dev Computes the struct hash for the InitModules EIP-712 message.
     *
     * ```
     * InitModules(uint256[] moduleTypeIds, address[] modules, bytes[] initDatas, uint256 nonce)
     * ```
     *
     * Where `nonce` is `userOp.nonce`. Caller must wrap with `_hashTypedDataV4` before
     * passing to signature verification.
     */
    function _installModulesStructHash(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        uint256 nonce
    ) internal pure virtual returns (bytes32) {
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

    /// @dev Attempts to decode module type ids from `userOp.initCode[4:]`.
    function _tryDecodeInstallModulesModuleTypeIds(
        bytes calldata data
    ) private pure returns (uint256[] calldata moduleTypeIds) {
        uint256 moduleTypeIdsOffset = uint256(bytes32(data[0x00:0x20]));
        if (moduleTypeIdsOffset < 0x80 || data.length < moduleTypeIdsOffset + 0x20) {
            return _emptyUint256Array();
        }
        uint256 moduleTypeIdsLength = uint256(bytes32(data[moduleTypeIdsOffset:moduleTypeIdsOffset + 0x20]));

        // Bounds check fixed-size array (uint256[])
        if (data.length < moduleTypeIdsOffset + 0x20 + moduleTypeIdsLength * 0x20) {
            return _emptyUint256Array();
        }

        assembly ("memory-safe") {
            moduleTypeIds.offset := add(data.offset, add(moduleTypeIdsOffset, 0x20))
            moduleTypeIds.length := moduleTypeIdsLength
        }

        return moduleTypeIds;
    }

    /// @dev Attempts to decode modules from `userOp.initCode[4:]`.
    function _tryDecodeInstallModulesModules(bytes calldata data) private pure returns (address[] calldata modules) {
        uint256 modulesOffset = uint256(bytes32(data[0x20:0x40]));
        if (modulesOffset < 0x80 || data.length < modulesOffset + 0x20) {
            return _emptyAddressArray();
        }
        uint256 modulesLength = uint256(bytes32(data[modulesOffset:modulesOffset + 0x20]));

        // Bounds check fixed-size array (address[])
        if (data.length < modulesOffset + 0x20 + modulesLength * 0x20) {
            return _emptyAddressArray();
        }

        assembly ("memory-safe") {
            modules.offset := add(data.offset, add(modulesOffset, 0x20))
            modules.length := modulesLength
        }
        return modules;
    }

    /// @dev Attempts to decode init datas from `userOp.initCode[4:]`.
    function _tryDecodeInstallModulesInitDatas(bytes calldata data) private pure returns (bytes[] calldata initDatas) {
        uint256 initDatasOffset = uint256(bytes32(data[0x40:0x60]));
        if (initDatasOffset < 0x80 || data.length < initDatasOffset + 0x20) {
            return _emptyBytesArray();
        }
        uint256 initDatasLength = uint256(bytes32(data[initDatasOffset:initDatasOffset + 0x20]));
        initDatas = _extractBytesArray(data, initDatasOffset, initDatasLength);
        if (initDatas.length == 0 && initDatasLength > 0) {
            return _emptyBytesArray();
        }
        return initDatas;
    }

    /// @dev Attempts to decode installation signature from `userOp.initCode[4:]`.
    function _tryDecodeInstallModulesInstallationSignature(
        bytes calldata data
    ) private pure returns (bytes calldata installationSignature) {
        uint256 installationSigOffset = uint256(bytes32(data[0x60:0x80]));
        if (installationSigOffset < 0x80 || data.length < installationSigOffset + 0x20) {
            return Calldata.emptyBytes();
        }
        uint256 installationSigLength = uint256(bytes32(data[installationSigOffset:installationSigOffset + 0x20]));
        if (installationSigLength > data.length || data.length < installationSigOffset + 0x20 + installationSigLength) {
            return Calldata.emptyBytes();
        }
        return data[installationSigOffset + 0x20:installationSigOffset + 0x20 + installationSigLength];
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
            bytes calldata installationSignature
        )
    {
        return (false, _emptyUint256Array(), _emptyAddressArray(), _emptyBytesArray(), Calldata.emptyBytes());
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
