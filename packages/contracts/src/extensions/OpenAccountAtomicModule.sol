// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OpenAccount} from "../OpenAccount.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Packing} from "@openzeppelin/contracts/utils/Packing.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";

/**
 * @dev Extension of `OpenAccount` that implements atomic module installation and usage.
 *
 * This extension allows installing and using a module within the same user operation by detecting
 * a magic nonce prefix (`0x01`) and decoding module installation data from the signature field.
 * The account owner authorizes module installation through EIP-712 signatures.
 *
 * This pattern is particularly useful for session keys and other modules that need to be
 * installed and immediately used, improving user experience by reducing user operation count.
 */
abstract contract OpenAccountAtomicModule is OpenAccount {
    using Packing for *;

    bytes1 private constant ATOMIC_MODULE_PREFIX = 0x01;
    bytes32 private constant INSTALL_MODULE_TYPEHASH =
        keccak256(
            "InstallAtomicModule(uint256 moduleTypeId,address module,bytes initData,uint256 nonce)"
        );

    /**
     * @dev Validates a user operation, checking for atomic module installation pattern.
     *
     * If the nonce starts with the atomic module prefix (`0x01`), attempts to decode and install
     * a module from the signature before proceeding with normal validation. If prefixed, it:
     *
     * 1. Decodes module installation data from the signature
     * 2. Validates the EIP-712 signature for module installation
     * 3. Installs the module if validation succeeds
     * 4. Continues with normal user operation validation using the installed module
     *
     * Otherwise, falls back to OpenAccount's `_validateUserOp` function.
     * See `_validateAtomicModule` for the validation of atomic module installation.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256) {
        if (bytes32(userOp.nonce).extract_32_1(0) == ATOMIC_MODULE_PREFIX) {
            (
                uint256 validationData,
                bytes calldata innerSignature
            ) = _validateAtomicModule(
                    userOp.signature,
                    userOp.nonce,
                    userOpHash
                );
            if (validationData == ERC4337Utils.SIG_VALIDATION_SUCCESS) {
                userOp.signature = innerSignature; // TODO: Can't reassign the signature in the user operation
                return super._validateUserOp(userOp, userOpHash);
            }
            return validationData; // Prefixed but invalid signature or failed installation
        }
        return super._validateUserOp(userOp, userOpHash);
    }

    /**
     * @dev Validates and installs a module atomically during user operation validation.
     *
     * Decodes module installation data from the user operation signature, validates the
     * EIP-712 signature for module installation authorization, and installs the module
     * if validation succeeds.
     *
     * See `_tryDecodeInstallAtomicModule` for the signature format.
     */
    function _validateAtomicModule(
        bytes calldata signature,
        uint256 nonce,
        bytes32 userOpHash
    ) internal virtual returns (uint256, bytes calldata) {
        (
            bool success,
            uint256 moduleTypeId,
            address module,
            bytes calldata initData,
            bytes calldata atomicInstallationSignature,
            bytes calldata userOpSignature
        ) = _tryDecodeInstallAtomicModule(signature);

        if (!success) {
            return (ERC4337Utils.SIG_VALIDATION_FAILED, signature);
        }

        bytes32 structHash = _installAtomicModuleStructHash(
            moduleTypeId,
            module,
            initData,
            nonce
        );
        if (
            isValidSignature(
                _hashTypedDataV4(structHash),
                atomicInstallationSignature
            ) == IERC1271.isValidSignature.selector
        ) {
            _installModule(moduleTypeId, module, initData);
            return (ERC4337Utils.SIG_VALIDATION_SUCCESS, userOpSignature);
        }

        return (ERC4337Utils.SIG_VALIDATION_FAILED, signature);
    }

    /**
     * @dev Computes the struct hash for the InstallAtomicModule EIP-712 message.
     *
     * The struct hash is used as part of the EIP-712 signature verification process
     * to ensure the module installation is properly authorized by the account owner.
     */
    function _installAtomicModuleStructHash(
        uint256 moduleTypeId,
        address module,
        bytes memory initData,
        uint256 nonce
    ) internal pure virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    INSTALL_MODULE_TYPEHASH,
                    moduleTypeId,
                    module,
                    keccak256(initData),
                    nonce
                )
            );
    }

    /**
     * @dev Attempts to decode atomic module installation data from a signature.
     *
     * Uses calldata slicing to avoid memory allocation. Performs bounds checking
     * to ensure safe access to the signature data without reverting.
     *
     * The signature format for atomic module installation is:
     * `abi.encode(moduleTypeId, module, initData, atomicInstallationSignature, userOpSignature)`
     *
     * Where:
     *
     * * `atomicInstallationSignature` is an EIP-712 signature over the InstallAtomicModule struct
     * * `userOpSignature` is the signature for validating the user operation itself
     */
    function _tryDecodeInstallAtomicModule(
        bytes calldata signature
    )
        private
        pure
        returns (
            bool success,
            uint256 moduleTypeId,
            address module,
            bytes calldata initData,
            bytes calldata atomicInstallationSignature,
            bytes calldata userOpSignature
        )
    {
        // Minimum length to hold 5 objects: moduleTypeId (32), module (32), initData offset (32),
        // atomicInstallationSignature offset (32), userOpSignature offset (32)
        if (signature.length < 0xa0)
            return (
                false,
                0,
                address(0),
                Calldata.emptyBytes(),
                Calldata.emptyBytes(),
                Calldata.emptyBytes()
            );

        // Extract the fixed-size values directly
        moduleTypeId = uint256(bytes32(signature[0x00:0x20]));
        module = address(bytes20(signature[0x2c:0x40])); // Skip 12 bytes padding for address

        // Get offsets for dynamic data (relative to signature buffer)
        uint256 initDataOffset = uint256(bytes32(signature[0x40:0x60]));
        uint256 atomicInstallationSignatureOffset = uint256(
            bytes32(signature[0x60:0x80])
        );
        uint256 userOpSignatureOffset = uint256(bytes32(signature[0x80:0xa0]));

        // Check offsets are within bounds (need at least 32 bytes for length)
        if (
            signature.length - 0x20 < initDataOffset ||
            signature.length - 0x20 < atomicInstallationSignatureOffset ||
            signature.length - 0x20 < userOpSignatureOffset
        ) {
            return (
                false,
                0,
                address(0),
                Calldata.emptyBytes(),
                Calldata.emptyBytes(),
                Calldata.emptyBytes()
            );
        }

        // Get the lengths of dynamic data
        uint256 initDataLength = uint256(
            bytes32(signature[initDataOffset:initDataOffset + 0x20])
        );
        uint256 atomicInstallationSignatureLength = uint256(
            bytes32(
                signature[atomicInstallationSignatureOffset:atomicInstallationSignatureOffset +
                    0x20]
            )
        );
        uint256 userOpSignatureLength = uint256(
            bytes32(
                signature[userOpSignatureOffset:userOpSignatureOffset + 0x20]
            )
        );

        // Check that signature buffer is long enough to contain the dynamic data
        if (
            signature.length - initDataOffset - 0x20 < initDataLength ||
            signature.length - atomicInstallationSignatureOffset - 0x20 <
            atomicInstallationSignatureLength ||
            signature.length - userOpSignatureOffset - 0x20 <
            userOpSignatureLength
        ) {
            return (
                false,
                0,
                address(0),
                Calldata.emptyBytes(),
                Calldata.emptyBytes(),
                Calldata.emptyBytes()
            );
        }

        // Extract calldata slices for dynamic data (skip the 32-byte length prefix)
        initData = signature[initDataOffset + 0x20:initDataOffset +
            0x20 +
            initDataLength];
        atomicInstallationSignature = signature[atomicInstallationSignatureOffset +
            0x20:atomicInstallationSignatureOffset +
            0x20 +
            atomicInstallationSignatureLength];
        userOpSignature = signature[userOpSignatureOffset +
            0x20:userOpSignatureOffset + 0x20 + userOpSignatureLength];

        return (
            true,
            moduleTypeId,
            module,
            initData,
            atomicInstallationSignature,
            userOpSignature
        );
    }
}
