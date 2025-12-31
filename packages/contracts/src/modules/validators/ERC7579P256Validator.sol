// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/**
 * @dev Implementation of an {ERC7579Validator} that uses P256 signatures for validation.
 *
 * This module provides P256 signature validation for ERC-7579 accounts. Each account
 * can have a single authorized P256 signer (public key coordinates) that can approve
 * operations through P256 signatures.
 *
 * The P256 signer consists of a P256 public key pair (qx, qy coordinates) that
 * is registered during module installation. Signatures must be valid P256 signatures
 * that can be verified against this public key.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with P256 public key coordinates
 * bytes memory initData = abi.encodePacked(qx, qy);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
contract ERC7579P256Validator is ERC7579Validator {
    /// @dev The provided signer data is too short (must be at least 64 bytes for P256 coordinates).
    error ERC7579P256ValidatorInvalidSignerLength();

    /// @dev The caller is not authorized to set the signer for the specified account.
    error ERC7579P256ValidatorNotAuthorized(address caller, address account);

    /// @dev The provided P256 public key is invalid.
    error ERC7579P256ValidatorInvalidPublicKey(bytes32 qx, bytes32 qy);

    /// @dev The `account` has already installed the module.
    error ERC7579P256ValidatorAlreadyInstalled();

    /// @dev Emitted when the signer is set.
    event ERC7579P256ValidatorSignerSet(address indexed account, bytes32 qx, bytes32 qy);

    /// @dev Stores the P256 signer for each account as P256 public key coordinates.
    struct P256Signer {
        bytes32 qx;
        bytes32 qy;
    }

    mapping(address account => P256Signer signer) private _signers;

    /// @dev Returns the authorized P256 signer for the specified account.
    function signer(address account) public view virtual returns (bytes32 qx, bytes32 qy) {
        return (_signers[account].qx, _signers[account].qy);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * The `data` parameter should contain the P256 public key coordinates (64 bytes minimum).
     *
     * If the account doesn't already have a signer configured, the first 64 bytes
     * of `data` will be used as the authorized P256 signer (qx, qy).
     * See {_extractSigner} for more details about the encoding.
     *
     * Requirements:
     *
     * * The `data` must be at least 64 bytes. Reverts with {ERC7579P256ValidatorInvalidSignerLength} if not.
     * * The `account` must have no signer installed. Reverts with {ERC7579P256ValidatorAlreadyInstalled} if not.
     * * Decode `data` into `abi.encode(bytes32 qx, bytes32 qy)`.
     * * The `data` must contain valid P256 public key coordinates. Reverts with {ERC7579P256ValidatorInvalidPublicKey} if not.
     *
     * NOTE: An account can only set a signer once. If called directly by an account
     * that already has a signer configured, this function will behave as a no-op.
     *
     * Emits a {ERC7579P256ValidatorSignerSet} event if the signer is set.
     */
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 64, ERC7579P256ValidatorInvalidSignerLength());
        (bytes32 qx, bytes32 qy) = signer(msg.sender);
        require(qx == bytes32(0) && qy == bytes32(0), ERC7579P256ValidatorAlreadyInstalled());
        (bytes32 newQx, bytes32 newQy) = _extractSigner(data);
        _setSigner(msg.sender, newQx, newQy);
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Removes the authorized P256 signer for the calling account.
     *
     * If the account has a configured signer, it will be cleared. If no signer
     * is configured, this function will behave as a no-op.
     *
     * Emits a {ERC7579P256ValidatorSignerSet} event if the signer is cleared.
     */
    function onUninstall(bytes calldata /* data */) public virtual override {
        (bytes32 qx, bytes32 qy) = signer(msg.sender);
        if (qx != bytes32(0) || qy != bytes32(0)) {
            _signers[msg.sender].qx = bytes32(0);
            _signers[msg.sender].qy = bytes32(0);
            emit ERC7579P256ValidatorSignerSet(msg.sender, bytes32(0), bytes32(0));
        }
    }

    /**
     * @dev Sets the P256 signer for the specified account.
     *
     * Requirements:
     *
     * * The `qx` and `qy` coordinates must not be zero.
     * * The `qx` and `qy` coordinates must be valid P256 public key coordinates.
     * * The caller must be the specified account.
     *
     * Emits a {ERC7579P256ValidatorSignerSet} event.
     */
    function setSigner(address account, bytes32 qx, bytes32 qy) public virtual {
        require(msg.sender == account, ERC7579P256ValidatorNotAuthorized(msg.sender, account));
        _setSigner(account, qx, qy);
    }

    /**
     * @dev Internal version of {setSigner} without access control.
     *
     * Requirements:
     *
     * * The `qx` and `qy` coordinates must not be zero.
     * * The `qx` and `qy` coordinates must be valid P256 public key coordinates.
     *
     * Emits a {ERC7579P256ValidatorSignerSet} event.
     */
    function _setSigner(address account, bytes32 qx, bytes32 qy) internal virtual {
        require(P256.isValidPublicKey(qx, qy), ERC7579P256ValidatorInvalidPublicKey(qx, qy));

        _signers[account].qx = qx;
        _signers[account].qy = qy;
        emit ERC7579P256ValidatorSignerSet(account, qx, qy);
    }

    /// @dev Extracts the P256 public key coordinates from the provided data for onInstall.
    function _extractSigner(bytes calldata data) internal pure virtual returns (bytes32 qx, bytes32 qy) {
        return (bytes32(data[:32]), bytes32(data[32:64]));
    }

    /**
     * @dev Validates a P256 signature against the configured signer for the account.
     *
     * This function extracts the r and s components from the signature and verifies
     * them against the P256 public key stored for the given account.
     *
     * The signature is expected to be at least 64 bytes containing the P256 signature
     * components (r, s) as 32-byte values.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        if (signature.length < 0x40) return false;
        bytes32 r = bytes32(signature[0x00:0x20]);
        bytes32 s = bytes32(signature[0x20:0x40]);
        (bytes32 qx, bytes32 qy) = signer(account);
        return P256.verify(hash, r, s, qx, qy);
    }
}
