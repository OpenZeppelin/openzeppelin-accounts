// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @dev Implementation of an {IERC7579Module} that uses an ECDSA signer for signature
 * validation.
 *
 * This module provides a base implementation for ECDSA signer validation that can be
 * attached to any function through the {_validateECDSA} internal function.
 */
abstract contract ERC7579ECDSA is IERC7579Module {
    /// @dev The provided signer data is too short (must be at least 20 bytes for an address).
    error ERC7579ECDSAInvalidSignerLength();

    /// @dev The caller is not authorized to set the signer for the specified account.
    error ERC7579ECDSANotAuthorized(address caller, address account);

    /// @dev The provided signer address is invalid.
    error ERC7579ECDSAInvalidSigner(address signer);

    /// @dev The `account` has already installed the module.
    error ERC7579ECDSAAlreadyInstalled();

    /// @dev Emitted when the signer is set.
    event ERC7579ECDSASignerSet(address indexed account, address signer);

    mapping(address account => address signer) private _signers;

    /// @dev Returns the authorized signer for the specified account.
    function signer(address account) public view virtual returns (address) {
        return _signers[account];
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * The `data` parameter should contain the signer address (20 bytes minimum).
     *
     * If the account doesn't already have a signer configured, the first 20 bytes
     * of `data` will be used as the authorized signer address.
     * See {_extractSigner} for more details about the encoding.
     *
     * Requirements:
     *
     * * The `data` must be at least 20 bytes. Reverts with {ERC7579ECDSAInvalidSignerLength} if not.
     * * The `data` must contain a valid signer address. Reverts with {ERC7579ECDSAInvalidSigner} if not.
     * * The `account` must have no signer installed. Reverts with {ERC7579ECDSAAlreadyInstalled} if not.
     *
     * Emits a {ERC7579ECDSASignerSet} event if the signer is set.
     */
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 20, ERC7579ECDSAInvalidSignerLength());
        require(signer(msg.sender) == address(0), ERC7579ECDSAAlreadyInstalled());
        address newSigner = _extractSigner(data);
        _setSigner(msg.sender, newSigner);
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Removes the authorized signer for the calling account.
     *
     * If the account has a configured signer, it will be cleared. If no signer
     * is configured, this function will behave as a no-op.
     *
     * Emits a {ERC7579ECDSASignerSet} event if the signer is cleared.
     */
    function onUninstall(bytes calldata /* data */) public virtual override {
        if (signer(msg.sender) != address(0)) {
            delete _signers[msg.sender];
            emit ERC7579ECDSASignerSet(msg.sender, address(0));
        }
    }

    /**
     * @dev Sets the signer for the specified account.
     *
     * Requirements:
     *
     * * The `newSigner` must not be the zero address.
     * * The caller must be the specified account.
     *
     * Emits a {ERC7579ECDSASignerSet} event.
     */
    function setSigner(address account, address newSigner) public virtual {
        require(msg.sender == account, ERC7579ECDSANotAuthorized(msg.sender, account));
        _setSigner(account, newSigner);
    }

    /**
     * @dev Internal version of {setSigner} without access control.
     *
     * Requirements:
     *
     * * The `newSigner` must not be the zero address.
     *
     * Emits a {ERC7579ECDSASignerSet} event.
     */
    function _setSigner(address account, address newSigner) internal virtual {
        require(newSigner != address(0), ERC7579ECDSAInvalidSigner(newSigner));
        _signers[account] = newSigner;
        emit ERC7579ECDSASignerSet(account, newSigner);
    }

    /// @dev Extracts the signer address from the provided data for onInstall.
    function _extractSigner(bytes calldata data) internal pure virtual returns (address) {
        return address(bytes20(data[:20]));
    }

    /**
     * @dev Validates an ECDSA signature against the configured signer for the account.
     *
     * This function recovers the signer address from the provided signature and hash,
     * then compares it against the authorized signer for the given account.
     */
    function _validateECDSA(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecoverCalldata(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == signer(account);
    }
}
