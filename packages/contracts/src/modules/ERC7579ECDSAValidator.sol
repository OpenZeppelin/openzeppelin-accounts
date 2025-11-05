// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @dev Implementation of an {ERC7579Validator} that uses ECDSA signatures for validation.
 *
 * This module provides ECDSA signature validation for ERC-7579 accounts. Each account
 * can have a single authorized signer (EOA address) that can approve operations through
 * ECDSA signatures.
 *
 * Example usage:
 *
 * ```solidity
 * // Install the validator with a signer address
 * bytes memory initData = abi.encodePacked(signerAddress);
 * account.installModule(MODULE_TYPE_VALIDATOR, validatorAddress, initData);
 * ```
 */
abstract contract ERC7579ECDSAValidator is ERC7579Validator {
    /// @dev The provided signer data is too short (must be at least 20 bytes for an address).
    error ERC7579ECDSAValidatorInvalidSignerLength();

    /// @dev The caller is not authorized to set the signer for the specified account.
    error ERC7579ECDSAValidatorNotAuthorized(address caller, address account);

    /// @dev The provided signer address is invalid.
    error ERC7579ECDSAValidatorInvalidSigner(address signer);

    /// @dev Emitted when the signer is set.
    event ERC7579ECDSAValidatorSignerSet(address indexed account, address signer);

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
     *
     * Requirements:
     *
     * * The `data` must be at least 20 bytes.
     * * The `data` must contain a valid signer address.
     *
     * NOTE: An account can only set a signer once. If called directly by an account
     * that already has a signer configured, this function will behave as a no-op.
     *
     * Emits a {ERC7579ECDSAValidatorSignerSet} event if the signer is set.
     */
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 20, ERC7579ECDSAValidatorInvalidSignerLength());
        if (signer(msg.sender) == address(0)) {
            _setSigner(msg.sender, _extractSigner(data));
        }
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Removes the authorized signer for the calling account.
     *
     * If the account has a configured signer, it will be cleared. If no signer
     * is configured, this function will behave as a no-op.
     *
     * Emits a {ERC7579ECDSAValidatorSignerSet} event if the signer is cleared.
     */
    function onUninstall(bytes calldata /* data */) public virtual override {
        if (signer(msg.sender) != address(0)) {
            delete _signers[msg.sender];
            emit ERC7579ECDSAValidatorSignerSet(msg.sender, address(0));
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
     * Emits a {ERC7579ECDSAValidatorSignerSet} event.
     */
    function setSigner(address account, address newSigner) public virtual {
        require(msg.sender == account, ERC7579ECDSAValidatorNotAuthorized(msg.sender, account));
        _setSigner(account, newSigner);
    }

    /**
     * @dev Internal version of {setSigner} without access control.
     *
     * Requirements:
     *
     * * The `newSigner` must not be the zero address.
     *
     * Emits a {ERC7579ECDSAValidatorSignerSet} event.
     */
    function _setSigner(address account, address newSigner) internal virtual {
        require(newSigner != address(0), ERC7579ECDSAValidatorInvalidSigner(newSigner));
        _signers[account] = newSigner;
        emit ERC7579ECDSAValidatorSignerSet(account, newSigner);
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
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecoverCalldata(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == signer(account);
    }
}
