// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {IERC6372} from "@openzeppelin/contracts/interfaces/IERC6372.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";

/**
 * @dev Abstract base for ERC-7579 session keys.
 *
 * This module allows registering ERC-7913 keys as session keys on a smart account, each with
 * a configurable validity range. A session key is any ERC-7913 signer (an arbitrary
 * cryptographic key identified by a `(verifier, key)` pair) that is registered for a
 * specific account. The key is only considered active between its `from` and `until`
 * timepoints.
 *
 * The key is encoded in the `signature` field of the user operations and ERC-1271 requests for
 * identification and cryptographic verification. See {_tryDecodeSignature} for the encoding details.
 *
 * This module provides session key management through the {_validateSessionKey} and
 * {isValid} internal functions. Concrete implementations should attach it to validation flows such as
 * {ERC7579Validator-_rawERC7579Validation}.
 */
abstract contract ERC7579SessionKeys is IERC7579Module, Nonces, IERC6372 {
    using EnumerableSet for EnumerableSet.BytesSet;

    /// @dev The `keys`, `starts`, and `ends` arrays passed to {onInstall} have different lengths.
    error ERC7579SessionKeyssMismatchedInitDataLengths();

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579SessionKeyssInvalidInitData();

    /// @dev The provided `key` is already registered.
    error ERC7579SessionKeyssAlreadyRegisteredKey(bytes key);

    /// @dev The provided `key` is not registered.
    error ERC7579SessionKeyssNonexistentKey(bytes key);

    /// @dev Emitted when all session keys are cleared for an account on uninstall.
    event ERC7579SessionKeyssCleared(address indexed account);

    /// @dev Emitted when a session key is registered or updated for an account.
    event ERC7579SessionKeyssERC7913KeySet(address indexed account, bytes indexed key, uint48 start, uint48 end);

    /// @dev Emitted when a session key is removed from an account.
    event ERC7579SessionKeyssERC7913KeyUnset(address indexed account, bytes indexed key);

    /**
     * @dev Validity range for a session key.
     *
     * * `from`: The earliest timepoint at which the key is valid (inclusive).
     * * `until`: The latest timepoint at which the key is valid (inclusive).
     */
    struct Validity {
        uint48 from;
        uint48 until;
    }

    mapping(address account => mapping(uint256 installation => EnumerableSet.BytesSet)) private _sessionKeys;
    mapping(address account => mapping(uint256 installation => mapping(bytes32 keyId => Validity))) private _validities;

    /**
     * @dev Clock used for flagging validity ranges. Defaults to timestamp but can be overridden
     * to use block numbers if needed.
     */
    function clock() public view virtual returns (uint48) {
        return Time.timestamp();
    }

    /**
     * @dev Machine-readable description of the clock as specified in ERC-6372.
     * Can be overridden to return `"mode=blocknumber&from=default"` if using block numbers.
     */
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public view virtual returns (string memory) {
        return "mode=timestamp";
    }

    /// @dev Returns the installation nonce for an `account`. See {onUninstall}.
    function installation(address account) public view virtual returns (uint256) {
        return nonces(account);
    }

    /// @dev Returns whether `key` is a registered session key for `account`.
    function isKey(address account, bytes calldata key) public view virtual returns (bool) {
        return _isKey(account, installation(account), key);
    }

    /// @dev Returns the validity range `(from, until)` for a `key` on an `account`.
    function validity(address account, bytes calldata key) public view virtual returns (uint48 from, uint48 until) {
        return _validity(account, installation(account), key);
    }

    /// @dev Returns whether a `key` is valid for an `account` at the current timepoint.
    function isValid(address account, bytes calldata key) public view virtual returns (bool) {
        return _isValid(account, installation(account), key);
    }

    /**
     * @dev Returns a slice of the registered session keys for an `account`.
     *
     * Using `startIdx = 0` and `endIdx = type(uint256).max` will return all keys.
     *
     * WARNING: Depending on the `startIdx` and `endIdx`, this operation can copy a large amount
     * of data to memory, which can be expensive. This is designed for view accessors queried
     * without gas fees. Using it in state-changing functions may become uncallable if the set
     * grows too large.
     */
    function keys(address account, uint256 startIdx, uint256 endIdx) public view virtual returns (bytes[] memory) {
        return _keys(account, installation(account), startIdx, endIdx);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * See {IERC7579Module-onInstall}. The `initData` encodes arrays of keys and their
     * corresponding validity ranges.
     *
     * See {_decodeKeysInitData} for the encoding details.
     *
     * Requirements:
     *
     * * Those from {_decodeKeysInitData} for the decoding requirements.
     * * Those from {_addKeys} for the key configuration requirements.
     *
     * TIP: Set `starts[i]` to `0` to activate the key immediately at the current timepoint.
     * TIP: Set `ends[i]` to `0` to register a key with no expiry.
     */
    function onInstall(bytes calldata initData) public virtual {
        (bytes[] calldata keys_, uint48[] calldata starts, uint48[] calldata ends) = _decodeKeysInitData(initData);
        _addKeys(msg.sender, keys_, starts, ends);
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Increments the account's nonce to invalidate all registered session keys.
     *
     * See {IERC7579Module-onUninstall}.
     *
     * NOTE: This approach avoids unbounded gas costs by not iterating over keys.
     * Previous key data remains in storage but becomes inaccessible due to the nonce increment.
     * Upon reinstallation, the module will use a new nonce and ignore old keys.
     */
    function onUninstall(bytes calldata) public virtual {
        _useNonce(msg.sender);
        emit ERC7579SessionKeyssCleared(msg.sender);
    }

    /**
     * @dev Adds new session keys to the module for the calling account.
     * Can only be called by the account itself.
     *
     * Requirements:
     *
     * * Those from {_addKeys} for the key configuration requirements.
     */
    function addKeys(bytes[] calldata newKeys, uint48[] calldata starts, uint48[] calldata ends) public virtual {
        require(
            newKeys.length == starts.length && newKeys.length == ends.length,
            ERC7579SessionKeyssMismatchedInitDataLengths()
        );
        _addKeys(msg.sender, newKeys, starts, ends);
    }

    /**
     * @dev Removes session keys from the module for the calling account.
     * Can only be called by the account itself.
     *
     * Requirements:
     *
     * * Those from {_removeKeys} for the key configuration requirements.
     */
    function removeKeys(bytes[] calldata oldKeys) public virtual {
        _removeKeys(msg.sender, oldKeys);
    }

    /// @dev Internal version of {isKey} that receives an `installation_` nonce.
    function _isKey(address account, uint256 installation_, bytes calldata key) internal view virtual returns (bool) {
        return _sessionKeys[account][installation_].contains(key);
    }

    /// @dev Internal version of {validity} that receives an `installation_` nonce.
    function _validity(
        address account,
        uint256 installation_,
        bytes calldata key
    ) internal view virtual returns (uint48 from, uint48 until) {
        return (
            _validities[account][installation_][_keyId(key)].from,
            _validities[account][installation_][_keyId(key)].until
        );
    }

    /// @dev Internal version of {isValid} that receives an `installation_` nonce.
    function _isValid(address account, uint256 installation_, bytes calldata key) internal view virtual returns (bool) {
        uint48 timepoint = clock();
        (uint48 from, uint48 until) = _validity(account, installation_, key);
        return from <= timepoint && until >= timepoint;
    }

    /// @dev Internal version of {keys} that receives an `installation_` nonce.
    function _keys(
        address account,
        uint256 installation_,
        uint256 startIdx,
        uint256 endIdx
    ) internal view virtual returns (bytes[] memory) {
        return _sessionKeys[account][installation_].values(startIdx, endIdx);
    }

    /**
     * @dev Internal function to register session keys for an `account`.
     *
     * For each key, stores the ERC-7913 key bytes in the enumerable set and records its
     * validity range. Keys are identified by `keccak256(key)` in the validity mapping.
     *
     * Requirements:
     *
     * * All arrays must have equal length. Reverts with {ERC7579SessionKeyssMismatchedInitDataLengths} if not.
     * * Each of `keys_` must not be registered. Reverts with {ERC7579SessionKeyssAlreadyRegisteredKey} if it is.
     *
     * TIP: Setting `starts[i]` to `0` resolves to the current timepoint.
     * TIP: Setting `ends[i]` to `0` stores `type(uint48).max`, meaning no expiry.
     *
     * Emits an {ERC7579SessionKeyssERC7913KeySet} event for each key.
     */
    function _addKeys(
        address account,
        bytes[] calldata keys_,
        uint48[] calldata starts,
        uint48[] calldata ends
    ) internal {
        require(
            keys_.length == starts.length && keys_.length == ends.length,
            ERC7579SessionKeyssMismatchedInitDataLengths()
        );
        uint256 installation_ = installation(account);
        for (uint256 i = 0; i < keys_.length; ++i) {
            bytes calldata key = keys_[i];
            require(_sessionKeys[account][installation_].add(key), ERC7579SessionKeyssAlreadyRegisteredKey(key));
            bytes32 keyId = _keyId(key);
            Validity storage validity_ = _validities[account][installation_][keyId];
            uint48 start = uint48(Math.ternary(starts[i] == 0, clock(), starts[i])); // Safe cast. Both are uint48.
            uint48 end = uint48(Math.ternary(ends[i] == 0, type(uint48).max, ends[i])); // Safe cast. Both are uint48.
            validity_.from = start;
            validity_.until = end;
            emit ERC7579SessionKeyssERC7913KeySet(account, key, start, end);
        }
    }

    /**
     * @dev Internal function to remove session keys from an `account`.
     *
     * Removes the key from the enumerable set and clears its validity range in storage.
     *
     * Requirements:
     *
     * * Each of `keys_` must be registered. Reverts with {ERC7579SessionKeyssNonexistentKey} if not.
     *
     * Emits an {ERC7579SessionKeyssERC7913KeyUnset} event for each key.
     */
    function _removeKeys(address account, bytes[] calldata keys_) internal {
        uint256 installation_ = installation(account);
        for (uint256 i = 0; i < keys_.length; ++i) {
            bytes calldata key = keys_[i];
            require(_sessionKeys[account][installation_].remove(key), ERC7579SessionKeyssNonexistentKey(key));
            bytes32 keyId = _keyId(key);
            Validity storage validity_ = _validities[account][installation_][keyId];
            validity_.from = 0;
            validity_.until = 0;
            emit ERC7579SessionKeyssERC7913KeyUnset(account, key);
        }
    }

    /**
     * @dev Validates an ERC-7913 session key signature against the registered keys for the account.
     *
     * Decodes the ERC-7913 key and its cryptographic signature from the encoded `signature`
     * field, then checks that the key is registered and that the cryptographic signature is
     * valid. Does not validate the {validity} range.
     *
     * See {_tryDecodeSignature} for the encoding details.
     *
     * NOTE: Does not validate the {validity} range.
     */
    function _validateSessionKey(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        (bool success, bytes calldata key, bytes calldata keySignature) = _tryDecodeSignature(signature);
        // Validity is enforced by the caller (e.g. ERC7579SessionKeysValidator).
        return success && isKey(account, key) && SignatureChecker.isValidSignatureNow(key, hash, keySignature);
    }

    /// @dev Returns the storage key used to identify a session key in the validity mapping.
    function _keyId(bytes memory key) internal pure returns (bytes32) {
        return keccak256(key);
    }

    /**
     * @dev Decodes a session key signature into its ERC-7913 `key` and cryptographic
     * `keySignature` components.
     *
     * The `signature` must be ABI-encoded as `abi.encode(bytes key, bytes keySignature)`.
     *
     * Returns `(false, emptyBytes, emptyBytes)` without reverting if the encoding is invalid
     * or if any offset or length would read out of bounds.
     */
    function _tryDecodeSignature(
        bytes calldata signature
    ) internal pure returns (bool success, bytes calldata key, bytes calldata keySignature) {
        // Minimum length: key offset (32 bytes) + signature offset (32 bytes) + key length (32 bytes) + signature length (32 bytes) = 128 bytes
        if (signature.length < 0x80) return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

        uint256 keyOffset = uint256(bytes32(signature[0x00:0x20]));
        uint256 signatureOffset = uint256(bytes32(signature[0x20:0x40]));

        uint256 keyDataOffset = keyOffset + 0x20;
        uint256 signatureDataOffset = signatureOffset + 0x20;

        if (keyDataOffset > signature.length || signatureDataOffset > signature.length)
            return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

        uint256 keyLength = uint256(bytes32(signature[keyOffset:keyDataOffset]));
        uint256 signatureLength = uint256(bytes32(signature[signatureOffset:signatureDataOffset]));

        if (keyDataOffset + keyLength > signature.length || signatureDataOffset + signatureLength > signature.length)
            return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

        assembly ("memory-safe") {
            key.offset := add(signature.offset, keyDataOffset)
            key.length := keyLength
            keySignature.offset := add(signature.offset, signatureDataOffset)
            keySignature.length := signatureLength
        }

        return (true, key, keySignature);
    }

    /**
     * @dev Decodes the initialization data for the session keys module.
     *
     * The `initData` must be ABI-encoded as `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)`
     * where each array has the same length.
     *
     * Requirements:
     *
     * * `initData` must be at least 192 bytes (6 × 32 bytes for the 3 ABI offsets and 3 array lengths).
     * * All offsets must point within the `initData` bounds.
     *
     * Reverts with {ERC7579SessionKeyssInvalidInitData} if the encoding is invalid.
     */
    function _decodeKeysInitData(
        bytes calldata initData
    ) internal pure returns (bytes[] calldata keys_, uint48[] calldata starts, uint48[] calldata ends) {
        // Minimum length:
        // keys offset (32 bytes) + starts offset (32 bytes) + ends offset (32 bytes) +
        // keys length (32 bytes) + starts length (32 bytes) + ends length (32 bytes) = 192 bytes
        require(initData.length > 0xbf, ERC7579SessionKeyssInvalidInitData());

        return (
            _decodeKeysInitDataKeys(initData),
            _decodeKeysInitDataStarts(initData),
            _decodeKeysInitDataEnds(initData)
        );
    }

    function _decodeKeysInitDataKeys(bytes calldata initData) private pure returns (bytes[] calldata keys_) {
        uint256 keysOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 keysDataOffset = keysOffset + 0x20;
        require(keysDataOffset <= initData.length, ERC7579SessionKeyssInvalidInitData());
        uint256 keysLength = uint256(bytes32(initData[keysOffset:keysDataOffset]));
        require(keysDataOffset + keysLength * 0x20 <= initData.length, ERC7579SessionKeyssInvalidInitData());
        assembly ("memory-safe") {
            keys_.offset := add(initData.offset, keysDataOffset)
            keys_.length := keysLength
        }
        return keys_;
    }

    function _decodeKeysInitDataStarts(bytes calldata initData) private pure returns (uint48[] calldata starts) {
        uint256 startsOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 startsDataOffset = startsOffset + 0x20;
        require(startsDataOffset <= initData.length, ERC7579SessionKeyssInvalidInitData());
        uint256 startsLength = uint256(bytes32(initData[startsOffset:startsDataOffset]));
        require(startsDataOffset + startsLength * 0x20 <= initData.length, ERC7579SessionKeyssInvalidInitData());
        assembly ("memory-safe") {
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
        }
        return starts;
    }

    function _decodeKeysInitDataEnds(bytes calldata initData) private pure returns (uint48[] calldata ends) {
        uint256 endsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 endsDataOffset = endsOffset + 0x20;
        require(endsDataOffset <= initData.length, ERC7579SessionKeyssInvalidInitData());
        uint256 endsLength = uint256(bytes32(initData[endsOffset:endsDataOffset]));
        require(endsDataOffset + endsLength * 0x20 <= initData.length, ERC7579SessionKeyssInvalidInitData());
        assembly ("memory-safe") {
            ends.offset := add(initData.offset, endsDataOffset)
            ends.length := endsLength
        }
        return ends;
    }
}
