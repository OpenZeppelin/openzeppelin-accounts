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
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";

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
    error ERC7579SessionKeysMismatchedInitDataLengths();

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579SessionKeysInvalidInitData();

    /// @dev The provided `key` is already registered.
    error ERC7579SessionKeysAlreadyRegisteredKey(bytes key);

    /// @dev The provided `key` is not registered.
    error ERC7579SessionKeysNonexistentKey(bytes key);

    /// @dev The resolved validity range `[start, end]` is inverted or exceeds 47 bits.
    error ERC7579SessionKeysInvalidValidity(uint48 start, uint48 end);

    /// @dev Emitted when all session keys are cleared for an account on uninstall.
    event ERC7579SessionKeysCleared(address indexed account);

    /// @dev Emitted when a session key is registered or updated for an account.
    event ERC7579SessionKeysERC7913KeySet(address indexed account, bytes indexed key, uint48 start, uint48 end);

    /// @dev Emitted when a session key is removed from an account.
    event ERC7579SessionKeysERC7913KeyUnset(address indexed account, bytes indexed key);

    /**
     * @dev Validity range for a session key.
     *
     * * `from`: The earliest timepoint at which the key is valid (inclusive).
     * * `until`: The latest timepoint at which the key is valid (inclusive).
     *
     * Both bounds fit in 47 bits (see {ERC4337Utils-BLOCK_RANGE_MASK}), since the highest bit of each
     * ERC-4337 validity field flags block-number ranges.
     */
    struct Validity {
        uint48 from;
        uint48 until;
    }

    mapping(address account => mapping(uint256 installation => EnumerableSet.BytesSet)) private _sessionKeys;
    // The account is the innermost key of mappings read or written during validation, so that their slots are
    // associated with the account (ERC-7562).
    mapping(uint256 installation => mapping(bytes32 keyId => mapping(address account => Validity))) private _validities;

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
        return _validity(account, installation(account), _keyId(key));
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
     * > [!WARNING]
     * > Depending on the `startIdx` and `endIdx`, this operation can copy a large amount
     * > of data to memory, which can be expensive. This is designed for view accessors queried
     * > without gas fees. Using it in state-changing functions may become uncallable if the set
     * > grows too large.
     */
    function keys(address account, uint256 startIdx, uint256 endIdx) public view virtual returns (bytes[] memory) {
        return _keys(account, installation(account), startIdx, endIdx);
    }

    /// @dev Returns the number of registered session keys for an `account`.
    function keyCount(address account) public view virtual returns (uint256) {
        return _keyCount(account, installation(account));
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
     * > [!TIP]
     * > Set `starts[i]` to `0` to activate the key immediately at the current timepoint.
     *
     * > [!TIP]
     * > Set `ends[i]` to `0` to register a key with no expiry (stored as `type(uint48).max >> 1`).
     */
    function onInstall(bytes calldata initData) public virtual {
        (bytes[] calldata keys_, uint48[] calldata starts, uint48[] calldata ends) = _decodeKeysInitData(initData);
        _addKeys(msg.sender, installation(msg.sender), keys_, starts, ends);
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Increments the account's nonce to invalidate all registered session keys.
     *
     * See {IERC7579Module-onUninstall}.
     *
     * > [!NOTE]
     * > This approach avoids unbounded gas costs by not iterating over keys.
     * > Previous key data remains in storage but becomes inaccessible due to the nonce increment.
     * > Upon reinstallation, the module will use a new nonce and ignore old keys.
     */
    function onUninstall(bytes calldata) public virtual {
        _useNonce(msg.sender);
        emit ERC7579SessionKeysCleared(msg.sender);
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
        _addKeys(msg.sender, installation(msg.sender), newKeys, starts, ends);
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
        _removeKeys(msg.sender, installation(msg.sender), oldKeys);
    }

    /// @dev Internal version of {isKey} that receives an `installation_` nonce.
    function _isKey(address account, uint256 installation_, bytes calldata key) internal view virtual returns (bool) {
        return _sessionKeys[account][installation_].contains(key);
    }

    /// @dev Internal version of {validity} that receives an `installation_` nonce.
    function _validity(
        address account,
        uint256 installation_,
        bytes32 keyId
    ) internal view virtual returns (uint48 from, uint48 until) {
        return (_validities[installation_][keyId][account].from, _validities[installation_][keyId][account].until);
    }

    /// @dev Internal version of {isValid} that receives an `installation_` nonce.
    function _isValid(address account, uint256 installation_, bytes calldata key) internal view virtual returns (bool) {
        uint48 timepoint = clock();
        (uint48 from, uint48 until) = _validity(account, installation_, _keyId(key));
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

    /// @dev Internal version of {keyCount} that receives an `installation_` nonce.
    function _keyCount(address account, uint256 installation_) internal view virtual returns (uint256) {
        return _sessionKeys[account][installation_].length();
    }

    /**
     * @dev Internal function to register session keys for an `account`.
     *
     * For each key, stores the ERC-7913 key bytes in the enumerable set and records its
     * validity range. Keys are identified by `keccak256(key)` in the validity mapping.
     *
     * Requirements:
     *
     * * All arrays must have equal length. Reverts with {ERC7579SessionKeysMismatchedInitDataLengths} if not.
     * * Each of `keys_` must not be registered. Reverts with {ERC7579SessionKeysAlreadyRegisteredKey} if it is.
     * * Each resolved range must satisfy `start <= end <= type(uint48).max >> 1`. Reverts with
     *   {ERC7579SessionKeysInvalidValidity} if not.
     *
     * > [!TIP]
     * > Setting `starts[i]` to `0` resolves to the current timepoint.
     *
     * > [!TIP]
     * > Setting `ends[i]` to `0` stores `type(uint48).max >> 1`, meaning no expiry.
     *
     * Emits an {ERC7579SessionKeysERC7913KeySet} event for each key.
     */
    function _addKeys(
        address account,
        uint256 installation_,
        bytes[] calldata keys_,
        uint48[] calldata starts,
        uint48[] calldata ends
    ) internal virtual {
        require(
            keys_.length == starts.length && keys_.length == ends.length,
            ERC7579SessionKeysMismatchedInitDataLengths()
        );
        for (uint256 i = 0; i < keys_.length; ++i) {
            bytes calldata key = keys_[i];
            require(_sessionKeys[account][installation_].add(key), ERC7579SessionKeysAlreadyRegisteredKey(key));
            bytes32 keyId = _keyId(key);
            Validity storage validity_ = _validities[installation_][keyId][account];
            uint48 start = uint48(Math.ternary(starts[i] == 0, clock(), starts[i])); // Safe cast. Both are uint48.
            uint48 end = uint48(Math.ternary(ends[i] == 0, ERC4337Utils.BLOCK_RANGE_MASK, ends[i])); // Safe cast. Both are uint48.
            require(
                start <= end && end <= ERC4337Utils.BLOCK_RANGE_MASK,
                ERC7579SessionKeysInvalidValidity(start, end)
            );
            validity_.from = start;
            validity_.until = end;
            emit ERC7579SessionKeysERC7913KeySet(account, key, start, end);
        }
    }

    /**
     * @dev Internal function to remove session keys from an `account`.
     *
     * Removes the key from the enumerable set and clears its validity range in storage.
     *
     * Requirements:
     *
     * * Each of `keys_` must be registered. Reverts with {ERC7579SessionKeysNonexistentKey} if not.
     *
     * Emits an {ERC7579SessionKeysERC7913KeyUnset} event for each key.
     */
    function _removeKeys(address account, uint256 installation_, bytes[] calldata keys_) internal virtual {
        for (uint256 i = 0; i < keys_.length; ++i) {
            bytes calldata key = keys_[i];
            require(_sessionKeys[account][installation_].remove(key), ERC7579SessionKeysNonexistentKey(key));
            bytes32 keyId = _keyId(key);
            Validity storage validity_ = _validities[installation_][keyId][account];
            validity_.from = 0;
            validity_.until = 0;
            emit ERC7579SessionKeysERC7913KeyUnset(account, key);
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
     * > [!NOTE]
     * > Does not validate the {validity} range.
     */
    function _validateSessionKey(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        return _validateSessionKey(account, installation(account), hash, signature);
    }

    /// @dev Variant of {_validateSessionKey} that receives an `installation_` nonce.
    function _validateSessionKey(
        address account,
        uint256 installation_,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual returns (bool) {
        (bool success, bytes calldata key, bytes calldata keySignature) = _tryDecodeSignature(signature);
        return
            success &&
            _isKey(account, installation_, key) &&
            SignatureChecker.isValidSignatureNow(key, hash, keySignature);
    }

    /// @dev Returns the storage key used to identify a session key in the validity mapping.
    function _keyId(bytes memory key) internal pure virtual returns (bytes32) {
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
    ) internal pure virtual returns (bool success, bytes calldata key, bytes calldata keySignature) {
        // Minimum length: key offset (32 bytes) + signature offset (32 bytes) + key length (32 bytes) + signature length (32 bytes) = 128 bytes
        if (signature.length < 0x80) return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

        unchecked {
            uint256 bufferLength = signature.length;

            uint256 keyOffset = uint256(bytes32(signature[0x00:0x20]));
            uint256 signatureOffset = uint256(bytes32(signature[0x20:0x40]));

            // The length fields must be within the bounds of the buffer. Safe subtraction given `bufferLength >= 0x80`.
            if (keyOffset > bufferLength - 0x20 || signatureOffset > bufferLength - 0x20)
                return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

            // Data is just after the length fields. Cannot overflow given the check above.
            uint256 keyDataOffset = keyOffset + 0x20;
            uint256 signatureDataOffset = signatureOffset + 0x20;

            uint256 keyLength = uint256(bytes32(signature[keyOffset:keyDataOffset]));
            uint256 signatureLength = uint256(bytes32(signature[signatureOffset:signatureDataOffset]));

            // The data must fit within the bounds of the buffer. Safe subtraction given `dataOffset <= bufferLength`.
            if (keyLength > bufferLength - keyDataOffset || signatureLength > bufferLength - signatureDataOffset)
                return (false, Calldata.emptyBytes(), Calldata.emptyBytes());

            assembly ("memory-safe") {
                success := 1 // true
                key.offset := add(signature.offset, keyDataOffset)
                key.length := keyLength
                keySignature.offset := add(signature.offset, signatureDataOffset)
                keySignature.length := signatureLength
            }
        }
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
     * Reverts with {ERC7579SessionKeysInvalidInitData} if the encoding is invalid.
     */
    function _decodeKeysInitData(
        bytes calldata initData
    ) internal pure virtual returns (bytes[] calldata keys_, uint48[] calldata starts, uint48[] calldata ends) {
        // Minimum length:
        // keys offset (32 bytes) + starts offset (32 bytes) + ends offset (32 bytes) +
        // keys length (32 bytes) + starts length (32 bytes) + ends length (32 bytes) = 192 bytes
        require(initData.length > 0xbf, ERC7579SessionKeysInvalidInitData());

        return (
            _decodeKeysInitDataKeys(initData),
            _decodeKeysInitDataStarts(initData),
            _decodeKeysInitDataEnds(initData)
        );
    }

    function _decodeKeysInitDataKeys(bytes calldata initData) private pure returns (bytes[] calldata keys_) {
        uint256 keysOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 keysDataOffset = keysOffset + 0x20;
        require(keysDataOffset <= initData.length, ERC7579SessionKeysInvalidInitData());
        uint256 keysLength = uint256(bytes32(initData[keysOffset:keysDataOffset]));
        require(keysDataOffset + keysLength * 0x20 <= initData.length, ERC7579SessionKeysInvalidInitData());
        assembly ("memory-safe") {
            keys_.offset := add(initData.offset, keysDataOffset)
            keys_.length := keysLength
        }
        return keys_;
    }

    function _decodeKeysInitDataStarts(bytes calldata initData) private pure returns (uint48[] calldata starts) {
        uint256 startsOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 startsDataOffset = startsOffset + 0x20;
        require(startsDataOffset <= initData.length, ERC7579SessionKeysInvalidInitData());
        uint256 startsLength = uint256(bytes32(initData[startsOffset:startsDataOffset]));
        require(startsDataOffset + startsLength * 0x20 <= initData.length, ERC7579SessionKeysInvalidInitData());
        assembly ("memory-safe") {
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
        }
        return starts;
    }

    function _decodeKeysInitDataEnds(bytes calldata initData) private pure returns (uint48[] calldata ends) {
        uint256 endsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 endsDataOffset = endsOffset + 0x20;
        require(endsDataOffset <= initData.length, ERC7579SessionKeysInvalidInitData());
        uint256 endsLength = uint256(bytes32(initData[endsOffset:endsDataOffset]));
        require(endsDataOffset + endsLength * 0x20 <= initData.length, ERC7579SessionKeysInvalidInitData());
        assembly ("memory-safe") {
            ends.offset := add(initData.offset, endsDataOffset)
            ends.length := endsLength
        }
        return ends;
    }
}
