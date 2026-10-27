// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Panic} from "@openzeppelin/contracts/utils/Panic.sol";

/**
 * @dev Library for managing per-account sets of primitive types whose storage is associated with the account
 * under the [ERC-7562](https://eips.ethereum.org/EIPS/eip-7562) validation rules.
 *
 * During ERC-4337 validation, an unstaked account may only access storage of other contracts in slots
 * associated with it: `keccak256(account || x) + n` with `n < 128`, where `account` is the first 32-byte word of
 * the keccak preimage. This variant of OpenZeppelin's `EnumerableSet` keys every slot by the account as the
 * innermost mapping key, so all of its operations are allowed during validation for that account.
 *
 * Each set holds one independent collection per account. Functions take the `account` explicitly:
 *
 * ```solidity
 * contract Example {
 *     // Declare a set state variable. It can be nested under other keys.
 *     mapping(uint256 installation => EnumerableSetERC4337.BytesSet) private _keys;
 *
 *     function _addKey(address account, uint256 installation, bytes memory key) internal returns (bool) {
 *         return EnumerableSetERC4337.add(_keys[installation], account, key);
 *     }
 * }
 * ```
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 * - Set can be cleared (all elements removed) in O(n).
 *
 * The following types are supported:
 *
 * - `bytes32` (`Bytes32Set`)
 * - `address` (`AddressSet`)
 * - `bytes` (`BytesSet`), up to {MAX_BYTES_LENGTH} bytes per value.
 *
 * The storage layout of a set at slot `p` is:
 *
 * - `p + 0`: `mapping(address account => uint256) length`.
 * - `p + 1`: `mapping(uint256 index => mapping(address account => T)) values`.
 * - `p + 2`: `mapping(T value => mapping(address account => uint256)) positions`, keyed by `keccak256(value)`
 * for `BytesSet`. A position is the index of the value plus 1, and 0 means the value is not in the set.
 *
 * Every slot is `keccak256(account || x) + n`, where `x` is `p` for the length, `keccak256(index || p + 1)` for
 * the values and `keccak256(value || p + 2)` for the positions. `n` is 0, except for `BytesSet` values (see below).
 * Since `p` can be any slot, sets can be nested in other mappings, arrays or structs (e.g. under an installation
 * nonce) and remain associated with the account.
 *
 * A `bytes` value would normally keep data of 32 bytes or more at `keccak256(slot) + j`, which is not associated
 * with the account. Instead, `BytesSet` stores each value inline in a window of 128 consecutive slots starting at
 * its associated base slot `X = keccak256(account || keccak256(index || p + 1))`: the length at `X` and the data
 * in 32-byte chunks at `X + 1` to `X + 127`, with the last chunk zero-padded. Windows of different indexes and
 * accounts start at unrelated hashes, so they do not overlap. Slots of a window past the last chunk are zero, and
 * so are the windows at indexes not lower than the length of the set.
 *
 * > [!NOTE]
 * > Values are only associated with the `account` they are stored for. Reading or writing another account's set
 * > during the validation of a user operation is not allowed under ERC-7562.
 *
 * > [!WARNING]
 * > Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * > unusable. Use {clear} to remove all elements of an account's set, or create a fresh instance using a mapping
 * > of sets (e.g. keyed by an installation nonce).
 */
library EnumerableSetERC4337 {
    /// @dev Maximum length of a `BytesSet` value: 127 chunks of 32 bytes after the length slot of its window.
    uint256 internal constant MAX_BYTES_LENGTH = 4064;

    /// @dev The `length` of a value added to a `BytesSet` exceeds {MAX_BYTES_LENGTH}.
    error EnumerableSetERC4337ValueTooLong(uint256 length);

    // To implement this library for multiple types with as little code repetition as possible, we write it in
    // terms of a generic Set type with bytes32 values, as in {EnumerableSet}. `BytesSet` uses its own storage
    // since its values don't fit in a single slot.

    struct Set {
        // Number of values in the set
        mapping(address account => uint256) _length;
        // Storage of set values
        mapping(uint256 index => mapping(address account => bytes32)) _values;
        // Position is the index of the value plus 1. Position 0 is used to mean a value is not in the set.
        mapping(bytes32 value => mapping(address account => uint256)) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not already present.
     */
    function _add(Set storage set, address account, bytes32 value) private returns (bool) {
        if (_contains(set, account, value)) return false;
        uint256 index = set._length[account];
        set._values[index][account] = value;
        // The value is stored at `index`, but we add 1 to all indexes and use 0 as a sentinel value
        set._positions[value][account] = index + 1;
        set._length[account] = index + 1;
        return true;
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was present.
     */
    function _remove(Set storage set, address account, bytes32 value) private returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value][account];
        if (position == 0) return false;

        unchecked {
            // Underflow not possible: 1 <= position <= length.
            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._length[account] - 1;

            // To delete an element in O(1), we swap the element to delete with the last one, and then remove
            // the last element (sometimes called as 'swap and pop'). This modifies the order, as noted in {at}.
            if (valueIndex != lastIndex) {
                bytes32 lastValue = set._values[lastIndex][account];
                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex][account] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue][account] = position;
            }

            // Delete the slot where the moved value was stored and the tracked position of the deleted value
            delete set._values[lastIndex][account];
            delete set._positions[value][account];
            set._length[account] = lastIndex;
        }
        return true;
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function _clear(Set storage set, address account) private {
        uint256 len = _length(set, account);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i][account]][account];
            delete set._values[i][account];
        }
        delete set._length[account];
    }

    /// @dev Returns true if the value is in the set. O(1).
    function _contains(Set storage set, address account, bytes32 value) private view returns (bool) {
        return set._positions[value][account] != 0;
    }

    /// @dev Returns the number of values on the set. O(1).
    function _length(Set storage set, address account) private view returns (uint256) {
        return set._length[account];
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the set, and it may change when more
     * values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function _at(Set storage set, address account, uint256 index) private view returns (bytes32) {
        if (index >= _length(set, account)) Panic.panic(Panic.ARRAY_OUT_OF_BOUNDS);
        return set._values[index][account];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set, address account) private view returns (bytes32[] memory) {
        return _values(set, account, 0, type(uint256).max);
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(
        Set storage set,
        address account,
        uint256 start,
        uint256 end
    ) private view returns (bytes32[] memory) {
        unchecked {
            end = Math.min(end, _length(set, account));
            start = Math.min(start, end);

            // Underflow not possible: start <= end.
            uint256 len = end - start;
            bytes32[] memory result = new bytes32[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = set._values[start + i][account];
            }
            return result;
        }
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not already present.
     */
    function add(Bytes32Set storage set, address account, bytes32 value) internal returns (bool) {
        return _add(set._inner, account, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was present.
     */
    function remove(Bytes32Set storage set, address account, bytes32 value) internal returns (bool) {
        return _remove(set._inner, account, value);
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(Bytes32Set storage set, address account) internal {
        _clear(set._inner, account);
    }

    /// @dev Returns true if the value is in the set. O(1).
    function contains(Bytes32Set storage set, address account, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, account, value);
    }

    /// @dev Returns the number of values in the set. O(1).
    function length(Bytes32Set storage set, address account) internal view returns (uint256) {
        return _length(set._inner, account);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the set, and it may change when more
     * values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes32Set storage set, address account, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, account, index);
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set, address account) internal view returns (bytes32[] memory) {
        return _values(set._inner, account);
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(
        Bytes32Set storage set,
        address account,
        uint256 start,
        uint256 end
    ) internal view returns (bytes32[] memory) {
        return _values(set._inner, account, start, end);
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not already present.
     */
    function add(AddressSet storage set, address account, address value) internal returns (bool) {
        return _add(set._inner, account, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was present.
     */
    function remove(AddressSet storage set, address account, address value) internal returns (bool) {
        return _remove(set._inner, account, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(AddressSet storage set, address account) internal {
        _clear(set._inner, account);
    }

    /// @dev Returns true if the value is in the set. O(1).
    function contains(AddressSet storage set, address account, address value) internal view returns (bool) {
        return _contains(set._inner, account, bytes32(uint256(uint160(value))));
    }

    /// @dev Returns the number of values in the set. O(1).
    function length(AddressSet storage set, address account) internal view returns (uint256) {
        return _length(set._inner, account);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the set, and it may change when more
     * values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(AddressSet storage set, address account, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, account, index))));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set, address account) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner, account);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(
        AddressSet storage set,
        address account,
        uint256 start,
        uint256 end
    ) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner, account, start, end);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // BytesSet

    struct BytesSet {
        // Number of values in the set
        mapping(address account => uint256) _length;
        // Storage of set values. Each value is stored inline in its window: the length in the first slot and the
        // data in the next ones. See {_writeWindow}.
        mapping(uint256 index => mapping(address account => bytes32[128] window)) _values;
        // Position is the index of the value plus 1. Position 0 is used to mean a value is not in the set.
        mapping(bytes32 valueHash => mapping(address account => uint256)) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not already present.
     *
     * Requirements:
     *
     * - The length of `value` must not exceed {MAX_BYTES_LENGTH}. Reverts with {EnumerableSetERC4337ValueTooLong}
     * otherwise.
     */
    function add(BytesSet storage set, address account, bytes memory value) internal returns (bool) {
        bytes32 valueHash = keccak256(value);
        if (set._positions[valueHash][account] != 0) return false;
        if (value.length > MAX_BYTES_LENGTH) revert EnumerableSetERC4337ValueTooLong(value.length);

        uint256 index = set._length[account];
        // The window at `index` is empty since `index` is not lower than the length of the set.
        _writeWindow(_window(set, account, index), value, 0);
        // The value is stored at `index`, but we add 1 to all indexes and use 0 as a sentinel value
        set._positions[valueHash][account] = index + 1;
        set._length[account] = index + 1;
        return true;
    }

    /**
     * @dev Removes a value from a set. O(1) in the number of values, linear in the length of the moved value.
     *
     * Returns true if the value was removed from the set, that is if it was present.
     */
    function remove(BytesSet storage set, address account, bytes memory value) internal returns (bool) {
        bytes32 valueHash = keccak256(value);
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[valueHash][account];
        if (position == 0) return false;

        unchecked {
            // Underflow not possible: 1 <= position <= length.
            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._length[account] - 1;
            uint256 lastWindow = _window(set, account, lastIndex);
            // Length of the value stored in the last window, which is removed below
            uint256 lastLength = value.length;

            // Swap and pop, as in {EnumerableSet}. This modifies the order, as noted in {at}.
            if (valueIndex != lastIndex) {
                bytes memory lastValue = _readWindow(lastWindow);
                lastLength = lastValue.length;
                // Move the lastValue to the window of the value to delete, clearing its trailing chunks
                _writeWindow(_window(set, account, valueIndex), lastValue, value.length);
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[keccak256(lastValue)][account] = position;
            }

            // Delete the window where the moved value was stored and the tracked position of the deleted value
            _clearWindow(lastWindow, lastLength);
            delete set._positions[valueHash][account];
            set._length[account] = lastIndex;
        }
        return true;
    }

    /**
     * @dev Removes all the values from a set. O(n) in the total length of the values.
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(BytesSet storage set, address account) internal {
        uint256 len = length(set, account);
        for (uint256 i = 0; i < len; ++i) {
            uint256 window = _window(set, account, i);
            bytes memory value = _readWindow(window);
            delete set._positions[keccak256(value)][account];
            _clearWindow(window, value.length);
        }
        delete set._length[account];
    }

    /// @dev Returns true if the value is in the set. O(1).
    function contains(BytesSet storage set, address account, bytes memory value) internal view returns (bool) {
        return set._positions[keccak256(value)][account] != 0;
    }

    /// @dev Returns the number of values in the set. O(1).
    function length(BytesSet storage set, address account) internal view returns (uint256) {
        return set._length[account];
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1) in the number of values.
     *
     * Note that there are no guarantees on the ordering of values inside the set, and it may change when more
     * values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(BytesSet storage set, address account, uint256 index) internal view returns (bytes memory) {
        if (index >= length(set, account)) Panic.panic(Panic.ARRAY_OUT_OF_BOUNDS);
        return _readWindow(_window(set, account, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(BytesSet storage set, address account) internal view returns (bytes[] memory) {
        return values(set, account, 0, type(uint256).max);
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(
        BytesSet storage set,
        address account,
        uint256 start,
        uint256 end
    ) internal view returns (bytes[] memory) {
        unchecked {
            end = Math.min(end, length(set, account));
            start = Math.min(start, end);

            // Underflow not possible: start <= end.
            uint256 len = end - start;
            bytes[] memory result = new bytes[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = _readWindow(_window(set, account, start + i));
            }
            return result;
        }
    }

    /// @dev Returns the first slot of the window storing the value at `index` of the `account`'s set.
    function _window(BytesSet storage set, address account, uint256 index) private view returns (uint256 slot) {
        bytes32[128] storage window = set._values[index][account];
        assembly ("memory-safe") {
            slot := window.slot
        }
    }

    /**
     * @dev Writes `value` to the window starting at `slot`: its length at `slot` and its data in 32-byte chunks at
     * `slot + 1` onwards, with the last chunk zero-padded. Chunks of a previous value of `previousLength` bytes
     * past the new ones are cleared.
     *
     * The length of `value` must not exceed {MAX_BYTES_LENGTH}, so that every chunk is within the window.
     */
    function _writeWindow(uint256 slot, bytes memory value, uint256 previousLength) private {
        assembly ("memory-safe") {
            let len := mload(value)
            sstore(slot, len)

            // Full chunks
            let fullChunks := shr(5, len)
            for {
                let i := 0
            } lt(i, fullChunks) {
                i := add(i, 1)
            } {
                sstore(add(slot, add(i, 1)), mload(add(value, shl(5, add(i, 1)))))
            }

            // Last partial chunk, keeping its first `rem` bytes only
            let chunks := fullChunks
            let rem := and(len, 0x1f)
            if rem {
                chunks := add(chunks, 1)
                let mask := shl(sub(256, shl(3, rem)), not(0))
                sstore(add(slot, chunks), and(mload(add(value, shl(5, chunks))), mask))
            }

            // Trailing chunks of the previous value
            let previousChunks := shr(5, add(previousLength, 0x1f))
            for {
                let i := add(chunks, 1)
            } iszero(gt(i, previousChunks)) {
                i := add(i, 1)
            } {
                sstore(add(slot, i), 0)
            }
        }
    }

    /// @dev Reads the value stored in the window starting at `slot`. See {_writeWindow}.
    function _readWindow(uint256 slot) private view returns (bytes memory value) {
        assembly ("memory-safe") {
            value := mload(0x40)
            let len := sload(slot)
            mstore(value, len)
            let chunks := shr(5, add(len, 0x1f))
            for {
                let i := 1
            } iszero(gt(i, chunks)) {
                i := add(i, 1)
            } {
                mstore(add(value, shl(5, i)), sload(add(slot, i)))
            }
            // Chunks are zero-padded in storage, so the memory past `len` is clean
            mstore(0x40, add(value, shl(5, add(chunks, 1))))
        }
    }

    /// @dev Clears the window starting at `slot`, which stores a value of `len` bytes. See {_writeWindow}.
    function _clearWindow(uint256 slot, uint256 len) private {
        assembly ("memory-safe") {
            sstore(slot, 0)
            let chunks := shr(5, add(len, 0x1f))
            for {
                let i := 1
            } iszero(gt(i, chunks)) {
                i := add(i, 1)
            } {
                sstore(add(slot, i), 0)
            }
        }
    }
}
