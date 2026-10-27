// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test, stdError} from "forge-std/Test.sol";
import {EnumerableSetERC4337} from "../../../src/utils/structs/EnumerableSetERC4337.sol";

/// @dev Holds the sets under test so that their storage accesses can be recorded on a single address.
contract EnumerableSetERC4337Holder {
    using EnumerableSetERC4337 for *;

    EnumerableSetERC4337.AddressSet private _addressSet;
    EnumerableSetERC4337.Bytes32Set private _bytes32Set;
    EnumerableSetERC4337.BytesSet private _bytesSet;
    mapping(uint256 installation => EnumerableSetERC4337.BytesSet) private _nestedBytesSets;

    // AddressSet

    function addressSetSlot() external view returns (uint256 slot) {
        EnumerableSetERC4337.AddressSet storage set = _addressSet;
        assembly ("memory-safe") {
            slot := set.slot
        }
    }

    function addAddress(address account, address value) external returns (bool) {
        return _addressSet.add(account, value);
    }

    function removeAddress(address account, address value) external returns (bool) {
        return _addressSet.remove(account, value);
    }

    function clearAddresses(address account) external {
        _addressSet.clear(account);
    }

    function containsAddress(address account, address value) external view returns (bool) {
        return _addressSet.contains(account, value);
    }

    function addressCount(address account) external view returns (uint256) {
        return _addressSet.length(account);
    }

    function addressAt(address account, uint256 index) external view returns (address) {
        return _addressSet.pos(account, index);
    }

    function addresses(address account) external view returns (address[] memory) {
        return _addressSet.values(account);
    }

    function addresses(address account, uint256 start, uint256 end) external view returns (address[] memory) {
        return _addressSet.values(account, start, end);
    }

    // Bytes32Set

    function bytes32SetSlot() external view returns (uint256 slot) {
        EnumerableSetERC4337.Bytes32Set storage set = _bytes32Set;
        assembly ("memory-safe") {
            slot := set.slot
        }
    }

    function addBytes32(address account, bytes32 value) external returns (bool) {
        return _bytes32Set.add(account, value);
    }

    function removeBytes32(address account, bytes32 value) external returns (bool) {
        return _bytes32Set.remove(account, value);
    }

    function clearBytes32s(address account) external {
        _bytes32Set.clear(account);
    }

    function containsBytes32(address account, bytes32 value) external view returns (bool) {
        return _bytes32Set.contains(account, value);
    }

    function bytes32Count(address account) external view returns (uint256) {
        return _bytes32Set.length(account);
    }

    function bytes32At(address account, uint256 index) external view returns (bytes32) {
        return _bytes32Set.pos(account, index);
    }

    function bytes32s(address account) external view returns (bytes32[] memory) {
        return _bytes32Set.values(account);
    }

    function bytes32s(address account, uint256 start, uint256 end) external view returns (bytes32[] memory) {
        return _bytes32Set.values(account, start, end);
    }

    // BytesSet. Installation 0 is the top-level set, any other value is a set nested under that key.

    function bytesSetSlot(uint256 installation) external view returns (uint256 slot) {
        EnumerableSetERC4337.BytesSet storage set = _bytes(installation);
        assembly ("memory-safe") {
            slot := set.slot
        }
    }

    function addBytes(address account, uint256 installation, bytes memory value) external returns (bool) {
        return _bytes(installation).add(account, value);
    }

    function removeBytes(address account, uint256 installation, bytes memory value) external returns (bool) {
        return _bytes(installation).remove(account, value);
    }

    function clearBytes(address account, uint256 installation) external {
        _bytes(installation).clear(account);
    }

    function containsBytes(address account, uint256 installation, bytes memory value) external view returns (bool) {
        return _bytes(installation).contains(account, value);
    }

    function bytesCount(address account, uint256 installation) external view returns (uint256) {
        return _bytes(installation).length(account);
    }

    function bytesAt(address account, uint256 installation, uint256 index) external view returns (bytes memory) {
        return _bytes(installation).pos(account, index);
    }

    function bytesValues(address account, uint256 installation) external view returns (bytes[] memory) {
        return _bytes(installation).values(account);
    }

    function bytesValues(
        address account,
        uint256 installation,
        uint256 start,
        uint256 end
    ) external view returns (bytes[] memory) {
        return _bytes(installation).values(account, start, end);
    }

    function _bytes(uint256 installation) private view returns (EnumerableSetERC4337.BytesSet storage) {
        if (installation == 0) return _bytesSet;
        return _nestedBytesSets[installation];
    }
}

contract EnumerableSetERC4337Test is Test {
    // Lengths of the values in the `BytesSet` fuzzing universe. See {_universeValue}.
    uint256 private constant UNIVERSE_SIZE = 8;
    // Maximum number of chunks of a value in the universe (300 bytes)
    uint256 private constant UNIVERSE_MAX_CHUNKS = 10;
    // Slots of a `BytesSet` window: the length and 127 chunks
    uint256 private constant WINDOW_SIZE = 128;

    // Maximum number of operations of a fuzzed sequence
    uint256 private constant MAX_OPS = 32;

    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);

    EnumerableSetERC4337Holder private _holder;

    // Reference model of the `BytesSet` fuzzing: universe indexes per account and installation, in set order.
    mapping(address account => mapping(uint256 installation => uint256[])) private _model;

    function setUp() public {
        _holder = new EnumerableSetERC4337Holder();
    }

    // AddressSet

    function testAddressSetAddContainsLength() public {
        assertEq(_holder.addressCount(ALICE), 0);
        assertFalse(_holder.containsAddress(ALICE, address(1)));

        assertTrue(_holder.addAddress(ALICE, address(1)));
        assertFalse(_holder.addAddress(ALICE, address(1)));
        assertTrue(_holder.addAddress(ALICE, address(2)));

        assertEq(_holder.addressCount(ALICE), 2);
        assertTrue(_holder.containsAddress(ALICE, address(1)));
        assertTrue(_holder.containsAddress(ALICE, address(2)));
        assertFalse(_holder.containsAddress(ALICE, address(3)));
        assertEq(_holder.addressAt(ALICE, 0), address(1));
        assertEq(_holder.addressAt(ALICE, 1), address(2));

        address[] memory values = _holder.addresses(ALICE);
        assertEq(values.length, 2);
        assertEq(values[0], address(1));
        assertEq(values[1], address(2));
    }

    function testAddressSetRemove() public {
        _holder.addAddress(ALICE, address(1));
        _holder.addAddress(ALICE, address(2));
        _holder.addAddress(ALICE, address(3));

        assertFalse(_holder.removeAddress(ALICE, address(4)));
        assertTrue(_holder.removeAddress(ALICE, address(1)));
        assertFalse(_holder.removeAddress(ALICE, address(1)));

        // Swap and pop: the last value takes the place of the removed one.
        address[] memory values = _holder.addresses(ALICE);
        assertEq(values.length, 2);
        assertEq(values[0], address(3));
        assertEq(values[1], address(2));
        assertFalse(_holder.containsAddress(ALICE, address(1)));

        // Re-adding a removed value appends it.
        assertTrue(_holder.addAddress(ALICE, address(1)));
        assertEq(_holder.addressAt(ALICE, 2), address(1));
    }

    function testAddressSetClear() public {
        _holder.addAddress(ALICE, address(1));
        _holder.addAddress(ALICE, address(2));
        _holder.addAddress(BOB, address(1));

        _holder.clearAddresses(ALICE);
        assertEq(_holder.addressCount(ALICE), 0);
        assertFalse(_holder.containsAddress(ALICE, address(1)));
        assertFalse(_holder.containsAddress(ALICE, address(2)));
        assertEq(_holder.addresses(ALICE).length, 0);
        assertEq(_holder.addressCount(BOB), 1);
        assertTrue(_holder.containsAddress(BOB, address(1)));

        assertTrue(_holder.addAddress(ALICE, address(2)));
        assertEq(_holder.addressAt(ALICE, 0), address(2));
    }

    function testAddressSetPagination() public {
        for (uint160 i = 1; i <= 5; ++i) _holder.addAddress(ALICE, address(i));

        address[] memory slice = _holder.addresses(ALICE, 1, 3);
        assertEq(slice.length, 2);
        assertEq(slice[0], address(2));
        assertEq(slice[1], address(3));

        assertEq(_holder.addresses(ALICE, 3, type(uint256).max).length, 2);
        assertEq(_holder.addresses(ALICE, 4, 2).length, 0);
        assertEq(_holder.addresses(ALICE, 10, 20).length, 0);
        assertEq(_holder.addresses(ALICE, 0, type(uint256).max).length, 5);
    }

    function testAddressSetPosOutOfBounds() public {
        _holder.addAddress(ALICE, address(1));
        vm.expectRevert(stdError.indexOOBError);
        _holder.addressAt(ALICE, 1);
        vm.expectRevert(stdError.indexOOBError);
        _holder.addressAt(BOB, 0);
    }

    // Bytes32Set

    function testBytes32SetAddRemove() public {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        bytes32 c = keccak256("c");

        assertTrue(_holder.addBytes32(ALICE, a));
        assertTrue(_holder.addBytes32(ALICE, b));
        assertTrue(_holder.addBytes32(ALICE, c));
        assertFalse(_holder.addBytes32(ALICE, b));
        assertEq(_holder.bytes32Count(ALICE), 3);

        assertTrue(_holder.removeBytes32(ALICE, a));
        assertFalse(_holder.removeBytes32(ALICE, a));
        bytes32[] memory values = _holder.bytes32s(ALICE);
        assertEq(values.length, 2);
        assertEq(values[0], c);
        assertEq(values[1], b);

        // Removing the last value doesn't move any other.
        assertTrue(_holder.removeBytes32(ALICE, b));
        assertEq(_holder.bytes32At(ALICE, 0), c);
        assertEq(_holder.bytes32Count(ALICE), 1);

        // Zero is a valid value.
        assertTrue(_holder.addBytes32(ALICE, bytes32(0)));
        assertTrue(_holder.containsBytes32(ALICE, bytes32(0)));

        bytes32[] memory slice = _holder.bytes32s(ALICE, 1, 2);
        assertEq(slice.length, 1);
        assertEq(slice[0], bytes32(0));

        _holder.clearBytes32s(ALICE);
        assertEq(_holder.bytes32Count(ALICE), 0);
        assertFalse(_holder.containsBytes32(ALICE, c));
        assertFalse(_holder.containsBytes32(ALICE, bytes32(0)));

        vm.expectRevert(stdError.indexOOBError);
        _holder.bytes32At(ALICE, 0);
    }

    function testFuzzBytes32Set(uint8[] memory ops) public {
        _boundOps(ops);
        bytes32[] memory model = new bytes32[](ops.length);
        uint256 modelLength = 0;

        for (uint256 i = 0; i < ops.length; ++i) {
            bytes32 value = bytes32(uint256(ops[i] % 16));
            bool isAdd = ops[i] < 128;

            // Model
            uint256 position = 0;
            for (uint256 j = 0; j < modelLength; ++j) {
                if (model[j] == value) position = j + 1;
            }

            if (isAdd) {
                assertEq(_holder.addBytes32(ALICE, value), position == 0);
                if (position == 0) model[modelLength++] = value;
            } else {
                assertEq(_holder.removeBytes32(ALICE, value), position != 0);
                if (position != 0) model[position - 1] = model[--modelLength];
            }

            bytes32[] memory values = _holder.bytes32s(ALICE);
            assertEq(values.length, modelLength);
            for (uint256 j = 0; j < modelLength; ++j) {
                assertEq(values[j], model[j]);
                assertTrue(_holder.containsBytes32(ALICE, model[j]));
            }
        }
        assertEq(_holder.bytes32Count(BOB), 0);
    }

    // BytesSet

    function testBytesSetAddRemove() public {
        bytes memory a = _universeValue(1);
        bytes memory b = _universeValue(4);
        bytes memory c = _universeValue(6);

        assertTrue(_holder.addBytes(ALICE, 0, a));
        assertTrue(_holder.addBytes(ALICE, 0, b));
        assertTrue(_holder.addBytes(ALICE, 0, c));
        assertFalse(_holder.addBytes(ALICE, 0, b));
        assertEq(_holder.bytesCount(ALICE, 0), 3);
        assertTrue(_holder.containsBytes(ALICE, 0, a));
        assertFalse(_holder.containsBytes(ALICE, 0, _universeValue(2)));

        assertTrue(_holder.removeBytes(ALICE, 0, a));
        assertFalse(_holder.removeBytes(ALICE, 0, a));
        bytes[] memory values = _holder.bytesValues(ALICE, 0);
        assertEq(values.length, 2);
        assertEq(values[0], c);
        assertEq(values[1], b);

        bytes[] memory slice = _holder.bytesValues(ALICE, 0, 1, type(uint256).max);
        assertEq(slice.length, 1);
        assertEq(slice[0], b);
        assertEq(_holder.bytesValues(ALICE, 0, 2, 1).length, 0);

        vm.expectRevert(stdError.indexOOBError);
        _holder.bytesAt(ALICE, 0, 2);

        _holder.clearBytes(ALICE, 0);
        assertEq(_holder.bytesCount(ALICE, 0), 0);
        assertFalse(_holder.containsBytes(ALICE, 0, b));
        assertFalse(_holder.containsBytes(ALICE, 0, c));
        _assertCleanWindows(ALICE, 0, 3);
    }

    function testBytesSetStorageForms() public {
        uint256 p = _holder.bytesSetSlot(0);

        // Values shorter than 32 bytes take a single slot: the data left-aligned and `length * 2` in the lowest byte
        uint256[4] memory shortLengths = [uint256(0), 1, 20, 31];
        for (uint256 i = 0; i < shortLengths.length; ++i) {
            bytes memory value = _filledBytes(shortLengths[i], 0xab);
            _holder.addBytes(BOB, i, value);
            uint256 base = _windowSlot(BOB, _holder.bytesSetSlot(i), 0);
            uint256 expected = (shortLengths[i] == 0 ? 0 : uint256(bytes32(value))) | (shortLengths[i] * 2);
            assertEq(uint256(vm.load(address(_holder), bytes32(base))), expected);
            assertEq(vm.load(address(_holder), bytes32(base + 1)), bytes32(0));
            assertEq(_holder.bytesAt(BOB, i, 0), value);
        }

        // Longer values store `length * 2 + 1` followed by the zero-padded chunks
        bytes memory long = _filledBytes(33, 0xcd);
        _holder.addBytes(ALICE, 0, long);
        uint256 longBase = _windowSlot(ALICE, p, 0);
        assertEq(uint256(vm.load(address(_holder), bytes32(longBase))), 33 * 2 + 1);
        assertEq(vm.load(address(_holder), bytes32(longBase + 1)), bytes32(_filledBytes(32, 0xcd)));
        assertEq(vm.load(address(_holder), bytes32(longBase + 2)), bytes32(uint256(0xcd) << 248));

        // Moving a short value over a long one clears the long value's chunks
        bytes memory short = _filledBytes(20, 0xef);
        _holder.addBytes(ALICE, 0, short);
        _holder.removeBytes(ALICE, 0, long);
        assertEq(_holder.bytesAt(ALICE, 0, 0), short);
        assertEq(vm.load(address(_holder), bytes32(longBase + 1)), bytes32(0));
        assertEq(vm.load(address(_holder), bytes32(longBase + 2)), bytes32(0));
        _assertCleanWindows(ALICE, 0, 3);

        // Moving a long value over a short one writes the long form
        _holder.addBytes(ALICE, 0, long);
        _holder.removeBytes(ALICE, 0, short);
        assertEq(_holder.bytesAt(ALICE, 0, 0), long);
        assertEq(uint256(vm.load(address(_holder), bytes32(longBase))), 33 * 2 + 1);
        _assertCleanWindows(ALICE, 0, 3);
    }

    function testBytesSetLengths() public {
        uint256[8] memory lengths = [uint256(0), 1, 31, 32, 33, 84, 4063, 4064];
        for (uint256 i = 0; i < lengths.length; ++i) {
            bytes memory value = _pattern(i, lengths[i]);
            assertTrue(_holder.addBytes(ALICE, 0, value));
            assertTrue(_holder.containsBytes(ALICE, 0, value));
            assertEq(_holder.bytesAt(ALICE, 0, i), value);
        }

        bytes[] memory values = _holder.bytesValues(ALICE, 0);
        assertEq(values.length, lengths.length);
        for (uint256 i = 0; i < lengths.length; ++i) {
            assertEq(values[i], _pattern(i, lengths[i]));
        }

        // Moving the longest value over the shortest and the other way around
        assertTrue(_holder.removeBytes(ALICE, 0, _pattern(0, 0)));
        assertEq(_holder.bytesAt(ALICE, 0, 0), _pattern(7, 4064));
        assertTrue(_holder.removeBytes(ALICE, 0, _pattern(7, 4064)));
        assertEq(_holder.bytesAt(ALICE, 0, 0), _pattern(6, 4063));
        assertTrue(_holder.removeBytes(ALICE, 0, _pattern(6, 4063)));
        assertEq(_holder.bytesAt(ALICE, 0, 0), _pattern(5, 84));
        assertEq(_holder.bytesCount(ALICE, 0), 5);
        _assertCleanWindows(ALICE, 0, WINDOW_SIZE - 1);

        _holder.clearBytes(ALICE, 0);
        _assertCleanWindows(ALICE, 0, WINDOW_SIZE - 1);
    }

    function testBytesSetValueTooLong() public {
        bytes memory value = new bytes(4065);
        vm.expectRevert(abi.encodeWithSelector(EnumerableSetERC4337.EnumerableSetERC4337ValueTooLong.selector, 4065));
        _holder.addBytes(ALICE, 0, value);

        // Values that can't be added are never contained
        assertFalse(_holder.containsBytes(ALICE, 0, value));
        assertFalse(_holder.removeBytes(ALICE, 0, value));
    }

    function testFuzzBytesSetLength(uint256 len, uint256 seed) public {
        len = bound(len, 0, EnumerableSetERC4337.MAX_BYTES_LENGTH + 64);
        bytes memory value = _pattern(seed, len);
        if (len > EnumerableSetERC4337.MAX_BYTES_LENGTH) {
            vm.expectRevert(
                abi.encodeWithSelector(EnumerableSetERC4337.EnumerableSetERC4337ValueTooLong.selector, len)
            );
            _holder.addBytes(ALICE, 0, value);
        } else {
            _holder.addBytes(ALICE, 0, "previous");
            assertTrue(_holder.addBytes(ALICE, 0, value));
            assertEq(_holder.bytesAt(ALICE, 0, 1), value);
            assertTrue(_holder.removeBytes(ALICE, 0, "previous"));
            assertEq(_holder.bytesAt(ALICE, 0, 0), value);
            _assertCleanWindows(ALICE, 0, (len + 31) / 32 + 1);
        }
    }

    function testBytesSetAccountIsolation() public {
        bytes memory a = _universeValue(3);
        bytes memory b = _universeValue(5);

        _holder.addBytes(ALICE, 0, a);
        _holder.addBytes(BOB, 0, b);
        _holder.addBytes(BOB, 0, a);

        assertEq(_holder.bytesCount(ALICE, 0), 1);
        assertEq(_holder.bytesCount(BOB, 0), 2);
        assertFalse(_holder.containsBytes(ALICE, 0, b));
        assertEq(_holder.bytesAt(BOB, 0, 0), b);

        assertTrue(_holder.removeBytes(BOB, 0, a));
        assertTrue(_holder.containsBytes(ALICE, 0, a));
        assertEq(_holder.bytesAt(ALICE, 0, 0), a);

        _holder.clearBytes(BOB, 0);
        assertEq(_holder.bytesCount(ALICE, 0), 1);
        assertEq(_holder.bytesAt(ALICE, 0, 0), a);
    }

    function testBytesSetNested() public {
        bytes memory a = _universeValue(3);
        bytes memory b = _universeValue(5);

        _holder.addBytes(ALICE, 1, a);
        _holder.addBytes(ALICE, 2, b);

        assertEq(_holder.bytesCount(ALICE, 0), 0);
        assertEq(_holder.bytesCount(ALICE, 1), 1);
        assertEq(_holder.bytesCount(ALICE, 2), 1);
        assertTrue(_holder.containsBytes(ALICE, 1, a));
        assertFalse(_holder.containsBytes(ALICE, 1, b));
        assertEq(_holder.bytesAt(ALICE, 2, 0), b);

        _holder.clearBytes(ALICE, 1);
        assertEq(_holder.bytesCount(ALICE, 1), 0);
        assertEq(_holder.bytesAt(ALICE, 2, 0), b);
    }

    /// @dev Fuzz add/remove/clear sequences on two accounts and two installations against a reference model.
    function testFuzzBytesSet(uint8[] memory ops) public {
        _boundOps(ops);
        for (uint256 i = 0; i < ops.length; ++i) {
            (address account, uint256 installation, uint256 k, uint256 op) = _decodeOp(ops[i]);
            bytes memory value = _universeValue(k);
            uint256[] storage model = _model[account][installation];

            uint256 position = 0;
            for (uint256 j = 0; j < model.length; ++j) {
                if (model[j] == k) position = j + 1;
            }

            if (op == 0) {
                // Clear, rarely
                _holder.clearBytes(account, installation);
                delete _model[account][installation];
            } else if (op < 4) {
                assertEq(_holder.addBytes(account, installation, value), position == 0);
                if (position == 0) model.push(k);
            } else {
                assertEq(_holder.removeBytes(account, installation, value), position != 0);
                if (position != 0) {
                    model[position - 1] = model[model.length - 1];
                    model.pop();
                }
            }

            _assertModel(account, installation);
        }
        _assertModel(ALICE, 0);
        _assertModel(ALICE, 1);
        _assertModel(BOB, 0);
        _assertModel(BOB, 1);
    }

    // ERC-7562 association

    /// @dev Every slot accessed by an `AddressSet` operation is `keccak256(account || x)` for a layout `x`.
    function testAssociationAddressSet() public {
        uint256 p = _holder.addressSetSlot();
        bytes32[] memory keys = new bytes32[](3);
        for (uint256 i = 0; i < keys.length; ++i) keys[i] = bytes32(uint256(i + 1));

        for (uint256 i = 0; i < keys.length; ++i) {
            vm.record();
            _holder.addAddress(ALICE, address(bytes20(keys[i] << 96)));
            _assertAssociated(ALICE, p, keys, 1);
        }
        vm.record();
        _holder.containsAddress(ALICE, address(1));
        _holder.addressAt(ALICE, 1);
        _holder.addresses(ALICE);
        _assertAssociated(ALICE, p, keys, 1);

        vm.record();
        _holder.removeAddress(ALICE, address(1));
        _assertAssociated(ALICE, p, keys, 1);

        vm.record();
        _holder.clearAddresses(ALICE);
        _assertAssociated(ALICE, p, keys, 1);
    }

    /// @dev Same as {testAssociationAddressSet} for a `Bytes32Set`.
    function testAssociationBytes32Set() public {
        uint256 p = _holder.bytes32SetSlot();
        bytes32[] memory keys = new bytes32[](3);
        for (uint256 i = 0; i < keys.length; ++i) keys[i] = keccak256(abi.encode(i));

        for (uint256 i = 0; i < keys.length; ++i) {
            vm.record();
            _holder.addBytes32(ALICE, keys[i]);
            _assertAssociated(ALICE, p, keys, 1);
        }
        vm.record();
        _holder.containsBytes32(ALICE, keys[0]);
        _holder.bytes32At(ALICE, 2);
        _holder.bytes32s(ALICE, 0, 2);
        _assertAssociated(ALICE, p, keys, 1);

        vm.record();
        _holder.removeBytes32(ALICE, keys[0]);
        _assertAssociated(ALICE, p, keys, 1);

        vm.record();
        _holder.clearBytes32s(ALICE);
        _assertAssociated(ALICE, p, keys, 1);
    }

    /// @dev Every slot accessed by a `BytesSet` operation is `keccak256(account || x) + n`, with `n < 128` for the
    /// values window and `n == 0` otherwise, both top-level and nested under an installation key.
    function testFuzzAssociationBytesSet(uint8[] memory ops) public {
        _boundOps(ops);
        bytes32[] memory keys = new bytes32[](UNIVERSE_SIZE);
        for (uint256 k = 0; k < UNIVERSE_SIZE; ++k) keys[k] = keccak256(_universeValue(k));

        for (uint256 i = 0; i < ops.length; ++i) {
            (address account, uint256 installation, uint256 k, uint256 op) = _decodeOp(ops[i]);
            bytes memory value = _universeValue(k);
            uint256 p = _holder.bytesSetSlot(installation);

            vm.record();
            if (op == 0) {
                _holder.clearBytes(account, installation);
            } else if (op < 4) {
                _holder.addBytes(account, installation, value);
            } else {
                _holder.removeBytes(account, installation, value);
            }
            _holder.containsBytes(account, installation, value);
            _holder.bytesValues(account, installation);
            _assertAssociated(account, p, keys, WINDOW_SIZE);
        }
    }

    /// @dev The longest value uses the full window: the length at `n == 0` and the last chunk at `n == 127`.
    function testAssociationBytesSetMaxLength() public {
        bytes32[] memory keys = new bytes32[](2);
        bytes memory longest = _pattern(1, EnumerableSetERC4337.MAX_BYTES_LENGTH);
        keys[0] = keccak256("short");
        keys[1] = keccak256(longest);

        for (uint256 installation = 0; installation < 2; ++installation) {
            uint256 p = _holder.bytesSetSlot(installation);

            vm.record();
            _holder.addBytes(ALICE, installation, "short");
            _holder.addBytes(ALICE, installation, longest);
            _holder.removeBytes(ALICE, installation, "short");
            _holder.bytesAt(ALICE, installation, 0);
            _holder.clearBytes(ALICE, installation);
            (, bytes32[] memory writes) = _assertAssociated(ALICE, p, keys, WINDOW_SIZE);

            // The last chunk of the longest value at index 0 was written at the end of its window
            uint256 base = _windowSlot(ALICE, p, 0);
            bool found = false;
            for (uint256 i = 0; i < writes.length; ++i) {
                if (uint256(writes[i]) == base + WINDOW_SIZE - 1) found = true;
            }
            assertTrue(found);
        }
    }

    /// @dev The slots of a set nested under an installation key are derived from the installation, so that the
    /// account is still the first word of the keccak preimage.
    function testNestedSlotDerivation(uint256 installation) public view {
        installation = bound(installation, 1, type(uint256).max);
        // `_nestedBytesSets` is the 4th state variable of the holder, after 3 sets of 3 slots each.
        uint256 mappingSlot = 9;
        assertEq(_holder.bytesSetSlot(0), 6);
        assertEq(_holder.bytesSetSlot(installation), uint256(keccak256(abi.encode(installation, mappingSlot))));
    }

    // Helpers

    /**
     * @dev Asserts that every slot read or written on the holder since the last `vm.record()` is
     * `keccak256(account || x) + n` for some `x` derived from the layout of the set at slot `p`:
     *
     * - `x = p` with `n == 0` (length),
     * - `x = keccak256(index || p + 1)` with `n < window` (values), for any index below the maximum length,
     * - `x = keccak256(key || p + 2)` with `n == 0` (positions), for every `key` in `keys`.
     */
    function _assertAssociated(
        address account,
        uint256 p,
        bytes32[] memory keys,
        uint256 window
    ) private view returns (bytes32[] memory reads, bytes32[] memory writes) {
        (reads, writes) = vm.accesses(address(_holder));
        assertGt(reads.length, 0);
        for (uint256 i = 0; i < reads.length; ++i) {
            assertTrue(_isAssociated(uint256(reads[i]), account, p, keys, window), "read not associated");
        }
        for (uint256 i = 0; i < writes.length; ++i) {
            assertTrue(_isAssociated(uint256(writes[i]), account, p, keys, window), "write not associated");
        }
    }

    function _isAssociated(
        uint256 slot,
        address account,
        uint256 p,
        bytes32[] memory keys,
        uint256 window
    ) private pure returns (bool) {
        if (slot == _associated(account, p)) return true;
        for (uint256 i = 0; i < keys.length; ++i) {
            if (slot == _associated(account, uint256(keccak256(abi.encode(keys[i], p + 2))))) return true;
        }
        // The maximum length of any set in the tests is the number of keys
        for (uint256 index = 0; index < keys.length; ++index) {
            uint256 base = _windowSlot(account, p, index);
            if (slot >= base && slot - base < window) return true;
        }
        return false;
    }

    /// @dev `keccak256(account || x)`, the slot of `account` in a mapping at slot `x`.
    function _associated(address account, uint256 x) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(account, x)));
    }

    /// @dev First slot of the window (or the slot of the value) at `index` for `account` in a set at slot `p`.
    function _windowSlot(address account, uint256 p, uint256 index) private pure returns (uint256) {
        return _associated(account, uint256(keccak256(abi.encode(index, p + 1))));
    }

    /// @dev Asserts that the `BytesSet` of `account` under `installation` matches the reference model.
    function _assertModel(address account, uint256 installation) private view {
        uint256[] storage model = _model[account][installation];
        assertEq(_holder.bytesCount(account, installation), model.length);

        bytes[] memory values = _holder.bytesValues(account, installation);
        assertEq(values.length, model.length);
        for (uint256 j = 0; j < model.length; ++j) {
            assertEq(values[j], _universeValue(model[j]));
            assertEq(_holder.bytesAt(account, installation, j), values[j]);
        }

        for (uint256 k = 0; k < UNIVERSE_SIZE; ++k) {
            bool expected = false;
            for (uint256 j = 0; j < model.length; ++j) {
                if (model[j] == k) expected = true;
            }
            assertEq(_holder.containsBytes(account, installation, _universeValue(k)), expected);
        }

        _assertCleanWindows(account, installation, UNIVERSE_MAX_CHUNKS);
    }

    /**
     * @dev Asserts that the slots of the windows of the `BytesSet` of `account` under `installation` past each
     * value are zero, up to `maxChunks` chunks, and that the windows at the 2 indexes past its length are empty.
     */
    function _assertCleanWindows(address account, uint256 installation, uint256 maxChunks) private view {
        uint256 p = _holder.bytesSetSlot(installation);
        uint256 length = _holder.bytesCount(account, installation);
        for (uint256 index = 0; index < length + 2; ++index) {
            uint256 base = _windowSlot(account, p, index);
            uint256 word = uint256(vm.load(address(_holder), bytes32(base)));
            if (index >= length) assertEq(word, 0);
            // Short form values have no chunks, long form values have `ceil(len / 32)` chunks after the first slot
            uint256 chunks = word & 1 == 0 ? 0 : ((word >> 1) + 31) / 32;
            for (uint256 n = chunks + 1; n <= maxChunks; ++n) {
                assertEq(vm.load(address(_holder), bytes32(base + n)), bytes32(0));
            }
        }
    }

    /// @dev Returns `len` bytes all set to `fill`.
    function _filledBytes(uint256 len, bytes1 fill) private pure returns (bytes memory value) {
        value = new bytes(len);
        for (uint256 i = 0; i < len; ++i) value[i] = fill;
    }

    /// @dev Truncates a fuzzed sequence of operations to {MAX_OPS}.
    function _boundOps(uint8[] memory ops) private pure {
        if (ops.length > MAX_OPS) {
            assembly ("memory-safe") {
                mstore(ops, MAX_OPS)
            }
        }
    }

    /// @dev Decodes a fuzzed operation into an account, an installation, a universe index and an operation kind.
    function _decodeOp(uint8 op) private pure returns (address account, uint256 installation, uint256 k, uint256 kind) {
        account = op & 0x01 == 0 ? ALICE : BOB;
        installation = (op >> 1) & 0x01;
        k = (op >> 2) % UNIVERSE_SIZE;
        uint256 selector = op >> 5;
        // 0 clears (1/64 of the operations), 1 adds (5/8 minus the clears) and 4 removes (3/8)
        if (selector == 0 && k == 0) kind = 0;
        else if (selector < 5) kind = 1;
        else kind = 4;
    }

    /// @dev Value `k` of the `BytesSet` fuzzing universe, with lengths around chunk boundaries.
    function _universeValue(uint256 k) private pure returns (bytes memory) {
        uint256[UNIVERSE_SIZE] memory lengths = [uint256(0), 1, 31, 32, 33, 64, 84, 300];
        return _pattern(k, lengths[k]);
    }

    /// @dev Pseudorandom bytes of length `len` derived from `seed`.
    function _pattern(uint256 seed, uint256 len) private pure returns (bytes memory value) {
        value = new bytes(len);
        for (uint256 i = 0; i < len; i += 32) {
            bytes32 chunk = keccak256(abi.encode(seed, i));
            for (uint256 j = 0; j < 32 && i + j < len; ++j) value[i + j] = chunk[j];
        }
    }
}
