// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC8043Utils} from "../../src/utils/ERC8043Utils.sol";

contract ERC8043UtilsTest is Test {
    /// @dev External shim so that calldata slices flow into `ERC8043Utils.tryDecodeInitMode`.
    function tryDecodeInitMode(
        bytes calldata data
    )
        external
        pure
        returns (
            bool valid,
            uint256[] calldata moduleTypeIds,
            address[] calldata modules,
            bytes[] calldata initDatas,
            bytes calldata installationSignature
        )
    {
        return ERC8043Utils.tryDecodeInitMode(data);
    }

    /// @dev Same as {tryDecodeInitMode}, without `modules`. See {tryDecodeInitModeModules}.
    function tryDecodeInitModeWithoutModules(
        bytes calldata data
    )
        external
        pure
        returns (
            bool valid,
            uint256[] calldata moduleTypeIds,
            bytes[] calldata initDatas,
            bytes calldata installationSignature
        )
    {
        (valid, moduleTypeIds, , initDatas, installationSignature) = ERC8043Utils.tryDecodeInitMode(data);
    }

    /// @dev Returns the decoded `modules` as raw words so that dirty addresses do not revert on return.
    function tryDecodeInitModeModules(bytes calldata data) external pure returns (uint256[] calldata modules) {
        (, , address[] calldata modules_, , ) = ERC8043Utils.tryDecodeInitMode(data);
        assembly ("memory-safe") {
            modules.offset := modules_.offset
            modules.length := modules_.length
        }
    }

    /// @dev External shim around the standard ABI decoder, used as a reference for `tryDecodeInitMode`.
    /// Decodes `modules` as raw words, since the library does not check address cleanness.
    function abiDecodeInitModeRaw(
        bytes calldata data
    ) external pure returns (uint256[] memory, uint256[] memory, bytes[] memory, bytes memory) {
        return abi.decode(data, (uint256[], uint256[], bytes[], bytes));
    }

    /// @dev External shim so that calldata slices flow into `ERC8043Utils.initModulesStructHash`.
    function initModulesStructHash(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        uint256 nonce
    ) external pure returns (bytes32) {
        return ERC8043Utils.initModulesStructHash(moduleTypeIds, modules, initDatas, nonce);
    }

    /// @dev Reference implementation of the struct hash, used to cross-check the library.
    function _referenceStructHash(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        uint256 nonce
    ) private pure returns (bytes32) {
        bytes32[] memory initDataHashes = new bytes32[](initDatas.length);
        for (uint256 i = 0; i < initDatas.length; i++) {
            initDataHashes[i] = keccak256(initDatas[i]);
        }
        return
            keccak256(
                abi.encode(
                    ERC8043Utils.INIT_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            );
    }

    function testMagicValue() public pure {
        assertEq(ERC8043Utils.INIT_MODE_MAGIC_VALUE, bytes4(0x80438043));
    }

    function testTypehash() public pure {
        assertEq(
            ERC8043Utils.INIT_MODULES_TYPEHASH,
            keccak256("InitModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)")
        );
    }

    function testInitModulesStructHashFuzz(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        uint256 nonce
    ) public view {
        bytes32 expected = _referenceStructHash(moduleTypeIds, modules, initDatas, nonce);
        bytes32 actual = this.initModulesStructHash(moduleTypeIds, modules, initDatas, nonce);
        assertEq(actual, expected);
    }

    function testTryDecodeInitModeValid(uint256 moduleTypeId, address module, bytes memory initData) public view {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = moduleTypeId;
        address[] memory modules = new address[](1);
        modules[0] = module;
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;
        bytes memory installationSignature = hex"deadbeef";

        bytes memory payload = abi.encode(moduleTypeIds, modules, initDatas, installationSignature);

        (
            bool valid,
            uint256[] memory decodedTypeIds,
            address[] memory decodedModules,
            bytes[] memory decodedInitDatas,
            bytes memory decodedSignature
        ) = this.tryDecodeInitMode(payload);

        assertTrue(valid);
        assertEq(decodedTypeIds.length, 1);
        assertEq(decodedTypeIds[0], moduleTypeId);
        assertEq(decodedModules.length, 1);
        assertEq(decodedModules[0], module);
        assertEq(decodedInitDatas.length, 1);
        assertEq(decodedInitDatas[0], initData);
        assertEq(decodedSignature, installationSignature);
    }

    function testTryDecodeInitModeTooShort(uint16 len) public view {
        len = uint16(bound(len, 0, 0xff));
        bytes memory payload = new bytes(len);
        (bool valid, uint256[] memory tids, address[] memory ms, bytes[] memory ids, bytes memory sig) = this
            .tryDecodeInitMode(payload);
        assertFalse(valid);
        assertEq(tids.length, 0);
        assertEq(ms.length, 0);
        assertEq(ids.length, 0);
        assertEq(sig.length, 0);
    }

    function testTryDecodeInitModeEmptyArrays() public view {
        uint256[] memory moduleTypeIds = new uint256[](0);
        address[] memory modules = new address[](0);
        bytes[] memory initDatas = new bytes[](0);

        bytes memory payload = abi.encode(moduleTypeIds, modules, initDatas, bytes(""));

        (bool valid, , , , ) = this.tryDecodeInitMode(payload);
        assertFalse(valid);
    }

    function testTryDecodeInitModeMismatchedLengths() public view {
        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = 1;
        moduleTypeIds[1] = 2;
        address[] memory modules = new address[](1);
        modules[0] = address(0xA);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = "x";

        bytes memory payload = abi.encode(moduleTypeIds, modules, initDatas, bytes(""));

        (bool valid, , , , ) = this.tryDecodeInitMode(payload);
        assertFalse(valid);
    }

    function testTryDecodeInitModeArbitraryData(bytes memory data) public view {
        // Should never revert regardless of input shape; validity is not asserted.
        this.tryDecodeInitMode(data);
    }

    function testTryDecodeInitModeMultipleModules(
        uint256[3] memory moduleTypeIds_,
        address[3] memory modules_,
        bytes memory initData0,
        bytes memory initData1,
        bytes memory initData2,
        bytes memory installationSignature,
        uint8 count
    ) public view {
        count = uint8(bound(count, 2, 3));
        uint256[] memory moduleTypeIds = new uint256[](count);
        address[] memory modules = new address[](count);
        bytes[] memory initDatas = new bytes[](count);
        bytes[3] memory initDatas_ = [initData0, initData1, initData2];
        for (uint256 i = 0; i < count; i++) {
            moduleTypeIds[i] = moduleTypeIds_[i];
            modules[i] = modules_[i];
            initDatas[i] = initDatas_[i];
        }

        _assertDecodesAsAbi(abi.encode(moduleTypeIds, modules, initDatas, installationSignature));
    }

    function testTryDecodeInitModeMultisigThenECDSA() public view {
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(address(0xBEEF));
        bytes memory multisigInitData = abi.encode(signers, uint64(1));
        assertEq(multisigInitData.length, 192);

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = 1;
        moduleTypeIds[1] = 1;
        address[] memory modules = new address[](2);
        modules[0] = address(0x1111);
        modules[1] = address(0x2222);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = multisigInitData;
        initDatas[1] = abi.encodePacked(address(0xCAFE));

        _assertDecodesAsAbi(abi.encode(moduleTypeIds, modules, initDatas, hex"deadbeef"));
    }

    function testTryDecodeInitModeMalformedWords() public view {
        bytes memory payload = _twoModulePayload();
        uint256[4] memory values = [
            type(uint256).max,
            type(uint256).max - 0x1f,
            type(uint256).max / 0x20 + 1,
            2 ** 255
        ];
        // Positions of the array offset and length words in `_twoModulePayload`
        uint256[10] memory positions = [
            uint256(0x00), // moduleTypeIds offset
            0x20, // modules offset
            0x40, // initDatas offset
            0x80, // moduleTypeIds length
            0xe0, // modules length
            0x140, // initDatas length
            0x160, // initDatas[0] relative offset
            0x180, // initDatas[1] relative offset
            0x1a0, // initDatas[0] length
            0x1e0 // initDatas[1] length
        ];

        for (uint256 i = 0; i < positions.length; i++) {
            for (uint256 j = 0; j < values.length; j++) {
                bytes memory malformed = bytes.concat(payload);
                _writeWord(malformed, positions[i], values[j]);
                (bool valid, , , ) = this.tryDecodeInitModeWithoutModules(malformed);
                assertFalse(valid);
            }
        }

        // installationSignature offset and length. Validity does not depend on the signature, so check it is empty.
        uint256[2] memory sigPositions = [uint256(0x60), uint256(_readWord(payload, 0x60))];
        for (uint256 i = 0; i < sigPositions.length; i++) {
            for (uint256 j = 0; j < values.length; j++) {
                bytes memory malformed = bytes.concat(payload);
                _writeWord(malformed, sigPositions[i], values[j]);
                (, , , bytes memory sig) = this.tryDecodeInitModeWithoutModules(malformed);
                assertEq(sig.length, 0);
            }
        }
    }

    function testTryDecodeInitModeCorruptedWord(uint256 position, uint256 value) public view {
        bytes memory payload = _twoModulePayload();
        uint256 sigLengthPosition = uint256(_readWord(payload, 0x60));
        position = bound(position, 0, payload.length / 0x20 - 1) * 0x20;
        _writeWord(payload, position, value);

        // Must not revert. When the result is valid, the standard ABI decoder must accept the payload too,
        // except for a malformed installationSignature, which is returned empty without affecting validity.
        (bool valid, , , ) = this.tryDecodeInitModeWithoutModules(payload);
        if (valid && position != 0x60 && position != sigLengthPosition) _assertDecodesAsAbi(payload);
    }

    function _assertDecodesAsAbi(bytes memory payload) private view {
        (
            uint256[] memory expectedTypeIds,
            uint256[] memory expectedModules,
            bytes[] memory expectedInitDatas,
            bytes memory expectedSignature
        ) = this.abiDecodeInitModeRaw(payload);
        (
            bool valid,
            uint256[] memory decodedTypeIds,
            bytes[] memory decodedInitDatas,
            bytes memory decodedSignature
        ) = this.tryDecodeInitModeWithoutModules(payload);
        uint256[] memory decodedModules = this.tryDecodeInitModeModules(payload);

        assertTrue(valid);
        assertEq(decodedTypeIds, expectedTypeIds);
        assertEq(decodedModules, expectedModules);
        assertEq(decodedInitDatas.length, expectedInitDatas.length);
        for (uint256 i = 0; i < expectedInitDatas.length; i++) {
            assertEq(decodedInitDatas[i], expectedInitDatas[i]);
        }
        assertEq(decodedSignature, expectedSignature);
    }

    function _twoModulePayload() private pure returns (bytes memory) {
        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = 1;
        moduleTypeIds[1] = 2;
        address[] memory modules = new address[](2);
        modules[0] = address(0xA);
        modules[1] = address(0xB);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = "x";
        initDatas[1] = "y";
        return abi.encode(moduleTypeIds, modules, initDatas, hex"deadbeef");
    }

    function _readWord(bytes memory data, uint256 position) private pure returns (bytes32 word) {
        assembly ("memory-safe") {
            word := mload(add(add(data, 0x20), position))
        }
    }

    function _writeWord(bytes memory data, uint256 position, uint256 value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(data, 0x20), position), value)
        }
    }
}
