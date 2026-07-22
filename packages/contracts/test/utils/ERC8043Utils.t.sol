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

}
