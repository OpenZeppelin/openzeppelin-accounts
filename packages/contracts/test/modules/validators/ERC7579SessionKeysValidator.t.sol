// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579SessionKeysValidator} from "../../../src/modules/validators/ERC7579SessionKeysValidator.sol";
import {ERC7579SessionKeys} from "../../../src/modules/ERC7579SessionKeys.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";

contract ERC7579SessionKeysValidatorMock is ERC7579SessionKeysValidator {}

contract ERC7579SessionKeysValidatorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;

    uint256 private constant MAX_ETH = type(uint128).max;
    uint256 private constant SECP256K1_CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    CallReceiverMock private _target;
    ERC7579SessionKeysValidatorMock private _validator;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        _target = new CallReceiverMock();
        _validator = new ERC7579SessionKeysValidatorMock();
        _factory = new OpenAccountFactory();

        address entrypoint = address(ERC4337Utils.ENTRYPOINT_V09);
        vm.deal(entrypoint, MAX_ETH);
        vm.etch(
            entrypoint,
            vm.readFileBinary(
                string.concat(
                    "packages/contracts/node_modules/hardhat-predeploy/bin/",
                    Strings.toChecksumHexString(entrypoint),
                    ".bytecode"
                )
            )
        );

        // Advance block.timestamp past block.number (both start at 1 in Foundry).
        // This ensures clock() = Time.timestamp() != Time.blockNumber(), so the session
        // key validator consistently selects ValidationRange.TIMESTAMP instead of BLOCK.
        vm.warp(1000);
    }

    function testOnInstall(uint256 privateKey, uint48 start, uint48 end) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        // Ensure [start, end] is a valid, non-empty active range covering the current timestamp
        start = uint48(bound(start, 0, block.timestamp));
        end = uint48(bound(end, block.timestamp, type(uint48).max >> 1));

        address sessionKeyAddr = vm.addr(privateKey);
        bytes memory key = abi.encodePacked(sessionKeyAddr);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory starts = new uint48[](1);
        uint48[] memory ends = new uint48[](1);
        starts[0] = start;
        ends[0] = end;

        vm.prank(address(_account));
        _validator.onInstall(abi.encode(keys, starts, ends));

        assertTrue(_validator.isKey(address(_account), key));
        assertTrue(_validator.isValid(address(_account), key));
        (uint48 retFrom, uint48 retUntil) = _validator.validity(address(_account), key);
        assertEq(retFrom, start == 0 ? uint48(block.timestamp) : start);
        assertEq(retUntil, end);
    }

    function testOnUninstall(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        _installKey(address(_account), key, 0, 0);

        assertTrue(_validator.isKey(address(_account), key));
        uint256 installationBefore = _validator.installation(address(_account));

        vm.prank(address(_account));
        vm.expectEmit(true, false, false, false, address(_validator));
        emit ERC7579SessionKeys.ERC7579SessionKeysCleared(address(_account));
        _validator.onUninstall("");

        assertFalse(_validator.isKey(address(_account), key));
        assertEq(_validator.installation(address(_account)), installationBefore + 1);
    }

    function testAddKeys(uint256 numAdded) public {
        numAdded = bound(numAdded, 1, 10);

        // Start with one key already installed
        bytes memory firstKey = abi.encodePacked(vm.addr(1));
        _installKey(address(_account), firstKey, 0, 0);

        (, bytes[] memory newKeys) = _buildKeys(numAdded, 100);
        uint48[] memory starts = new uint48[](numAdded);
        uint48[] memory ends = new uint48[](numAdded);

        vm.prank(address(_account));
        _validator.addKeys(newKeys, starts, ends);

        for (uint256 i = 0; i < numAdded; i++) {
            assertTrue(_validator.isKey(address(_account), newKeys[i]));
        }
    }

    function testRemoveKeys(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        _installKey(address(_account), key, 0, 0);
        assertTrue(_validator.isKey(address(_account), key));

        bytes[] memory keys = new bytes[](1);
        keys[0] = key;

        vm.prank(address(_account));
        vm.expectEmit(true, true, false, false, address(_validator));
        emit ERC7579SessionKeys.ERC7579SessionKeysERC7913KeyUnset(address(_account), key);
        _validator.removeKeys(keys);

        assertFalse(_validator.isKey(address(_account), key));
    }

    function testIsKey(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        assertFalse(_validator.isKey(address(_account), key));

        _installKey(address(_account), key, 0, 0);
        assertTrue(_validator.isKey(address(_account), key));
    }

    function testIsValidActiveKey(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        // starts=0 → current timestamp (active now), ends=0 → no expiry
        _installKey(address(_account), key, 0, 0);
        assertTrue(_validator.isValid(address(_account), key));
    }

    function testIsValid(uint256 privateKey, uint48 duration) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        duration = uint48(bound(duration, 1, 1000));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        uint48 until = uint48(block.timestamp) + duration;

        _installKey(address(_account), key, uint48(block.timestamp), until);
        assertTrue(_validator.isValid(address(_account), key));

        vm.warp(uint256(until) + 1);
        assertFalse(_validator.isValid(address(_account), key));

        vm.warp(uint256(until) + 1);
        assertFalse(_validator.isValid(address(_account), key));
    }

    function testValidity(uint256 privateKey, uint48 from, uint48 until) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(from > 0 && until > from);

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _installKey(address(_account), key, from, until);

        (uint48 retFrom, uint48 retUntil) = _validator.validity(address(_account), key);
        assertEq(retFrom, from);
        assertEq(retUntil, until);
    }

    function testIsValidSignatureWithSender(bytes32 messageHash, uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        _installKey(address(_account), key, 0, 0);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory sig = abi.encode(key, abi.encodePacked(r, s, v));

        vm.prank(address(_account));
        assertEq(
            _validator.isValidSignatureWithSender(address(this), messageHash, sig),
            IERC1271.isValidSignature.selector
        );
    }

    function testIsValidSignatureWithSenderWrongSigner(
        bytes32 messageHash,
        uint256 correctKey,
        uint256 wrongKey
    ) public {
        correctKey = bound(correctKey, 1, SECP256K1_CURVE_ORDER - 1);
        wrongKey = bound(wrongKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(correctKey != wrongKey);

        bytes memory key = abi.encodePacked(vm.addr(correctKey));
        _installKey(address(_account), key, 0, 0);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, messageHash);
        bytes memory sig = abi.encode(key, abi.encodePacked(r, s, v));

        vm.prank(address(_account));
        assertEq(_validator.isValidSignatureWithSender(address(this), messageHash, sig), bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderExpiredKey(bytes32 messageHash, uint256 privateKey, uint48 duration) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        duration = uint48(bound(duration, 1, 1000));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        uint48 until = uint48(block.timestamp) + duration;
        _installKey(address(_account), key, uint48(block.timestamp), until);

        vm.warp(uint256(until) + 1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory sig = abi.encode(key, abi.encodePacked(r, s, v));

        vm.prank(address(_account));
        assertEq(_validator.isValidSignatureWithSender(address(this), messageHash, sig), bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderFutureKey(bytes32 messageHash, uint256 privateKey, uint48 delay) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        delay = uint48(bound(delay, 1, 1000));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        uint48 from = uint48(block.timestamp) + delay;
        _installKey(address(_account), key, from, from + 3600);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory sig = abi.encode(key, abi.encodePacked(r, s, v));

        vm.prank(address(_account));
        assertEq(_validator.isValidSignatureWithSender(address(this), messageHash, sig), bytes4(0xffffffff));
    }

    function testValidateUserOp(uint256 privateKey, uint256 nonce) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        address sessionKeyAddr = vm.addr(privateKey);
        bytes memory key = abi.encodePacked(sessionKeyAddr);

        _account = _deployAccount(key, 0, 0);
        vm.deal(address(_account), MAX_ETH);

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, 0);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        userOp.signature = abi.encode(key, abi.encodePacked(r, s, v));

        (uint48 from, uint48 until) = _validator.validity(address(_account), key);

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);
        assertEq(result, ERC4337Utils.packValidationData(true, from, until));
    }

    function testValidateUserOpWrongSigner(uint256 correctKey, uint256 wrongKey, uint256 nonce) public {
        correctKey = bound(correctKey, 1, SECP256K1_CURVE_ORDER - 1);
        wrongKey = bound(wrongKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(correctKey != wrongKey);

        bytes memory key = abi.encodePacked(vm.addr(correctKey));
        _account = _deployAccount(key, 0, 0);

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, 0);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        userOp.signature = abi.encode(key, abi.encodePacked(r, s, v));

        (uint48 from, uint48 until) = _validator.validity(address(_account), key);

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);
        assertEq(result, ERC4337Utils.packValidationData(false, from, until));
    }

    function _deployAccount(bytes memory key, uint48 start, uint48 end) internal returns (OpenAccount) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory starts = new uint48[](1);
        uint48[] memory ends = new uint48[](1);
        starts[0] = start;
        ends[0] = end;

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(abi.encode(keys, starts, ends));

        return
            OpenAccount(
                payable(
                    _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
                )
            );
    }

    function _installKey(address account, bytes memory key, uint48 start, uint48 end) internal {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory starts = new uint48[](1);
        uint48[] memory ends = new uint48[](1);
        starts[0] = start;
        ends[0] = end;

        vm.prank(account);
        _validator.onInstall(abi.encode(keys, starts, ends));
    }

    function _buildKeys(uint256 n) internal pure returns (uint256[] memory privateKeys, bytes[] memory keys) {
        return _buildKeys(n, 0);
    }

    function _buildKeys(
        uint256 n,
        uint256 offset
    ) internal pure returns (uint256[] memory privateKeys, bytes[] memory keys) {
        privateKeys = new uint256[](n);
        keys = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            privateKeys[i] = i + offset + 1;
            keys[i] = abi.encodePacked(vm.addr(privateKeys[i]));
        }
    }

    function _prepareUserOperation(uint256 nonce, uint256 value) private view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: (uint256(uint160(address(_validator))) << 96) | (nonce & type(uint96).max),
                initCode: bytes(""),
                callData: abi.encodeCall(
                    AccountERC7579.execute,
                    (
                        Mode.unwrap(
                            ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
                                ERC7579Utils.EXECTYPE_DEFAULT,
                                ModeSelector.wrap(0x00000000),
                                ModePayload.wrap(0x00000000)
                            )
                        ),
                        abi.encodePacked(address(_target), value, abi.encodeCall(CallReceiverMock.mockFunction, ()))
                    )
                ),
                preVerificationGas: 100000,
                accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
                gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });
    }

    function _buildInstallationModules(
        bytes memory initData
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_validator);
        initDatas[0] = initData;
    }
}
