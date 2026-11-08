// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579SessionKeysValidator} from "../../../src/modules/validators/ERC7579SessionKeysValidator.sol";
import {ERC7579SessionKeys} from "../../../src/modules/ERC7579SessionKeys.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation, IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";
import {BytesDecoderReference} from "../../helpers/BytesDecoderReference.sol";

contract ERC7579SessionKeysValidatorMock is ERC7579SessionKeysValidator {
    function tryDecodeSignature(
        bytes calldata signature
    ) external pure returns (bool success, bytes calldata key, bytes calldata keySignature) {
        return _tryDecodeSignature(signature);
    }

    function maxGasCost(PackedUserOperation calldata userOp) external pure returns (uint256) {
        return _maxGasCost(userOp);
    }
}

contract ERC7579SessionKeysValidatorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;

    uint256 private constant MAX_ETH = type(uint128).max;
    uint48 private constant MAX_TIMEPOINT = type(uint48).max >> 1;
    uint256 private constant SECP256K1_CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant GAS_BUDGET = 1 ether;
    // Maximum gas cost of the user operation built by `_prepareUserOperation`:
    // (preVerificationGas + verificationGasLimit + callGasLimit) * maxFeePerGas
    uint256 private constant USER_OP_COST = (100000 + 100000 + 100000) * 1000000;

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
        _validator.onInstall(abi.encode(keys, starts, ends, _gasBudgets(keys.length, GAS_BUDGET)));

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
            assertEq(_validator.gasBudget(address(_account), newKeys[i]), 0);
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

    function testKeyGeneration(uint256 privateKey, uint256 gasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;

        assertEq(_validator.keyGeneration(address(_account), key), 0);
        _installKey(address(_account), key, 0, 0, gasBudget);
        assertEq(_validator.keyGeneration(address(_account), key), 0);

        // Removing the key bumps its generation and makes its validity and gas budget unreachable.
        vm.prank(address(_account));
        _validator.removeKeys(keys);
        assertEq(_validator.keyGeneration(address(_account), key), 1);
        (uint48 from, uint48 until) = _validator.validity(address(_account), key);
        assertEq(from, 0);
        assertEq(until, 0);
        assertEq(_validator.gasBudget(address(_account), key), 0);

        // Registering the key again keeps the generation and starts from empty state.
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));
        assertEq(_validator.keyGeneration(address(_account), key), 1);
        assertTrue(_validator.isValid(address(_account), key));
        assertEq(_validator.gasBudget(address(_account), key), 0);

        vm.prank(address(_account));
        _validator.removeKeys(keys);
        assertEq(_validator.keyGeneration(address(_account), key), 2);

        // Generations are scoped to the installation.
        vm.prank(address(_account));
        _validator.onUninstall("");
        assertEq(_validator.keyGeneration(address(_account), key), 0);
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
        from = uint48(bound(from, 1, MAX_TIMEPOINT - 1));
        until = uint48(bound(until, from + 1, MAX_TIMEPOINT));

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
        assertEq(result, ERC4337Utils.packValidationData(true, from - 1, until));
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
        assertEq(result, ERC4337Utils.packValidationData(false, from - 1, until));
    }

    function testOnInstallRevertsWhenEndExceeds47Bits(uint256 privateKey, uint48 start, uint48 end) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        start = uint48(bound(start, 0, MAX_TIMEPOINT));
        end = uint48(bound(end, uint256(MAX_TIMEPOINT) + 1, type(uint48).max));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        uint48 resolvedStart = start == 0 ? uint48(block.timestamp) : start;

        vm.expectRevert(
            abi.encodeWithSelector(ERC7579SessionKeys.ERC7579SessionKeysInvalidValidity.selector, resolvedStart, end)
        );
        _installKey(address(_account), key, start, end);
    }

    function testOnInstallRevertsWhenStartExceeds47Bits(uint256 privateKey, uint48 start) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        start = uint48(bound(start, uint256(MAX_TIMEPOINT) + 1, type(uint48).max));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        // `ends == 0` resolves to MAX_TIMEPOINT, which is below `start`.
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579SessionKeys.ERC7579SessionKeysInvalidValidity.selector, start, MAX_TIMEPOINT)
        );
        _installKey(address(_account), key, start, 0);
    }

    function testOnInstallRevertsWhenRangeIsInverted(uint256 privateKey, uint48 start, uint48 end) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        start = uint48(bound(start, 2, MAX_TIMEPOINT));
        end = uint48(bound(end, 1, start - 1));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        vm.expectRevert(
            abi.encodeWithSelector(ERC7579SessionKeys.ERC7579SessionKeysInvalidValidity.selector, start, end)
        );
        _installKey(address(_account), key, start, end);
    }

    function testOnInstallAcceptsSingleTimepointRange(uint256 privateKey, uint48 timepoint) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        timepoint = uint48(bound(timepoint, 1, MAX_TIMEPOINT));

        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _installKey(address(_account), key, timepoint, timepoint);

        (uint48 retFrom, uint48 retUntil) = _validator.validity(address(_account), key);
        assertEq(retFrom, timepoint);
        assertEq(retUntil, timepoint);
    }

    function testNoExpiry(uint256 privateKey, bytes32 messageHash) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        _account = _deployAccount(key, 0, 0);
        vm.deal(address(_account), MAX_ETH);

        (, uint48 until) = _validator.validity(address(_account), key);
        assertEq(until, MAX_TIMEPOINT);

        vm.warp(MAX_TIMEPOINT);

        // ERC-1271 path
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        vm.prank(address(_account));
        assertEq(
            _validator.isValidSignatureWithSender(
                address(this),
                messageHash,
                abi.encode(key, abi.encodePacked(r, s, v))
            ),
            IERC1271.isValidSignature.selector
        );

        // ERC-4337 path
        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);
        (, , uint48 validUntil, ERC4337Utils.ValidationRange range) = ERC4337Utils.parseValidationData(
            _simulateValidation(userOp)
        );
        assertEq(validUntil, MAX_TIMEPOINT);
        assertEq(uint8(range), uint8(ERC4337Utils.ValidationRange.TIMESTAMP));

        vm.expectEmit(address(_target));
        emit CallReceiverMock.MockFunctionCalled();
        _handleOp(userOp);
    }

    function testHandleOpsAtValidityStart(uint256 privateKey, uint48 delay) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        delay = uint48(bound(delay, 1, 365 days));
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        uint48 from = uint48(block.timestamp) + delay;
        _account = _deployAccount(key, from, 0);
        vm.deal(address(_account), MAX_ETH);

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);

        (, uint48 validAfter, , ) = ERC4337Utils.parseValidationData(_simulateValidation(userOp));
        assertEq(validAfter, from - 1);

        // One timepoint before `from` the EntryPoint rejects the operation.
        vm.warp(from - 1);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA22 expired or not due"));
        vm.prank(makeAddr("bundler"), makeAddr("bundler"));
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // At `from` the key is valid on both paths.
        vm.warp(from);
        assertTrue(_validator.isValid(address(_account), key));
        vm.expectEmit(address(_target));
        emit CallReceiverMock.MockFunctionCalled();
        _handleOp(userOp);
    }

    function testOnInstallSetsGasBudget(uint256 privateKey, uint256 gasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        vm.expectEmit(address(_validator));
        emit ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorGasBudgetSet(address(_account), key, gasBudget);
        _installKey(address(_account), key, 0, 0, gasBudget);
        assertEq(_validator.gasBudget(address(_account), key), gasBudget);
    }

    function testOnInstallRevertsOnMismatchedGasBudgets(uint8 numGasBudgets) public {
        vm.assume(numGasBudgets != 1);
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(vm.addr(1));

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorMismatchedGasBudgetsLength.selector,
                1,
                numGasBudgets
            )
        );
        _validator.onInstall(abi.encode(keys, new uint48[](1), new uint48[](1), new uint256[](numGasBudgets)));
    }

    function testOnInstallRevertsOnInitDataWithoutGasBudgets(uint256 numKeys) public {
        numKeys = bound(numKeys, 0, 10);
        (, bytes[] memory keys) = _buildKeys(numKeys);

        // The 3-array encoding is valid for the key registration but has no `gasBudgets` array.
        vm.prank(address(_account));
        vm.expectRevert(ERC7579SessionKeys.ERC7579SessionKeysInvalidInitData.selector);
        _validator.onInstall(abi.encode(keys, new uint48[](numKeys), new uint48[](numKeys)));
    }

    function testOnInstallRevertsOnShortInitData(uint8 length) public {
        // Zeroed data decodes as empty arrays where it is long enough for the key registration.
        vm.prank(address(_account));
        vm.expectRevert(ERC7579SessionKeys.ERC7579SessionKeysInvalidInitData.selector);
        _validator.onInstall(new bytes(length));
    }

    function testSetGasBudget(uint256 privateKey, uint256 initialGasBudget, uint256 newGasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        address otherAccount = makeAddr("otherAccount");

        _installKey(address(_account), key, 0, 0, initialGasBudget);
        _installKey(otherAccount, key, 0, 0, initialGasBudget);

        // Overwrites the remaining budget, both up and down.
        vm.prank(address(_account));
        vm.expectEmit(address(_validator));
        emit ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorGasBudgetSet(address(_account), key, newGasBudget);
        _validator.setGasBudget(key, newGasBudget);
        assertEq(_validator.gasBudget(address(_account), key), newGasBudget);

        // Only affects the calling account.
        assertEq(_validator.gasBudget(otherAccount, key), initialGasBudget);
    }

    function testSetGasBudgetRevertsForUnregisteredKey(uint256 privateKey, uint256 gasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSelector(ERC7579SessionKeys.ERC7579SessionKeysNonexistentKey.selector, key));
        _validator.setGasBudget(key, gasBudget);
    }

    function testRemoveKeysClearsGasBudget(uint256 privateKey, uint256 gasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _installKey(address(_account), key, 0, 0, gasBudget);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        vm.prank(address(_account));
        _validator.removeKeys(keys);
        assertEq(_validator.gasBudget(address(_account), key), 0);

        // Re-adding the key starts without a budget under a new generation.
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));
        assertEq(_validator.keyGeneration(address(_account), key), 1);
        assertEq(_validator.gasBudget(address(_account), key), 0);
    }

    function testReAddedKeyGasBudgetDoesNotReviveOldBudget(
        uint256 privateKey,
        uint256 oldGasBudget,
        uint256 newGasBudget
    ) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        oldGasBudget = bound(oldGasBudget, USER_OP_COST, type(uint256).max);
        newGasBudget = bound(newGasBudget, 0, USER_OP_COST - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _installKey(address(_account), key, 0, 0, oldGasBudget);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        vm.prank(address(_account));
        _validator.removeKeys(keys);
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));

        // The budget set on the new generation is the only one readable.
        vm.prank(address(_account));
        _validator.setGasBudget(key, newGasBudget);
        assertEq(_validator.gasBudget(address(_account), key), newGasBudget);

        // The old budget does not cover an operation that the new one cannot pay for.
        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);
        assertEq(_simulateValidation(userOp), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_validator.gasBudget(address(_account), key), newGasBudget);

        // The same operation validates once the new generation's budget covers it.
        vm.prank(address(_account));
        _validator.setGasBudget(key, USER_OP_COST);
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_simulateValidation(userOp));
        assertEq(authorizer, address(0));
        assertEq(_validator.gasBudget(address(_account), key), 0);

        // Removing and re-adding again does not bring back either budget.
        vm.prank(address(_account));
        _validator.removeKeys(keys);
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));
        assertEq(_validator.keyGeneration(address(_account), key), 2);
        assertEq(_validator.gasBudget(address(_account), key), 0);
    }

    function testReinstallResetsGasBudget(uint256 privateKey, uint256 gasBudget, uint256 newGasBudget) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _installKey(address(_account), key, 0, 0, gasBudget);

        vm.prank(address(_account));
        _validator.onUninstall("");
        assertEq(_validator.gasBudget(address(_account), key), 0);

        _installKey(address(_account), key, 0, 0, newGasBudget);
        assertEq(_validator.gasBudget(address(_account), key), newGasBudget);

        // A key added after reinstalling does not inherit the budget of the previous installation either.
        vm.prank(address(_account));
        _validator.onUninstall("");
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));
        assertEq(_validator.gasBudget(address(_account), key), 0);
    }

    function testMaxGasCost(
        uint256 preVerificationGas,
        uint128 verificationGasLimit,
        uint128 callGasLimit,
        uint128 maxPriorityFeePerGas,
        uint128 maxFeePerGas,
        uint128 paymasterVerificationGasLimit,
        uint128 paymasterPostOpGasLimit,
        address paymaster,
        bool withPaymasterAndData
    ) public view {
        PackedUserOperation memory userOp;
        userOp.preVerificationGas = preVerificationGas;
        userOp.accountGasLimits = bytes32(abi.encodePacked(verificationGasLimit, callGasLimit));
        userOp.gasFees = bytes32(abi.encodePacked(maxPriorityFeePerGas, maxFeePerGas));
        if (withPaymasterAndData) {
            userOp.paymasterAndData = abi.encodePacked(
                paymaster,
                paymasterVerificationGasLimit,
                paymasterPostOpGasLimit
            );
        }

        uint256 gasLimits = uint256(verificationGasLimit) + callGasLimit;
        if (withPaymasterAndData) gasLimits += uint256(paymasterVerificationGasLimit) + paymasterPostOpGasLimit;
        (bool addSuccess, uint256 requiredGas) = Math.tryAdd(preVerificationGas, gasLimits);
        (bool mulSuccess, uint256 requiredPrefund) = Math.tryMul(
            addSuccess ? requiredGas : type(uint256).max,
            maxFeePerGas
        );
        // Overflowing values saturate, unless the fee is zero and nothing is charged.
        uint256 expected = maxFeePerGas == 0 ? 0 : (addSuccess && mulSuccess ? requiredPrefund : type(uint256).max);
        assertEq(_validator.maxGasCost(userOp), expected);
    }

    function testValidateUserOpGasBudget(
        uint256 privateKey,
        uint256 gasBudget,
        uint64 preVerificationGas,
        uint64 maxFeePerGas
    ) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _account = _deployAccount(key, 0, 0, gasBudget);

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = bytes32(abi.encodePacked(uint128(maxFeePerGas), uint128(maxFeePerGas)));
        _signUserOp(userOp, privateKey, key);

        uint256 cost = (uint256(preVerificationGas) + 100000 + 100000) * maxFeePerGas;
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_simulateValidation(userOp));
        assertEq(authorizer == address(0), cost <= gasBudget);
        assertEq(_validator.gasBudget(address(_account), key), cost <= gasBudget ? gasBudget - cost : gasBudget);
    }

    function testHandleOpsAtGasBudget(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        // At the budget, the operation is accepted and executed, and the budget is exhausted.
        _account = _deployAccount(key, 0, 0, USER_OP_COST);
        vm.deal(address(_account), MAX_ETH);
        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);
        vm.expectEmit(address(_target));
        emit CallReceiverMock.MockFunctionCalled();
        _handleOp(userOp);
        assertEq(_validator.gasBudget(address(_account), key), 0);

        // One wei over the budget, validation fails and the EntryPoint rejects the operation.
        _account = _deployAccount(key, 0, 0, USER_OP_COST - 1);
        vm.deal(address(_account), MAX_ETH);
        userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);
        assertEq(_simulateValidation(userOp), ERC4337Utils.SIG_VALIDATION_FAILED);
        _expectHandleOpRevert(userOp, "AA24 signature error");
        assertEq(_validator.gasBudget(address(_account), key), USER_OP_COST - 1);
    }

    function testHandleOpsDeductsGasBudgetCumulatively(uint256 privateKey, uint8 numOps, uint256 remainder) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        numOps = uint8(bound(numOps, 1, 5));
        remainder = bound(remainder, 0, USER_OP_COST - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        _account = _deployAccount(key, 0, 0, USER_OP_COST * numOps + remainder);
        vm.deal(address(_account), MAX_ETH);

        PackedUserOperation memory userOp;
        for (uint256 i = 0; i < numOps; ++i) {
            userOp = _prepareUserOperation(i, 0);
            _signUserOp(userOp, privateKey, key);
            _handleOp(userOp);
            assertEq(_validator.gasBudget(address(_account), key), USER_OP_COST * (numOps - i - 1) + remainder);
        }

        // The remaining budget does not cover another operation.
        userOp = _prepareUserOperation(numOps, 0);
        _signUserOp(userOp, privateKey, key);
        _expectHandleOpRevert(userOp, "AA24 signature error");
        assertEq(_validator.gasBudget(address(_account), key), remainder);

        // Topping up the budget allows new operations.
        vm.prank(address(_account));
        _validator.setGasBudget(key, USER_OP_COST);
        vm.expectEmit(address(_target));
        emit CallReceiverMock.MockFunctionCalled();
        _handleOp(userOp);
        assertEq(_validator.gasBudget(address(_account), key), 0);
    }

    function testValidateUserOpWithPaymasterIsCharged(
        uint256 privateKey,
        address paymaster,
        uint64 paymasterVerificationGasLimit,
        uint64 paymasterPostOpGasLimit
    ) public {
        vm.assume(paymaster != address(0));
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        userOp.paymasterAndData = abi.encodePacked(
            paymaster,
            uint128(paymasterVerificationGasLimit),
            uint128(paymasterPostOpGasLimit)
        );
        uint256 cost = USER_OP_COST + (uint256(paymasterVerificationGasLimit) + paymasterPostOpGasLimit) * 1000000;

        // A budget that only covers the account gas limits is not enough.
        _account = _deployAccount(key, 0, 0, cost - 1);
        userOp.sender = address(_account);
        _signUserOp(userOp, privateKey, key);
        assertEq(_simulateValidation(userOp), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_validator.gasBudget(address(_account), key), cost - 1);

        // A budget that includes the paymaster gas limits is.
        _account = _deployAccount(key, 0, 0, cost);
        userOp.sender = address(_account);
        _signUserOp(userOp, privateKey, key);
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_simulateValidation(userOp));
        assertEq(authorizer, address(0));
        assertEq(_validator.gasBudget(address(_account), key), 0);
    }

    function testValidateUserOpInvalidSignatureDoesNotDeduct(uint256 correctKey, uint256 wrongKey) public {
        correctKey = bound(correctKey, 1, SECP256K1_CURVE_ORDER - 1);
        wrongKey = bound(wrongKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(correctKey != wrongKey);
        bytes memory key = abi.encodePacked(vm.addr(correctKey));
        _account = _deployAccount(key, 0, 0, GAS_BUDGET);

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, wrongKey, key);
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_simulateValidation(userOp));
        assertEq(authorizer, address(1));
        assertEq(_validator.gasBudget(address(_account), key), GAS_BUDGET);
    }

    function testValidateUserOpFromThirdPartyDoesNotDeduct(uint256 privateKey, address caller) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        bytes memory key = abi.encodePacked(vm.addr(privateKey));
        _account = _deployAccount(key, 0, 0, GAS_BUDGET);
        vm.assume(caller != address(_account));

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, privateKey, key);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        vm.prank(caller);
        assertEq(_validator.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_validator.gasBudget(address(_account), key), GAS_BUDGET);
    }

    function testHandleOpsAfterAddKeysRequiresGasBudget(uint256 privateKey) public {
        privateKey = bound(privateKey, 2, SECP256K1_CURVE_ORDER - 1);
        _account = _deployAccount(abi.encodePacked(vm.addr(privateKey)), 0, 0);
        vm.deal(address(_account), MAX_ETH);

        uint256 newPrivateKey = privateKey - 1;
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(vm.addr(newPrivateKey));
        vm.prank(address(_account));
        _validator.addKeys(keys, new uint48[](1), new uint48[](1));

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        _signUserOp(userOp, newPrivateKey, keys[0]);
        _expectHandleOpRevert(userOp, "AA24 signature error");

        vm.prank(address(_account));
        _validator.setGasBudget(keys[0], USER_OP_COST);
        vm.expectEmit(address(_target));
        emit CallReceiverMock.MockFunctionCalled();
        _handleOp(userOp);
    }

    function testSelfBundlingKeyCannotDrainAccount(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        address sessionKeyHolder = vm.addr(privateKey);
        bytes memory key = abi.encodePacked(sessionKeyHolder);
        _account = _deployAccount(key, 0, 0, 0.01 ether);
        vm.deal(address(_account), 100 ether);

        // The key holder bundles its own operation and names itself beneficiary. An inflated
        // `preVerificationGas` would otherwise turn ~99 ether of the account balance into fees.
        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        userOp.preVerificationGas = 99_000_000;
        userOp.gasFees = bytes32(abi.encodePacked(uint128(1e12), uint128(1e12)));
        _signUserOp(userOp, privateKey, key);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(sessionKeyHolder, sessionKeyHolder);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(sessionKeyHolder));

        assertEq(address(_account).balance, 100 ether);
        assertEq(sessionKeyHolder.balance, 0);
        assertEq(_validator.gasBudget(address(_account), key), 0.01 ether);

        // With an unlimited budget, the same operation turns most of the account balance into fees.
        _account = _deployAccount(key, 0, 0, type(uint256).max);
        vm.deal(address(_account), 100 ether);
        userOp.sender = address(_account);
        _signUserOp(userOp, privateKey, key);
        ops[0] = userOp;
        vm.prank(sessionKeyHolder, sessionKeyHolder);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(sessionKeyHolder));
        assertGt(sessionKeyHolder.balance, 99 ether);
    }

    function _expectHandleOpRevert(PackedUserOperation memory userOp, string memory reason) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, reason));
        vm.prank(makeAddr("bundler"), makeAddr("bundler"));
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function _signUserOp(PackedUserOperation memory userOp, uint256 privateKey, bytes memory key) internal view {
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        userOp.signature = abi.encode(key, abi.encodePacked(r, s, v));
    }

    function _simulateValidation(PackedUserOperation memory userOp) internal returns (uint256) {
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        vm.prank(address(_account));
        return _validator.validateUserOp(userOp, userOpHash);
    }

    function _handleOp(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(makeAddr("bundler"), makeAddr("bundler"));
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function testTryDecodeSignature(bytes memory key, bytes memory keySignature) public view {
        (bool success, bytes memory decodedKey, bytes memory decodedKeySignature) = _validator.tryDecodeSignature(
            abi.encode(key, keySignature)
        );
        assertTrue(success);
        assertEq(decodedKey, key);
        assertEq(decodedKeySignature, keySignature);
    }

    function testTryDecodeSignatureArbitraryData(bytes memory signature) public view {
        _assertTryDecodeSignatureMatchesReference(signature);
    }

    function testTryDecodeSignatureArbitraryWords(
        uint256 keyOffset,
        uint256 signatureOffset,
        uint256 word2,
        uint256 word3,
        bytes memory tail
    ) public view {
        _assertTryDecodeSignatureMatchesReference(abi.encodePacked(keyOffset, signatureOffset, word2, word3, tail));
    }

    function testTryDecodeSignatureArbitraryLengths(
        uint256 keyLength,
        uint256 signatureLength,
        bytes memory tail
    ) public view {
        _assertTryDecodeSignatureMatchesReference(
            abi.encodePacked(uint256(0x40), uint256(0x60), keyLength, signatureLength, tail)
        );
    }

    function testTryDecodeSignatureOverflowingOffsetsAndLengths() public view {
        bytes[] memory signatures = _overflowingSignatures();
        for (uint256 i = 0; i < signatures.length; ++i) {
            (bool success, bytes memory key, bytes memory keySignature) = _validator.tryDecodeSignature(signatures[i]);
            assertFalse(success);
            assertEq(key.length, 0);
            assertEq(keySignature.length, 0);
            _assertTryDecodeSignatureMatchesReference(signatures[i]);
        }
    }

    function testValidateUserOpOverflowingSignature(uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        _account = _deployAccount(abi.encodePacked(vm.addr(privateKey)), 0, 0);

        PackedUserOperation memory userOp = _prepareUserOperation(0, 0);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        bytes[] memory signatures = _overflowingSignatures();
        for (uint256 i = 0; i < signatures.length; ++i) {
            userOp.signature = signatures[i];
            vm.prank(address(_account));
            assertEq(_validator.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
        }
    }

    function testIsValidSignatureWithSenderOverflowingSignature(bytes32 messageHash, uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        _installKey(address(_account), abi.encodePacked(vm.addr(privateKey)), 0, 0);

        bytes[] memory signatures = _overflowingSignatures();
        for (uint256 i = 0; i < signatures.length; ++i) {
            vm.prank(address(_account));
            assertEq(
                _validator.isValidSignatureWithSender(address(this), messageHash, signatures[i]),
                bytes4(0xffffffff)
            );
        }
    }

    function _assertTryDecodeSignatureMatchesReference(bytes memory signature) private view {
        (bool success, bytes memory key, bytes memory keySignature) = _validator.tryDecodeSignature(signature);

        (bool keySuccess, bytes memory expectedKey) = BytesDecoderReference.tryDecode(signature, 0x00, 0);
        (bool keySignatureSuccess, bytes memory expectedKeySignature) = BytesDecoderReference.tryDecode(
            signature,
            0x20,
            0
        );
        if (signature.length >= 0x80 && keySuccess && keySignatureSuccess) {
            assertTrue(success);
            assertEq(key, expectedKey);
            assertEq(keySignature, expectedKeySignature);
        } else {
            assertFalse(success);
            assertEq(key.length, 0);
            assertEq(keySignature.length, 0);
        }
    }

    /// @dev Encodings where the offset or length words make the bounds arithmetic overflow.
    function _overflowingSignatures() private pure returns (bytes[] memory signatures) {
        uint256 max = type(uint256).max;
        signatures = new bytes[](8);
        signatures[0] = abi.encode(max, 0x60, 0, 0); // keyOffset + 0x20 overflows
        signatures[1] = abi.encode(0x40, max, 0, 0); // signatureOffset + 0x20 overflows
        signatures[2] = abi.encode(max - 0x1f, 0x60, 0, 0); // keyOffset + 0x20 wraps to 0
        signatures[3] = abi.encode(0x40, max - 0x1f, 0, 0); // signatureOffset + 0x20 wraps to 0
        signatures[4] = abi.encode(0x40, 0x60, max, 0); // keyDataOffset + keyLength overflows
        signatures[5] = abi.encode(0x40, 0x60, 0, max); // signatureDataOffset + signatureLength overflows
        signatures[6] = abi.encode(0x40, 0x60, max - 0x5f, 0); // keyDataOffset + keyLength wraps to 0
        signatures[7] = abi.encode(0x40, 0x60, 0, max - 0x7f); // signatureDataOffset + signatureLength wraps to 0
    }

    function _deployAccount(bytes memory key, uint48 start, uint48 end) internal returns (OpenAccount) {
        return _deployAccount(key, start, end, GAS_BUDGET);
    }

    function _deployAccount(
        bytes memory key,
        uint48 start,
        uint48 end,
        uint256 gasBudget
    ) internal returns (OpenAccount) {
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
        ) = _buildInstallationModules(abi.encode(keys, starts, ends, _gasBudgets(1, gasBudget)));

        return
            OpenAccount(
                payable(
                    _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
                )
            );
    }

    function _installKey(address account, bytes memory key, uint48 start, uint48 end) internal {
        _installKey(account, key, start, end, GAS_BUDGET);
    }

    function _installKey(address account, bytes memory key, uint48 start, uint48 end, uint256 gasBudget) internal {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory starts = new uint48[](1);
        uint48[] memory ends = new uint48[](1);
        starts[0] = start;
        ends[0] = end;

        vm.prank(account);
        _validator.onInstall(abi.encode(keys, starts, ends, _gasBudgets(1, gasBudget)));
    }

    function _gasBudgets(uint256 n, uint256 gasBudget) private pure returns (uint256[] memory gasBudgets) {
        gasBudgets = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            gasBudgets[i] = gasBudget;
        }
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
