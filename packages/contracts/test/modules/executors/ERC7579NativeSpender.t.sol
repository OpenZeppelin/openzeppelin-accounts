// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579NativeSpender} from "../../../src/modules/executors/ERC7579NativeSpender.sol";
import {ERC7579Utils, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579NativeSpenderTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;
    uint48 private constant MAX_TIMEPOINT = type(uint48).max >> 1;

    ERC7579NativeSpender private _spender;
    OpenAccount private _account;

    address private _eoa;
    bytes private _key;

    address private _recipient;

    function setUp() public {
        _spender = new ERC7579NativeSpender();
        _account = new OpenAccountMock();

        vm.deal(address(_account), MAX_ETH);
        (_eoa, ) = makeAddrAndKey("session-key-eoa");
        _key = abi.encodePacked(_eoa);
        _recipient = makeAddr("recipient");
    }

    function testIsModuleType() public view {
        assertTrue(_spender.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(_spender.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_spender.isModuleType(0));
        assertFalse(_spender.isModuleType(3));
    }

    function testInstallation(uint48 startOffset, uint160 limit, uint48 renewPeriod) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        limit = uint160(bound(limit, 1, MAX_ETH));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT - uint48(block.timestamp)));

        uint48 from = uint48(block.timestamp) + startOffset;

        _installSpenderBoth(from, 0, limit, renewPeriod);

        assertEq(_spender.limit(address(_account), _key), limit);
        assertEq(_spender.renewPeriod(address(_account), _key), renewPeriod);
        (uint48 storedFrom, ) = _spender.validity(address(_account), _key);
        assertEq(storedFrom, from);
    }

    function testEoaSelfCallTransferWithinLimit(uint160 limit, uint160 amount, uint48 renewPeriod) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        limit = uint160(bound(limit, 1, MAX_ETH));
        amount = uint160(bound(amount, 0, limit));

        _installSpenderBoth(uint48(block.timestamp), 0, limit, renewPeriod);

        uint256 recipientBalanceBefore = _recipient.balance;
        uint256 accountBalanceBefore = address(_account).balance;

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, amount);

        assertEq(_recipient.balance, recipientBalanceBefore + amount);
        assertEq(address(_account).balance, accountBalanceBefore - amount);
        assertEq(_spender.spent(address(_account), _key, 0), amount);
    }

    function testEoaSelfCallRevertsWhenExceedingLimit(uint160 limit, uint256 amount) public {
        limit = uint160(bound(limit, 1, MAX_ETH - 1));
        amount = bound(amount, limit + 1, MAX_ETH);

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        vm.prank(_eoa);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC7579NativeInsufficientAvailable(address,bytes,uint256)",
                address(_account),
                _key,
                amount
            )
        );
        _spender.transferFrom(address(_account), _key, _recipient, amount);
    }

    function testEoaSelfCallRevertsForWrongCaller(address wrongCaller) public {
        vm.assume(wrongCaller != _eoa && wrongCaller != address(_account) && wrongCaller != address(0));

        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        vm.prank(wrongCaller);
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderUnauthorized(address,bytes)", wrongCaller, _key));
        _spender.transferFrom(address(_account), _key, _recipient, 1);
    }

    function testEoaSelfCallRevertsForUnregisteredKey() public {
        // No install at all
        vm.prank(_eoa);
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderUnauthorized(address,bytes)", _eoa, _key));
        _spender.transferFrom(address(_account), _key, _recipient, 1);
    }

    function testPeriodCalculation(uint48 startOffset, uint48 renewPeriod, uint48 elapsed) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT / 2));
        elapsed = uint48(bound(elapsed, 0, MAX_TIMEPOINT - uint48(block.timestamp) - startOffset));

        uint48 from = uint48(block.timestamp) + startOffset;
        _installSpenderBoth(from, 0, 1 ether, renewPeriod);

        uint48 timepoint = from + elapsed;
        vm.warp(timepoint);

        (uint256 returnedStart, uint256 period) = _spender.periodAt(address(_account), _key, timepoint);
        assertEq(returnedStart, from);
        assertEq(period, elapsed / renewPeriod);
    }

    function testBatchTransferWithinLimit(uint160 limit, uint8 numRecipients) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        numRecipients = uint8(bound(numRecipients, 1, 10));

        uint160 amountPerRecipient = limit / numRecipients;

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        address[] memory recipients = new address[](numRecipients);
        uint256[] memory amounts = new uint256[](numRecipients);
        uint256 totalAmount = 0;

        for (uint256 i = 0; i < numRecipients; i++) {
            recipients[i] = makeAddr(string(abi.encodePacked("recipient", i)));
            amounts[i] = amountPerRecipient;
            totalAmount += amounts[i];
        }

        vm.prank(_eoa);
        _spender.batchTransferFrom(address(_account), _key, recipients, amounts);

        assertEq(_spender.spent(address(_account), _key, 0), totalAmount);

        for (uint256 i = 0; i < numRecipients; i++) {
            assertEq(recipients[i].balance, amounts[i]);
        }
    }

    function testSpendingAcrossPeriods(uint160 limit, uint8 numPeriods, uint48 renewPeriod) public {
        numPeriods = uint8(bound(numPeriods, 1, 5));
        limit = uint160(bound(limit, 2, MAX_ETH / numPeriods));
        renewPeriod = uint48(bound(renewPeriod, 1, MAX_TIMEPOINT / numPeriods));

        uint160 amountPerPeriod = limit / 2;

        _installSpenderBoth(uint48(block.timestamp), 0, limit, renewPeriod);

        for (uint256 i = 0; i < numPeriods; i++) {
            vm.prank(_eoa);
            _spender.transferFrom(address(_account), _key, _recipient, amountPerPeriod);
            assertEq(_spender.spent(address(_account), _key, i), amountPerPeriod);

            vm.warp(block.timestamp + renewPeriod);
        }
    }

    function testThirdInstallReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 2 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 2 days;
        bytes memory configBundle = abi.encode(keys, limits, renewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderAlreadyInstalled()"));
        _spender.onInstall(configBundle);
    }

    function testSecondInstallWithEmptyKeysReverts() public {
        // Validator install registers `_key`
        bytes[] memory keysOne = new bytes[](1);
        keysOne[0] = _key;
        uint48[] memory startsOne = new uint48[](1);
        startsOne[0] = uint48(block.timestamp);
        uint48[] memory endsOne = new uint48[](1);
        endsOne[0] = 0;

        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_spender);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = abi.encode(keysOne, startsOne, endsOne);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        // Executor install with zero keys must revert
        bytes[] memory emptyKeys = new bytes[](0);
        uint160[] memory emptyLimits = new uint160[](0);
        uint48[] memory emptyRenewPeriods = new uint48[](0);
        bytes memory emptyConfig = abi.encode(emptyKeys, emptyLimits, emptyRenewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderEmptyKeys()"));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), emptyConfig);
    }

    function testAddKeysWithPastStartReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        // Move time forward so we have a real "past" timepoint to point at
        vm.warp(block.timestamp + 1 days);
        uint48 pastStart = uint48(block.timestamp - 1);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key2;
        uint48[] memory starts = new uint48[](1);
        starts[0] = pastStart;
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderInvalidStart(uint256)", pastStart));
        _spender.addKeysWithConfig(keys, starts, ends, limits, renewPeriods);
    }

    function testReAddRemovedKey() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);
        assertFalse(_spender.isKey(address(_account), _key));

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = 0; // resolves to clock()
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 2 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 2 days;

        vm.prank(address(_account));
        _spender.addKeysWithConfig(keys, starts, ends, limits, renewPeriods);

        assertTrue(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 2 ether);
    }

    function testRemoveKeysClearsConfig() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;

        vm.prank(address(_account));
        _spender.removeKeys(keys);

        assertFalse(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 0);
        assertEq(_spender.renewPeriod(address(_account), _key), 0);
    }

    function testRemoveKeysPreservesHistoryAtHistoricalStart() public {
        uint48 from = uint48(block.timestamp);
        _installSpenderBoth(from, 0, 1 ether, 1 days);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, 0.5 ether);
        assertEq(_spender.spent(address(_account), _key, 0, from), 0.5 ether);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(keys);

        // Convenience accessor reads from validity().from which is now 0
        assertEq(_spender.spent(address(_account), _key, 0), 0);
        // Explicit-start overload still returns the history
        assertEq(_spender.spent(address(_account), _key, 0, from), 0.5 ether);
    }

    function testMultipleKeysIndependence(uint160 limit, uint160 amount1, uint160 amount2) public {
        limit = uint160(bound(limit, 2, MAX_ETH / 2));
        amount1 = uint160(bound(amount1, 0, limit));
        amount2 = uint160(bound(amount2, 0, limit));

        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        bytes[] memory keys = new bytes[](2);
        keys[0] = _key;
        keys[1] = key2;
        uint48[] memory starts = new uint48[](2);
        starts[0] = uint48(block.timestamp);
        starts[1] = uint48(block.timestamp);
        uint48[] memory ends = new uint48[](2);
        ends[0] = 0;
        ends[1] = 0;
        uint160[] memory limits = new uint160[](2);
        limits[0] = limit;
        limits[1] = limit;
        uint48[] memory renewPeriods = new uint48[](2);
        renewPeriods[0] = 1 days;
        renewPeriods[1] = 1 days;

        bytes memory initData = abi.encode(keys, starts, ends, limits, renewPeriods);
        _installAccountBoth(initData);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, amount1);

        vm.prank(eoa2);
        _spender.transferFrom(address(_account), key2, _recipient, amount2);

        assertEq(_spender.spent(address(_account), _key, 0), amount1);
        assertEq(_spender.spent(address(_account), key2, 0), amount2);
    }

    function testUninstallClearsData(uint160 limit, uint160 spentAmount) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        spentAmount = uint160(bound(spentAmount, 0, limit));

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        if (spentAmount > 0) {
            vm.prank(_eoa);
            _spender.transferFrom(address(_account), _key, _recipient, spentAmount);
        }

        uint256 nonceBefore = _spender.installation(address(_account));

        // Uninstalling the validator role bumps the nonce; the executor uninstall is a no-op for storage
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");

        assertGt(_spender.installation(address(_account)), nonceBefore);
        assertEq(_spender.spent(address(_account), _key, 0), 0);
        assertFalse(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 0);
    }

    // ----- Helpers -----

    function _installSpenderBoth(uint48 from, uint48 until, uint160 limit, uint48 renewPeriod) private {
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = from;
        uint48[] memory ends = new uint48[](1);
        ends[0] = until;
        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;

        bytes memory initData = abi.encode(keys, starts, ends, limits, renewPeriods);
        _installAccountBoth(initData);
    }

    function _installAccountBoth(bytes memory initData) private {
        // The combined install bundle is split: keys/starts/ends go to the first install (validator),
        // and a matching keys/limits/renewPeriods bundle goes to the second install (executor).
        (
            bytes[] memory keys,
            uint48[] memory starts,
            uint48[] memory ends,
            uint160[] memory limits,
            uint48[] memory renewPeriods
        ) = abi.decode(initData, (bytes[], uint48[], uint48[], uint160[], uint48[]));

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](2);
        modules[0] = address(_spender);
        modules[1] = address(_spender);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = abi.encode(keys, starts, ends);
        initDatas[1] = abi.encode(keys, limits, renewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }
}
