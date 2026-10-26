// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579NativeSpender} from "../../../src/modules/executors/ERC7579NativeSpender.sol";
import {ERC7579Utils, Mode, Execution} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579NativeSpenderTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

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
        startOffset = uint48(bound(startOffset, 0, type(uint48).max - uint48(block.timestamp)));

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
        startOffset = uint48(bound(startOffset, 0, type(uint48).max / 2));
        elapsed = uint48(bound(elapsed, 0, type(uint48).max - uint48(block.timestamp) - startOffset));

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
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max / numPeriods));

        uint160 amountPerPeriod = limit / 2;

        _installSpenderBoth(uint48(block.timestamp), 0, limit, renewPeriod);

        for (uint256 i = 0; i < numPeriods; i++) {
            vm.prank(_eoa);
            _spender.transferFrom(address(_account), _key, _recipient, amountPerPeriod);
            assertEq(_spender.spent(address(_account), _key, i), amountPerPeriod);

            vm.warp(block.timestamp + renewPeriod);
        }
    }

    function testSingleCallInstallsBothRoles() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(_spender), ""));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));
        assertTrue(_spender.installed(address(_account)));
        assertTrue(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 1 ether);
    }

    function testSingleCallInstallAfterInitialization() public {
        _initializeWithoutSpender();

        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 1 ether, 1 days));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));
        assertEq(_spender.limit(address(_account), _key), 1 ether);
    }

    function testDirectValidatorInstallReverts() public {
        _initializeWithoutSpender();

        // Neither the install bundle nor a plain session-keys bundle is accepted under the validator role
        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _bundle(_key, 1 ether, 1 days));

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _keysInitData(_key));
    }

    function testDirectValidatorInstallRevertsWithExecutorInstalled() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        // Drop the validator role only, then try to add it back directly. The transient flag set by the
        // executor install has been cleared, even within the same transaction.
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _keysInitData(_key));
    }

    function testReinstallReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Utils.ERC7579AlreadyInstalledModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(_spender)
            )
        );
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 2 ether, 2 days));
    }

    function testReconfigurationThroughOnInstallReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _spender.onInstall(_bundle(_key, 2 ether, 2 days));

        assertEq(_spender.limit(address(_account), _key), 1 ether);
    }

    function testReconfigurationAfterKeyReorderingReverts() public {
        // Register two keys but only configure the second one, so `keys[0]` has no spending config.
        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        bytes[] memory keys = new bytes[](2);
        keys[0] = _key;
        keys[1] = key2;
        uint48[] memory startsEnds = new uint48[](2);
        bytes[] memory configured = new bytes[](1);
        configured[0] = key2;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        _installExecutor(
            abi.encode(abi.encode(keys, startsEnds, startsEnds), abi.encode(configured, limits, renewPeriods))
        );

        // Reorder the key set by removing and re-adding `key2`.
        bytes[] memory rm = new bytes[](1);
        rm[0] = key2;
        uint48[] memory zero = new uint48[](1);
        vm.prank(address(_account));
        _spender.removeKeys(rm);
        vm.prank(address(_account));
        _spender.addKeys(rm, zero, zero);

        // A second `onInstall` can no longer write spending policies under the same installation.
        uint160[] memory newLimits = new uint160[](2);
        newLimits[0] = 100 ether;
        newLimits[1] = 100 ether;
        uint48[] memory newRenewPeriods = new uint48[](2);
        newRenewPeriods[0] = 1;
        newRenewPeriods[1] = 1;
        bytes memory reconfig = abi.encode(keys, newLimits, newRenewPeriods);

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _spender.onInstall(abi.encode(_keysInitData(_key), reconfig));

        // The old executor-schema bundle is rejected as well.
        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _spender.onInstall(reconfig);

        assertEq(_spender.limit(address(_account), _key), 0);
    }

    function testExecutorOnInstallWithRegisteredKeysReverts() public {
        _initializeWithoutSpender();

        // Keys registered before the module is installed block the install bundle.
        uint48[] memory zero = new uint48[](1);
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        vm.prank(address(_account));
        _spender.addKeys(keys, zero, zero);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderAlreadyInstalled()"));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 1 ether, 1 days));
    }

    function testInstallWithEmptySessionKeysReverts() public {
        bytes[] memory emptyKeys = new bytes[](0);
        uint48[] memory empty48 = new uint48[](0);
        bytes memory sessionKeysInitData = abi.encode(emptyKeys, empty48, empty48);
        (, bytes memory spendingInitData) = abi.decode(_bundle(_key, 1 ether, 1 days), (bytes, bytes));

        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderEmptyKeys()"));
        _installExecutor(abi.encode(sessionKeysInitData, spendingInitData));
    }

    function testInstallWithEmptySpendingPoliciesReverts() public {
        bytes[] memory emptyKeys = new bytes[](0);
        uint160[] memory emptyLimits = new uint160[](0);
        uint48[] memory emptyRenewPeriods = new uint48[](0);

        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderEmptyKeys()"));
        _installExecutor(abi.encode(_keysInitData(_key), abi.encode(emptyKeys, emptyLimits, emptyRenewPeriods)));
    }

    function testInstallWithUnregisteredPolicyKeyReverts() public {
        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);
        (, bytes memory spendingInitData) = abi.decode(_bundle(key2, 1 ether, 1 days), (bytes, bytes));

        vm.expectRevert(abi.encodeWithSignature("ERC7579SessionKeysNonexistentKey(bytes)", key2));
        _installExecutor(abi.encode(_keysInitData(_key), spendingInitData));
    }

    function testInstallWithMalformedBundleReverts() public {
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderInvalidInitData()"));
        _installExecutor(new bytes(0x7f));
    }

    function testUninstallExecutorOnlyBlocksReinstall() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);
        uint256 nonceBefore = _spender.installation(address(_account));

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");
        assertEq(_spender.installation(address(_account)), nonceBefore + 1);
        assertFalse(_spender.isKey(address(_account), _key));
        // The validator role is left installed.
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579NativeSpender.ERC7579NativeSpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 2 ether, 2 days));

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");
        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 2 ether, 2 days));
        assertEq(_spender.limit(address(_account), _key), 2 ether);
        assertEq(_spender.renewPeriod(address(_account), _key), 2 days);
    }

    function testReinstallAfterFullUninstallWritesFreshConfig() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, 0.5 ether);

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");

        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(_key, 3 ether, 3 days));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));
        assertEq(_spender.limit(address(_account), _key), 3 ether);
        assertEq(_spender.spent(address(_account), _key, 0), 0);
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

        // Uninstalling either role bumps the nonce
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
        // The flat test bundle is split into the session-keys and spending-policy halves of the install bundle.
        (
            bytes[] memory keys,
            uint48[] memory starts,
            uint48[] memory ends,
            uint160[] memory limits,
            uint48[] memory renewPeriods
        ) = abi.decode(initData, (bytes[], uint48[], uint48[], uint160[], uint48[]));

        _installExecutor(abi.encode(abi.encode(keys, starts, ends), abi.encode(keys, limits, renewPeriods)));
    }

    /// @dev Initializes the account with the spender as its only module, installed as an executor.
    function _installExecutor(bytes memory bundle) private {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_spender);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = bundle;
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    /// @dev Initializes the account with an unrelated executor so the spender can be installed afterwards.
    function _initializeWithoutSpender() private {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](1);
        modules[0] = address(new ERC7579NativeSpender());
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = _bundle(_key, 1 ether, 1 days);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    function _keysInitData(bytes memory key) private pure returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory zero = new uint48[](1);
        return abi.encode(keys, zero, zero);
    }

    function _bundle(bytes memory key, uint160 limit, uint48 renewPeriod) private pure returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;
        return abi.encode(_keysInitData(key), abi.encode(keys, limits, renewPeriods));
    }
}
