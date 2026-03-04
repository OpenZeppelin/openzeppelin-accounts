// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579NativeSpender} from "../../../src/modules/executors/ERC7579NativeSpender.sol";
import {ERC7579Utils, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579NativeSpenderTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    ERC7579NativeSpender private _spender;
    OpenAccount private _account;
    address private _spenderAddress;
    address private _recipient;

    function setUp() public {
        // Deploy native spender module
        _spender = new ERC7579NativeSpender();

        // Deploy account
        _account = new OpenAccountMock();

        // Fund account
        vm.deal(address(_account), MAX_ETH);

        // Create addresses
        _spenderAddress = makeAddr("spender");
        _recipient = makeAddr("recipient");
    }

    function testInstallation(uint48 start, uint160 limit, uint48 renewPeriod) public {
        vm.assume(renewPeriod > 0);
        vm.assume(limit > 0);
        vm.assume(start >= block.timestamp || start == 0);

        address[] memory spenders = new address[](1);
        spenders[0] = _spenderAddress;

        uint48[] memory starts = new uint48[](1);
        starts[0] = start;

        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;

        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;

        bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initData);

        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        assertTrue(_spender.isModuleType(MODULE_TYPE_EXECUTOR));
        assertEq(_spender.spendersCount(address(_account)), 1);
        assertEq(_spender.start(address(_account), _spenderAddress), start == 0 ? block.timestamp : start);
        assertEq(_spender.limit(address(_account), _spenderAddress), limit);
        assertEq(_spender.renewPeriod(address(_account), _spenderAddress), renewPeriod);
    }

    function testInstallationWithMultipleSpenders(
        uint8 numSpenders,
        uint48 start,
        uint160 limit,
        uint48 renewPeriod
    ) public {
        numSpenders = uint8(bound(numSpenders, 1, 10));
        vm.assume(renewPeriod > 0);
        vm.assume(limit > 0);
        vm.assume(start >= block.timestamp);

        address[] memory spenders = new address[](numSpenders);
        uint48[] memory starts = new uint48[](numSpenders);
        uint160[] memory limits = new uint160[](numSpenders);
        uint48[] memory renewPeriods = new uint48[](numSpenders);

        for (uint256 i = 0; i < numSpenders; i++) {
            spenders[i] = makeAddr(string(abi.encodePacked("spender", i)));
            starts[i] = start;
            limits[i] = limit;
            renewPeriods[i] = renewPeriod;
        }

        bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initData);

        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        assertEq(_spender.spendersCount(address(_account)), numSpenders);

        for (uint256 i = 0; i < numSpenders; i++) {
            assertEq(_spender.start(address(_account), spenders[i]), start);
            assertEq(_spender.limit(address(_account), spenders[i]), limit);
            assertEq(_spender.renewPeriod(address(_account), spenders[i]), renewPeriod);
        }
    }

    function testTransferWithinLimit(uint160 limit, uint160 amount, uint48 renewPeriod) public {
        vm.assume(renewPeriod > 0);
        limit = uint160(bound(limit, 1, MAX_ETH));
        amount = uint160(bound(amount, 1, limit));

        uint48 start = uint48(block.timestamp);

        _installSpender(start, limit, renewPeriod);

        uint256 recipientBalanceBefore = _recipient.balance;
        uint256 accountBalanceBefore = address(_account).balance;

        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, amount);

        assertEq(_recipient.balance, recipientBalanceBefore + amount);
        assertEq(address(_account).balance, accountBalanceBefore - amount);
        assertEq(_spender.spent(address(_account), _spenderAddress, 0), amount);
    }

    function testTransferRevertsWhenExceedingLimit(uint160 limit, uint256 amount) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        amount = uint256(bound(amount, limit + 1, MAX_ETH));

        uint48 start = uint48(block.timestamp);
        uint48 renewPeriod = 1 days;

        _installSpender(start, limit, renewPeriod);

        vm.prank(_spenderAddress);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC7579NativeInsufficientAvailable(address,address,uint256)",
                address(_account),
                _spenderAddress,
                amount
            )
        );
        _spender.transferFrom(address(_account), _recipient, amount);
    }

    function testMultipleTransfersWithinLimit(uint160 limit, uint8 numTransfers) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        numTransfers = uint8(bound(numTransfers, 1, 20));

        uint160 amountPerTransfer = limit / numTransfers;

        uint48 start = uint48(block.timestamp);
        uint48 renewPeriod = 1 days;

        _installSpender(start, limit, renewPeriod);

        uint256 totalSpent = 0;

        for (uint256 i = 0; i < numTransfers; i++) {
            vm.prank(_spenderAddress);
            vm.expectCall(address(_recipient), amountPerTransfer, bytes(""));
            _spender.transferFrom(address(_account), _recipient, amountPerTransfer);
            totalSpent += amountPerTransfer;
        }

        assertEq(_spender.spent(address(_account), _spenderAddress, 0), totalSpent);
        assertLe(_spender.spent(address(_account), _spenderAddress, 0), limit);
    }

    function testPeriodCalculation(uint48 start, uint48 renewPeriod, uint48 timeElapsed) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        start = uint48(bound(start, block.timestamp, type(uint48).max));
        timeElapsed = uint48(bound(timeElapsed, 0, type(uint48).max - start));

        _installSpender(start, 1 ether, renewPeriod);

        uint48 timepoint = start + timeElapsed;
        vm.warp(timepoint);

        (uint256 returnedStart, uint256 period) = _spender.periodAt(address(_account), _spenderAddress, timepoint);

        assertEq(returnedStart, start);
        assertEq(period, timeElapsed / renewPeriod);
    }

    function testBatchTransferWithinLimit(uint160 limit, uint8 numRecipients) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        numRecipients = uint8(bound(numRecipients, 1, 10));

        uint160 amountPerRecipient = limit / numRecipients;

        uint48 start = uint48(block.timestamp);
        uint48 renewPeriod = 1 days;

        _installSpender(start, limit, renewPeriod);

        address[] memory recipients = new address[](numRecipients);
        uint256[] memory amounts = new uint256[](numRecipients);

        for (uint256 i = 0; i < numRecipients; i++) {
            recipients[i] = makeAddr(string(abi.encodePacked("recipient", i)));
            amounts[i] = amountPerRecipient;
        }

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < numRecipients; i++) {
            totalAmount += amounts[i];
        }

        vm.prank(_spenderAddress);
        for (uint256 i = 0; i < numRecipients; i++) {
            vm.expectCall(recipients[i], amounts[i], bytes(""));
        }
        _spender.batchTransferFrom(address(_account), recipients, amounts);

        assertEq(_spender.spent(address(_account), _spenderAddress, 0), totalAmount);
        assertLe(totalAmount, limit);

        for (uint256 i = 0; i < numRecipients; i++) {
            assertEq(recipients[i].balance, amounts[i]);
        }
    }

    function testSpendingAcrossMultiplePeriods(uint160 limit, uint8 numPeriods, uint48 renewPeriod) public {
        numPeriods = uint8(bound(numPeriods, 1, 5));
        limit = uint160(bound(limit, 1, MAX_ETH / numPeriods));
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max / numPeriods));

        uint48 start = uint48(block.timestamp);
        uint160 amountPerPeriod = limit / 2; // Spend half the limit per period

        _installSpender(start, limit, renewPeriod);

        for (uint256 i = 0; i < numPeriods; i++) {
            vm.prank(_spenderAddress);
            vm.expectCall(address(_recipient), amountPerPeriod, bytes(""));
            _spender.transferFrom(address(_account), _recipient, amountPerPeriod);
            assertEq(_spender.spent(address(_account), _spenderAddress, i), amountPerPeriod);

            // Move to next period
            vm.warp(block.timestamp + renewPeriod);
        }

        // Verify all periods have the expected spending
        for (uint256 i = 0; i < numPeriods; i++) {
            assertEq(_spender.spent(address(_account), _spenderAddress, i), amountPerPeriod);
        }
    }

    function testSetSpendingConfig(uint48 newStart, uint160 newLimit, uint48 newRenewPeriod) public {
        vm.assume(newRenewPeriod > 0);
        vm.assume(newLimit > 0);
        vm.assume(newStart >= block.timestamp || newStart == 0);

        uint48 start = uint48(block.timestamp);
        _installSpender(start, 1 ether, 1 days);

        vm.prank(address(_account));
        _spender.setSpendingConfig(_spenderAddress, newStart, newLimit, newRenewPeriod);

        assertEq(_spender.start(address(_account), _spenderAddress), newStart == 0 ? block.timestamp : newStart);
        assertEq(_spender.limit(address(_account), _spenderAddress), newLimit);
        assertEq(_spender.renewPeriod(address(_account), _spenderAddress), newRenewPeriod);
    }

    function testLimitReduction(uint160 initialLimit, uint160 spentAmount, uint160 newLimit) public {
        vm.assume(initialLimit > 0);
        spentAmount = uint160(bound(spentAmount, 1, Math.min(initialLimit, MAX_ETH)));
        newLimit = uint160(bound(newLimit, 1, Math.max(spentAmount, 1)));

        uint48 start = uint48(block.timestamp);
        uint48 renewPeriod = 1 days;

        _installSpender(start, initialLimit, renewPeriod);

        // Spend some amount
        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, spentAmount);

        // Set new configuration with future start time
        uint48 futureStart = uint48(block.timestamp + 1 days);
        vm.prank(address(_account));
        _spender.setSpendingConfig(_spenderAddress, futureStart, newLimit, renewPeriod);

        // Move to the new start time
        vm.warp(futureStart);

        // Check that available equals newLimit (spending reset with new start)
        (uint256 spending, uint256 available) = _spender.spendingAt(address(_account), _spenderAddress, 0);
        assertEq(spending, 0);
        assertEq(available, newLimit);
    }

    function testUninstallClearsData(uint160 limit, uint160 spentAmount, uint48 renewPeriod) public {
        vm.assume(renewPeriod > 0);
        limit = uint160(bound(limit, 1, MAX_ETH));
        spentAmount = uint160(bound(spentAmount, 1, limit));

        uint48 start = uint48(block.timestamp);
        _installSpender(start, limit, renewPeriod);

        // Spend some amount
        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, spentAmount);

        uint256 installationBefore = _spender.installation(address(_account));
        assertEq(_spender.spent(address(_account), _spenderAddress, 0), spentAmount);

        // Uninstall
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");

        // Verify nonce incremented
        assertEq(_spender.installation(address(_account)), installationBefore + 1);

        // Verify old data is inaccessible (returns 0)
        assertEq(_spender.spent(address(_account), _spenderAddress, 0), 0);
        assertEq(_spender.spendersCount(address(_account)), 0);
        assertEq(_spender.start(address(_account), _spenderAddress), 0);
        assertEq(_spender.limit(address(_account), _spenderAddress), 0);
    }

    function testReinstallationWithDifferentConfig(
        uint160 limit1,
        uint160 limit2,
        uint48 renewPeriod1,
        uint48 renewPeriod2
    ) public {
        renewPeriod1 = uint48(bound(renewPeriod1, 1, type(uint48).max / 2));
        renewPeriod2 = uint48(bound(renewPeriod2, 1, type(uint48).max / 2));
        limit1 = uint160(bound(limit1, 1, MAX_ETH));
        limit2 = uint160(bound(limit2, 1, MAX_ETH));

        uint48 start1 = uint48(block.timestamp);
        _installSpender(start1, limit1, renewPeriod1);

        // Uninstall
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");

        // Reinstall with different configuration
        // Use future start to avoid timing issues during installation
        uint48 start2 = uint48(block.timestamp + 1 days);

        address[] memory spenders = new address[](1);
        spenders[0] = _spenderAddress;
        uint48[] memory starts = new uint48[](1);
        starts[0] = start2;
        uint160[] memory limits = new uint160[](1);
        limits[0] = limit2;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod2;

        bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);

        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), initData);

        // Verify new configuration
        assertEq(_spender.start(address(_account), _spenderAddress), start2);
        assertEq(_spender.limit(address(_account), _spenderAddress), limit2);
        assertEq(_spender.renewPeriod(address(_account), _spenderAddress), renewPeriod2);
    }

    function testSpendingAtVariousTimepoints(uint160 limit, uint48 renewPeriod, uint48 timeOffset) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max / 20));
        limit = uint160(bound(limit, 1, MAX_ETH));
        timeOffset = uint48(bound(timeOffset, 0, renewPeriod * 10));

        uint48 start = uint48(block.timestamp);
        _installSpender(start, limit, renewPeriod);

        uint48 timepoint = start + timeOffset;
        vm.warp(timepoint);

        uint256 expectedPeriod = timeOffset / renewPeriod;

        (uint256 spending, uint256 available) = _spender.spendingAt(address(_account), _spenderAddress, expectedPeriod);

        assertEq(spending, 0);
        assertEq(available, limit);
    }

    function testZeroAmountTransfer(uint160 limit, uint48 renewPeriod) public {
        vm.assume(renewPeriod > 0);
        vm.assume(limit > 0);

        uint48 start = uint48(block.timestamp);
        _installSpender(start, limit, renewPeriod);

        uint256 recipientBalanceBefore = _recipient.balance;

        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, 0);

        assertEq(_recipient.balance, recipientBalanceBefore);
        assertEq(_spender.spent(address(_account), _spenderAddress, 0), 0);
    }

    function testExactLimitSpending(uint160 limit, uint48 renewPeriod) public {
        vm.assume(renewPeriod > 0);
        limit = uint160(bound(limit, 1, MAX_ETH));

        uint48 start = uint48(block.timestamp);
        _installSpender(start, limit, renewPeriod);

        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, limit);

        assertEq(_spender.spent(address(_account), _spenderAddress, 0), limit);

        (uint256 spending, uint256 available) = _spender.spendingAt(address(_account), _spenderAddress, 0);
        assertEq(spending, limit);
        assertEq(available, 0);
    }

    function testMultipleSpendersIndependence(uint160 limit, uint160 amount1, uint160 amount2) public {
        limit = uint160(bound(limit, 1, MAX_ETH / 2));
        amount1 = uint160(bound(amount1, 1, limit));
        amount2 = uint160(bound(amount2, 1, limit));

        address spender2 = makeAddr("spender2");

        // Avoid stack too deep
        {
            // Install two spenders
            address[] memory spenders = new address[](2);
            spenders[0] = _spenderAddress;
            spenders[1] = spender2;

            uint48 start = uint48(block.timestamp);
            uint48[] memory starts = new uint48[](2);
            starts[0] = start;
            starts[1] = start;

            uint160[] memory limits = new uint160[](2);
            limits[0] = limit;
            limits[1] = limit;

            uint48 renewPeriod = 1 days;
            uint48[] memory renewPeriods = new uint48[](2);
            renewPeriods[0] = renewPeriod;
            renewPeriods[1] = renewPeriod;

            bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);
            (
                uint256[] memory moduleTypeIds,
                address[] memory modules,
                bytes[] memory initDatas
            ) = _buildInstallationModules(initData);

            _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
        }

        // Spend from both spenders
        vm.prank(_spenderAddress);
        _spender.transferFrom(address(_account), _recipient, amount1);

        vm.prank(spender2);
        _spender.transferFrom(address(_account), _recipient, amount2);

        // Verify independence
        assertEq(_spender.spent(address(_account), _spenderAddress, 0), amount1);
        assertEq(_spender.spent(address(_account), spender2, 0), amount2);
    }

    function testUnsetSpendingConfig(uint48 renewPeriod, uint160 limit1, uint160 limit2) public {
        renewPeriod = uint48(bound(renewPeriod, 1, 365 days));
        limit1 = uint160(bound(limit1, 1, MAX_ETH));
        limit2 = uint160(bound(limit2, 1, MAX_ETH));

        uint48 start = uint48(block.timestamp);

        // Install with 2 spenders
        address spender2 = makeAddr("spender2");
        address[] memory spenders = new address[](2);
        spenders[0] = _spenderAddress;
        spenders[1] = spender2;

        uint48[] memory starts = new uint48[](2);
        starts[0] = start;
        starts[1] = start;

        uint160[] memory limits = new uint160[](2);
        limits[0] = limit1;
        limits[1] = limit2;

        uint48[] memory renewPeriods = new uint48[](2);
        renewPeriods[0] = renewPeriod;
        renewPeriods[1] = renewPeriod;

        bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initData);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        // Verify both spenders are installed
        assertEq(_spender.spendersCount(address(_account)), 2);
        assertEq(_spender.limit(address(_account), _spenderAddress), limit1);

        // Unset first spender
        vm.prank(address(_account));
        _spender.unsetSpendingConfig(_spenderAddress);

        // Verify first spender is removed
        assertEq(_spender.spendersCount(address(_account)), 1);
        assertEq(_spender.limit(address(_account), _spenderAddress), 0);
        assertEq(_spender.start(address(_account), _spenderAddress), 0);

        // Second spender should still be there
        assertEq(_spender.limit(address(_account), spender2), limit2);
    }

    function _installSpender(uint48 start, uint160 limit, uint48 renewPeriod) private {
        address[] memory spenders = new address[](1);
        spenders[0] = _spenderAddress;

        uint48[] memory starts = new uint48[](1);
        starts[0] = start;

        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;

        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;

        bytes memory initData = abi.encode(spenders, starts, limits, renewPeriods);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initData);

        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    function _buildInstallationModules(
        bytes memory initData
    ) private view returns (uint256[] memory, address[] memory, bytes[] memory) {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;

        address[] memory modules = new address[](1);
        modules[0] = address(_spender);

        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        return (moduleTypeIds, modules, initDatas);
    }
}
