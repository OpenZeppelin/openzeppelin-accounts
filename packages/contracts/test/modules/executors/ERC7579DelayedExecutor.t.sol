// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579DelayedExecutorMock} from "../../../src/mocks/modules/ERC7579Mock.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {ERC7579DelayedExecutor} from "../../../src/modules/executors/ERC7579DelayedExecutor.sol";
import {console} from "forge-std/console.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579DelayedExecutorTestMock is ERC7579DelayedExecutorMock {}

contract ERC7579DelayedExecutorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    CallReceiverMock private _target;
    ERC7579DelayedExecutorTestMock private _delayedExecutor;
    OpenAccount private _account;
    address private _other;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy delayed executor
        _delayedExecutor = new ERC7579DelayedExecutorTestMock();

        // Deploy account
        _account = new OpenAccountMock();

        // Create other address
        _other = makeAddr("other");
    }

    function testDelayedExecutorInstallation(uint32 initialDelay, uint32 initialExpiration) public {
        bytes memory initData = abi.encodePacked(initialDelay, initialExpiration);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(
            address(_account),
            initialDelay,
            uint48(block.timestamp)
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), initialExpiration);

        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        assertTrue(_delayedExecutor.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_delayedExecutor.isModuleType(999)); // Random invalid type

        (uint32 delay, uint32 pendingDelay, uint48 effectTime) = _delayedExecutor.getDelay(address(_account));
        assertEq(delay, initialDelay);
        assertEq(pendingDelay, 0);
        assertEq(effectTime, 0);

        assertEq(_delayedExecutor.getExpiration(address(_account)), initialExpiration);
    }

    function testDelayedExecutorInstallationWithDefaults() public {
        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(
            address(_account),
            _delayedExecutor.minSetback(),
            uint48(block.timestamp)
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(
            address(_account),
            _delayedExecutor.defaultExpiration()
        );

        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), "");

        (uint32 delay, , ) = _delayedExecutor.getDelay(address(_account));
        assertEq(delay, _delayedExecutor.minSetback());
        assertEq(_delayedExecutor.getExpiration(address(_account)), _delayedExecutor.defaultExpiration());
    }

    function testDelayedExecutorUninstallation(uint32 initialDelay, uint32 initialExpiration) public {
        bytes memory initData = abi.encodePacked(initialDelay, initialExpiration);
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        vm.expectEmit(true, true, true, true);
        console.log(_delayedExecutor.minSetback());
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(
            address(_account),
            0,
            uint48(block.timestamp) + uint48(Math.max(initialDelay, _delayedExecutor.minSetback()))
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), 0);

        vm.prank(address(_account));
        _delayedExecutor.onUninstall("");

        assertEq(_delayedExecutor.getExpiration(address(_account)), 0);
    }

    function testOperationStates(uint32 initialDelay, uint32 initialExpiration, bytes32 salt) public {
        bytes memory initData = abi.encodePacked(initialDelay, initialExpiration);
        vm.assume(initialDelay > 0);
        vm.assume(initialExpiration > 0);
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();

        // Initially Unknown
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Unknown)
        );

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Now Scheduled
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Scheduled)
        );

        // After delay, becomes Ready
        vm.warp(uint48(block.timestamp) + initialDelay);
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Ready)
        );

        // Execute operation
        _delayedExecutor.execute(address(_account), salt, mode, data);

        // Now Executed
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Executed)
        );
    }

    function testOperationExpiration(uint32 initialDelay, uint32 initialExpiration, bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();
        bytes memory initData = abi.encodePacked(initialDelay, initialExpiration);
        vm.assume(initialDelay > 0);
        vm.assume(initialExpiration > 0);
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // After delay, becomes Ready
        vm.warp(block.timestamp + initialDelay);
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Ready)
        );

        // After expiration, becomes Expired
        vm.warp(block.timestamp + initialExpiration);
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Expired)
        );
    }

    function testOperationCancellation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();
        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Cancel operation
        bytes32 operationId = _delayedExecutor.hashOperation(address(_account), salt, mode, data);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorOperationCanceled(address(_account), operationId);

        vm.prank(address(_account));
        _delayedExecutor.cancel(address(_account), salt, mode, data);

        // Now Canceled
        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Canceled)
        );
    }

    function testScheduleOperation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();

        // Doesn't work if uninstalled
        vm.expectRevert(ERC7579DelayedExecutor.ERC7579ExecutorModuleNotInstalled.selector);
        vm.prank(address(_account));
        _delayedExecutor.schedule(_other, salt, mode, data);

        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        bytes32 operationId = _delayedExecutor.hashOperation(address(_account), salt, mode, data);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorOperationScheduled(
            address(_account),
            operationId,
            salt,
            mode,
            data,
            uint48(block.timestamp + _delayedExecutor.minSetback())
        );

        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        (uint48 scheduledAt, uint48 executableAt, uint48 expiresAt) = _delayedExecutor.getSchedule(
            address(_account),
            salt,
            mode,
            data
        );
        assertEq(scheduledAt, block.timestamp);
        assertEq(executableAt, block.timestamp + _delayedExecutor.minSetback());
        assertEq(expiresAt, block.timestamp + _delayedExecutor.minSetback() + _delayedExecutor.defaultExpiration());

        // Try to schedule again
        vm.expectRevert();
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);
    }

    function testExecuteOperation(bytes32 salt, uint256 arg1, uint256 arg2) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode(arg1, arg2);
        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Try to execute before delay
        vm.expectRevert();
        _delayedExecutor.execute(address(_account), salt, mode, data);

        // Wait for delay
        vm.warp(block.timestamp + _delayedExecutor.minSetback());

        // Execute operation
        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(arg1, arg2);

        bytes[] memory returnData = _delayedExecutor.execute(address(_account), salt, mode, data);
        assertEq(returnData.length, 1);

        // Try to execute again
        vm.expectRevert();
        _delayedExecutor.execute(address(_account), salt, mode, data);
    }

    function testExecuteExpiredOperation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();
        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Wait for delay + expiration
        vm.warp(block.timestamp + _delayedExecutor.minSetback() + _delayedExecutor.defaultExpiration());

        // Try to execute expired operation
        vm.expectRevert();
        _delayedExecutor.execute(address(_account), salt, mode, data);
    }

    function testSetDelay() public {
        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        uint32 newDelay = 5 days;
        uint48 expectedEffectTime = uint48(block.timestamp + _delayedExecutor.minSetback());

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(address(_account), newDelay, expectedEffectTime);

        vm.prank(address(_account));
        _delayedExecutor.setDelay(newDelay);

        (uint32 currentDelay, uint32 pendingDelay, uint48 effectTime) = _delayedExecutor.getDelay(address(_account));
        assertEq(currentDelay, _delayedExecutor.minSetback());
        assertEq(pendingDelay, newDelay);
        assertEq(effectTime, expectedEffectTime);

        // After effect time, new delay should be active
        vm.warp(effectTime);
        (currentDelay, pendingDelay, effectTime) = _delayedExecutor.getDelay(address(_account));
        assertEq(currentDelay, newDelay);
        assertEq(pendingDelay, 0);
        assertEq(effectTime, 0);
    }

    function testSetExpiration() public {
        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        uint32 newExpiration = 30 days;

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), newExpiration);

        vm.prank(address(_account));
        _delayedExecutor.setExpiration(newExpiration);

        assertEq(_delayedExecutor.getExpiration(address(_account)), newExpiration);
    }

    function testCancelScheduledOperation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();

        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Cancel operation while scheduled
        vm.prank(address(_account));
        _delayedExecutor.cancel(address(_account), salt, mode, data);

        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Canceled)
        );

        // Try to cancel again
        vm.expectRevert();
        vm.prank(address(_account));
        _delayedExecutor.cancel(address(_account), salt, mode, data);
    }

    function testCancelReadyOperation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();

        bytes memory initData = abi.encodePacked(_delayedExecutor.minSetback(), _delayedExecutor.defaultExpiration());
        _account.initialize(MODULE_TYPE_EXECUTOR, address(_delayedExecutor), initData);

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Wait for delay
        vm.warp(block.timestamp + _delayedExecutor.minSetback());

        // Cancel operation while ready
        vm.prank(address(_account));
        _delayedExecutor.cancel(address(_account), salt, mode, data);

        assertEq(
            uint8(_delayedExecutor.state(address(_account), salt, mode, data)),
            uint8(ERC7579DelayedExecutor.OperationState.Canceled)
        );

        // Try to cancel again
        vm.expectRevert();
        vm.prank(address(_account));
        _delayedExecutor.cancel(address(_account), salt, mode, data);
    }

    function _prepareDataAndMode() private view returns (bytes memory data, bytes32 mode) {
        return _prepareDataAndMode(42, 0x1234);
    }

    function _prepareDataAndMode(uint256 arg1, uint256 arg2) private view returns (bytes memory data, bytes32 mode) {
        return (
            abi.encodePacked(
                address(_target),
                uint256(0),
                abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (arg1, arg2))
            ),
            Mode.unwrap(
                ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
                    ERC7579Utils.EXECTYPE_DEFAULT,
                    ModeSelector.wrap(0x00000000),
                    ModePayload.wrap(0x00000000)
                )
            )
        );
    }
}
