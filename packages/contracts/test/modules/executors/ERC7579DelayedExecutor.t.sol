// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {ERC7579DelayedExecutor} from "../../../src/modules/executors/ERC7579DelayedExecutor.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";

contract ERC7579DelayedExecutorTestMock is ERC7579DelayedExecutor {
    function schedule(address account, bytes32 salt, bytes32 mode, bytes calldata data) public virtual {
        _schedule(account, salt, mode, data);
    }

    function cancel(address account, bytes32 salt, bytes32 mode, bytes calldata data) public virtual {
        _cancel(account, salt, mode, data);
    }

    function execute(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes memory data
    ) public virtual returns (bytes[] memory) {
        return _execute(account, salt, mode, data);
    }
}

contract ERC7579DelayedExecutorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    CallReceiverMock private _target;
    ERC7579DelayedExecutorTestMock private _delayedExecutor;
    OpenAccount private _account;
    address private _other;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy delayed executor
        _delayedExecutor = new ERC7579DelayedExecutorTestMock();

        // Deploy factory
        _factory = new OpenAccountFactory();

        // Create other address
        _other = makeAddr("other");
    }

    function testDelayedExecutorInstallation(uint32 initialDelay, uint32 initialExpiration) public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, initialExpiration);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        assertTrue(_delayedExecutor.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_delayedExecutor.isModuleType(999)); // Random invalid type

        (uint32 delay, uint32 pendingDelay, uint48 effectTime) = _delayedExecutor.getDelay(address(_account));
        assertEq(delay, initialDelay);
        assertEq(pendingDelay, 0);
        assertEq(effectTime, 0);

        assertEq(_delayedExecutor.getExpiration(address(_account)), initialExpiration);
    }

    function testDelayedExecutorInstallationWithDefaults() public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (uint32 delay, , ) = _delayedExecutor.getDelay(address(_account));
        assertEq(delay, _delayedExecutor.delayChangeWindow());
        assertEq(_delayedExecutor.getExpiration(address(_account)), _delayedExecutor.defaultExpiration());
    }

    function testDelayedExecutorUninstallation(uint32 initialDelay, uint32 initialExpiration) public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, initialExpiration);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(
            address(_account),
            0,
            uint48(block.timestamp) + uint48(initialDelay)
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), 0);

        vm.prank(address(_account));
        _delayedExecutor.onUninstall("");

        assertEq(_delayedExecutor.getExpiration(address(_account)), 0);
    }

    function testReinstallUsesSetDelayTransitionRules(uint32 initialDelay, uint32 expiration, uint32 newDelay) public {
        vm.assume(initialDelay > 0);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, expiration);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        _delayedExecutor.onUninstall("");

        uint48 reinstallTime = uint48(block.timestamp);

        vm.prank(address(_account));
        _delayedExecutor.onInstall(abi.encodePacked(newDelay, expiration));

        (uint32 delay, uint32 pendingDelay, uint48 effectTime) = _delayedExecutor.getDelay(address(_account));
        bool immediate = newDelay == initialDelay;
        if (immediate) {
            assertEq(delay, newDelay);
            assertEq(pendingDelay, 0);
            assertEq(effectTime, 0);
        } else {
            assertEq(delay, initialDelay);
            assertEq(pendingDelay, newDelay);
            assertEq(
                effectTime,
                reinstallTime +
                    uint32(
                        newDelay > initialDelay
                            ? Math.min(newDelay, _delayedExecutor.delayChangeWindow())
                            : initialDelay - newDelay
                    )
            );
        }
    }

    function testOperationStates(uint32 initialDelay, uint32 initialExpiration, bytes32 salt) public {
        vm.assume(initialDelay > 0);
        vm.assume(initialExpiration > 0);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, initialExpiration);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
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
        vm.assume(initialDelay > 0);
        vm.assume(initialExpiration > 0);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, initialExpiration);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

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
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

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

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        bytes32 operationId = _delayedExecutor.hashOperation(address(_account), salt, mode, data);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorOperationScheduled(
            address(_account),
            operationId,
            salt,
            mode,
            data,
            uint48(block.timestamp + _delayedExecutor.delayChangeWindow())
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
        assertEq(executableAt, block.timestamp + _delayedExecutor.delayChangeWindow());
        assertEq(
            expiresAt,
            block.timestamp + _delayedExecutor.delayChangeWindow() + _delayedExecutor.defaultExpiration()
        );

        // Try to schedule again
        vm.expectRevert();
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);
    }

    function testExecuteOperation(bytes32 salt, uint256 arg1, uint256 arg2) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode(arg1, arg2);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Try to execute before delay
        vm.expectRevert();
        _delayedExecutor.execute(address(_account), salt, mode, data);

        // Wait for delay
        vm.warp(block.timestamp + _delayedExecutor.delayChangeWindow());

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
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Wait for delay + expiration
        vm.warp(block.timestamp + _delayedExecutor.delayChangeWindow() + _delayedExecutor.defaultExpiration());

        // Try to execute expired operation
        vm.expectRevert();
        _delayedExecutor.execute(address(_account), salt, mode, data);
    }

    function testSetDelay(uint32 initialDelay, uint32 newDelay) public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(initialDelay, _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        bool immediate = initialDelay == 0 || newDelay == initialDelay;
        uint48 expectedEffectTime = immediate
            ? uint48(block.timestamp)
            : newDelay > initialDelay
                ? uint48(block.timestamp) + uint48(Math.min(newDelay, _delayedExecutor.delayChangeWindow()))
                : uint48(block.timestamp) + uint48(initialDelay - newDelay);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(address(_account), newDelay, expectedEffectTime);

        vm.prank(address(_account));
        _delayedExecutor.setDelay(newDelay);

        (uint32 currentDelay, uint32 pendingDelay, uint48 effectTime) = _delayedExecutor.getDelay(address(_account));
        if (immediate) {
            assertEq(currentDelay, newDelay);
            assertEq(pendingDelay, 0);
            assertEq(effectTime, 0);
            return;
        }
        assertEq(currentDelay, initialDelay);
        assertEq(pendingDelay, newDelay);
        assertEq(effectTime, expectedEffectTime);

        vm.warp(effectTime);
        (currentDelay, pendingDelay, effectTime) = _delayedExecutor.getDelay(address(_account));
        assertEq(currentDelay, newDelay);
        assertEq(pendingDelay, 0);
        assertEq(effectTime, 0);
    }

    function testSetExpiration() public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        uint32 newExpiration = 30 days;

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), newExpiration);

        vm.prank(address(_account));
        _delayedExecutor.setExpiration(newExpiration);

        assertEq(_delayedExecutor.getExpiration(address(_account)), newExpiration);
    }

    function testCancelScheduledOperation(bytes32 salt) public {
        (bytes memory data, bytes32 mode) = _prepareDataAndMode();

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

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

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(_delayedExecutor.delayChangeWindow(), _delayedExecutor.defaultExpiration());
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        // Schedule operation
        vm.prank(address(_account));
        _delayedExecutor.schedule(address(_account), salt, mode, data);

        // Wait for delay
        vm.warp(block.timestamp + _delayedExecutor.delayChangeWindow());

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

    function _buildInstallationModules(
        uint32 initialDelay,
        uint32 initialExpiration
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        modules[0] = address(_delayedExecutor);
        initDatas[0] = abi.encodePacked(initialDelay, initialExpiration);
    }
}
