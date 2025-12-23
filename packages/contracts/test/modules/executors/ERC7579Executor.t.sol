// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579ExecutorMock} from "../../../src/mocks/modules/ERC7579Mock.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {ERC7579Executor} from "../../../src/modules/executors/ERC7579Executor.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579ExecutorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579ExecutorMock private _executor;
    OpenAccount private _account;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy executor
        _executor = new ERC7579ExecutorMock();

        // Deploy account
        _account = new OpenAccountMock();

        vm.deal(address(_account), MAX_ETH);
    }

    function testExecute(uint256 arg1, uint256 arg2) public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules();
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        bytes32 salt = bytes32(0);
        bytes32 mode = Mode.unwrap(
            ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
                ERC7579Utils.EXECTYPE_DEFAULT,
                ModeSelector.wrap(0x00000000),
                ModePayload.wrap(0x00000000)
            )
        );

        bytes memory data = abi.encodePacked(
            address(_target),
            uint256(0),
            abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (arg1, arg2))
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579Executor.ERC7579ExecutorOperationExecuted(address(_account), salt, mode, data);

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(arg1, arg2);

        bytes[] memory returnData = _executor.execute(address(_account), salt, mode, data);
        assertEq(returnData.length, 1);
    }

    function testExecuteBatch(uint256 arg1, uint256 arg2) public {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules();
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        bytes32 salt = bytes32(0);
        bytes32 mode = Mode.unwrap(
            ERC7579Utils.CALLTYPE_BATCH.encodeMode(
                ERC7579Utils.EXECTYPE_DEFAULT,
                ModeSelector.wrap(0x00000000),
                ModePayload.wrap(0x00000000)
            )
        );

        // Create batch execution data
        Execution[] memory execution = new Execution[](2);
        execution[0] = Execution({
            target: address(_target),
            value: 1 ether,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionExtra, ())
        });
        execution[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (arg1, arg2))
        });

        bytes memory data = execution.encodeBatch();

        vm.expectEmit(true, true, true, true);
        emit ERC7579Executor.ERC7579ExecutorOperationExecuted(address(_account), salt, mode, data);

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(arg1, arg2);

        vm.expectCall(address(_target), execution[0].callData);
        vm.expectCall(address(_target), execution[1].callData);

        bytes[] memory returnData = _executor.execute(address(_account), salt, mode, data);
        assertEq(returnData.length, 2);
    }

    function _buildInstallationModules()
        private
        view
        returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas)
    {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        modules[0] = address(_executor);
        initDatas[0] = "";
    }
}
