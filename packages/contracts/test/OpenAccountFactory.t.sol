// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccount, OpenAccountFactory} from "../src/OpenAccountFactory.sol";
import {
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock, ERC7579ExecutorMock} from "../src/mocks/modules/ERC7579Mock.sol";
import {CallReceiverMock} from "../src/mocks/CallReceiverMock.sol";

contract OpenAccountFactoryTest is Test {
    using ERC7579Utils for *;

    OpenAccountFactory private _factory;
    ERC7579ValidatorMock private _validator;
    ERC7579ExecutorMock private _executor;
    CallReceiverMock private _target;

    function setUp() public {
        _factory = new OpenAccountFactory();
        _validator = new ERC7579ValidatorMock();
        _executor = new ERC7579ExecutorMock();
        _target = new CallReceiverMock();
    }

    function testCloneAndInitializeWithSingleModule(address signer) public {
        (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) = _buildSingleModule(
            address(_validator),
            signer
        );

        address deployed = _factory.createAndInitialize(
            moduleTypeIds,
            modules,
            initDatas,
            Mode.wrap(0),
            "",
            bytes32(0)
        );
        assertEq(deployed, _factory.predictAddress(moduleTypeIds, modules, initDatas, Mode.wrap(0), "", bytes32(0)));

        assertTrue(OpenAccount(payable(deployed)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
    }

    function testCloneAndInitializeWithMultipleModules(address signer) public {
        (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) = _buildMultipleModules(
            address(_validator),
            address(_executor),
            signer
        );

        address deployed = _factory.createAndInitialize(
            moduleTypeIds,
            modules,
            initDatas,
            Mode.wrap(0),
            "",
            bytes32(0)
        );
        assertEq(deployed, _factory.predictAddress(moduleTypeIds, modules, initDatas, Mode.wrap(0), "", bytes32(0)));

        assertTrue(OpenAccount(payable(deployed)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
        assertTrue(OpenAccount(payable(deployed)).isModuleInstalled(MODULE_TYPE_EXECUTOR, address(_executor), ""));
    }

    function testCreateAndInitializeIdempotent(address signer) public {
        (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) = _buildSingleModule(
            address(_validator),
            signer
        );

        assertEq(
            _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), "", bytes32(0)),
            _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), "", bytes32(0))
        );
    }

    function testCreateAndInitializeWithSingleConfig(address signer) public {
        (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) = _buildSingleModule(
            address(_validator),
            signer
        );

        Mode configMode = ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        bytes memory configCalldata = abi.encodePacked(
            address(_target),
            uint256(0),
            abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (42, 100))
        );

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(42, 100);

        address deployed = _factory.createAndInitialize(
            moduleTypeIds,
            modules,
            initDatas,
            configMode,
            configCalldata,
            bytes32(0)
        );

        assertEq(
            deployed,
            _factory.predictAddress(moduleTypeIds, modules, initDatas, configMode, configCalldata, bytes32(0))
        );
        assertTrue(OpenAccount(payable(deployed)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
    }

    function testCreateAndInitializeWithBatchConfig(address signer) public {
        (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) = _buildSingleModule(
            address(_validator),
            signer
        );

        Mode configMode = ERC7579Utils.CALLTYPE_BATCH.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        Execution[] memory configExecution = new Execution[](2);
        configExecution[0] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (10, 20))
        });
        configExecution[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (30, 40))
        });

        bytes memory configCalldata = configExecution.encodeBatch();

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(10, 20);
        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(30, 40);

        address deployed = _factory.createAndInitialize(
            moduleTypeIds,
            modules,
            initDatas,
            configMode,
            configCalldata,
            bytes32(0)
        );

        assertEq(
            deployed,
            _factory.predictAddress(moduleTypeIds, modules, initDatas, configMode, configCalldata, bytes32(0))
        );
        assertTrue(OpenAccount(payable(deployed)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
    }

    function _buildSingleModule(
        address validator,
        address signer
    ) private pure returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = validator;
        initDatas[0] = abi.encodePacked(signer);
    }

    function _buildMultipleModules(
        address validator,
        address executor,
        address signer
    ) private pure returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](2);
        modules = new address[](2);
        initDatas = new bytes[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = validator;
        initDatas[0] = abi.encodePacked(signer);
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        modules[1] = executor;
        initDatas[1] = bytes("");
    }
}
