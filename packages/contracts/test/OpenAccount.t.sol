// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccount} from "../src/OpenAccount.sol";
import {
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock, ERC7579ExecutorMock} from "../src/mocks/modules/ERC7579Mock.sol";
import {CallReceiverMock} from "../src/mocks/CallReceiverMock.sol";
import {OpenAccountFactory, OpenAccountImplementation} from "../src/OpenAccountFactory.sol";
import {IERC1967} from "@openzeppelin/contracts/interfaces/IERC1967.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract OpenAccountImplementationV2 is OpenAccountImplementation {
    function accountId() public view virtual override returns (string memory) {
        return "@openzeppelin/contracts.AccountERC7579.v2.0.0";
    }
}

contract OpenAccountTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;

    uint256 private _accountPrivateKey = 0x1234;
    address private _signer = vm.addr(_accountPrivateKey);
    OpenAccount private _account;
    OpenAccountFactory private _factory;
    ERC7579ValidatorMock private _validator;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Setup account and install validator module
        _factory = new OpenAccountFactory();
        _validator = new ERC7579ValidatorMock();
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(address(_validator), _signer);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
        vm.deal(address(_account), MAX_ETH);

        // Setup entrypoint
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
    }

    function testInitializeWithSingleConfig() public {
        ERC7579ValidatorMock newValidator = new ERC7579ValidatorMock();
        CallReceiverMock configTarget = new CallReceiverMock();

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(address(newValidator), _signer);

        Mode configMode = ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        bytes memory configCalldata = abi.encodePacked(
            address(configTarget),
            uint256(0),
            abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (42, 100))
        );

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(42, 100);

        OpenAccount newAccount = OpenAccount(
            payable(
                _factory.createAndInitialize(
                    moduleTypeIds,
                    modules,
                    initDatas,
                    configMode,
                    configCalldata,
                    bytes32(uint256(1))
                )
            )
        );

        assertTrue(newAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), ""));
    }

    function testInitializeWithBatchConfig() public {
        ERC7579ValidatorMock newValidator = new ERC7579ValidatorMock();
        CallReceiverMock configTarget = new CallReceiverMock();

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(address(newValidator), _signer);

        Mode configMode = ERC7579Utils.CALLTYPE_BATCH.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        Execution[] memory configExecution = new Execution[](2);
        configExecution[0] = Execution({
            target: address(configTarget),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (10, 20))
        });
        configExecution[1] = Execution({
            target: address(configTarget),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (30, 40))
        });

        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(10, 20);
        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledWithArgs(30, 40);

        OpenAccount newAccount = OpenAccount(
            payable(
                _factory.createAndInitialize(
                    moduleTypeIds,
                    modules,
                    initDatas,
                    configMode,
                    configExecution.encodeBatch(),
                    bytes32(uint256(2))
                )
            )
        );

        assertTrue(newAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), ""));
    }

    function testInitializeWithMultipleModulesNoConfig() public {
        ERC7579ValidatorMock newValidator = new ERC7579ValidatorMock();
        ERC7579ExecutorMock newExecutor = new ERC7579ExecutorMock();

        // Build installation arrays for both validator and executor
        uint256[] memory moduleTypeIds = new uint256[](2);
        address[] memory modules = new address[](2);
        bytes[] memory initDatas = new bytes[](2);

        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(newValidator);
        initDatas[0] = abi.encodePacked(_signer);

        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        modules[1] = address(newExecutor);
        initDatas[1] = bytes("");

        // Initialize with multiple modules and no configuration call
        OpenAccount newAccount = OpenAccount(
            payable(
                _factory.createAndInitialize(
                    moduleTypeIds,
                    modules,
                    initDatas,
                    Mode.wrap(0),
                    bytes(""),
                    bytes32(uint256(3))
                )
            )
        );

        // Verify both modules are installed
        assertTrue(newAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), ""));
        assertTrue(newAccount.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(newExecutor), ""));
    }

    function testExecute(address bundler) public {
        vm.assume(bundler.code.length == 0);

        // Create the mode for single execution
        Mode mode = ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        // Pack the single execution within a PackedUserOperation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(_account),
            nonce: uint256(uint160(bytes20(address(_validator)))) << 96, // Identify validator
            initCode: bytes(""),
            callData: abi.encodeCall(
                AccountERC7579.execute,
                (
                    Mode.unwrap(mode),
                    abi.encodePacked(
                        address(_target),
                        uint256(1 ether),
                        abi.encodeCall(CallReceiverMock.mockFunctionExtra, ())
                    )
                )
            ),
            preVerificationGas: 100000,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
            gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _accountPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(ops[0])
        );
        ops[0].signature = abi.encodePacked(r, s, v);

        // Expect the event to be emitted
        vm.expectEmit(true, true, true, true);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        // Execute the single execution
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function testExecuteBatch(address bundler, uint256 argA, uint256 argB) public {
        vm.assume(bundler.code.length == 0);

        // Create the mode for batch execution
        Mode mode = ERC7579Utils.CALLTYPE_BATCH.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        Execution[] memory execution = new Execution[](2);
        execution[0] = Execution({
            target: address(_target),
            value: 1 ether,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionExtra, ())
        });
        execution[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (argA, argB))
        });

        // Pack the batch within a PackedUserOperation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(_account),
            nonce: uint256(uint160(bytes20(address(_validator)))) << 96, // Identify validator
            initCode: bytes(""),
            callData: abi.encodeCall(AccountERC7579.execute, (Mode.unwrap(mode), execution.encodeBatch())),
            preVerificationGas: 100000,
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
            gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _accountPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(ops[0])
        );
        ops[0].signature = abi.encodePacked(r, s, v);

        // Expect the events to be emitted
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledWithArgs(argA, argB);

        // Execute the batch
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function _buildInstallationModules(
        address validator,
        address signer
    ) private pure returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(validator);
        initDatas[0] = abi.encodePacked(signer);
    }

    function testUpgradeToV2FromAccount() public {
        // Deploy new implementation
        OpenAccountImplementationV2 newImplementation = new OpenAccountImplementationV2();

        // Upgrade via the account itself (direct call)
        vm.expectEmit(true, true, true, true);
        emit IERC1967.Upgraded(address(newImplementation));

        vm.prank(address(_account));
        UUPSUpgradeable(address(_account)).upgradeToAndCall(address(newImplementation), bytes(""));

        // Verify the upgrade
        OpenAccountImplementationV2 upgradedAccount = OpenAccountImplementationV2(payable(address(_account)));
        assertEq(upgradedAccount.accountId(), "@openzeppelin/contracts.AccountERC7579.v2.0.0");

        // Verify modules are still installed
        assertTrue(upgradedAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
    }

    function testUpgradeToV2ViaEntryPoint(address bundler) public {
        vm.assume(bundler.code.length == 0);

        // Deploy new implementation
        OpenAccountImplementationV2 newImplementation = new OpenAccountImplementationV2();

        // Create the mode for single execution
        Mode mode = ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0x00000000),
            ModePayload.wrap(0x00000000)
        );

        // Pack the upgrade call within a PackedUserOperation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(_account),
            nonce: uint256(uint160(bytes20(address(_validator)))) << 96,
            initCode: bytes(""),
            callData: abi.encodeCall(
                AccountERC7579.execute,
                (
                    Mode.unwrap(mode),
                    abi.encodePacked(
                        address(_account),
                        uint256(0),
                        abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(newImplementation), bytes("")))
                    )
                )
            ),
            preVerificationGas: 100000,
            accountGasLimits: bytes32(abi.encodePacked(uint128(200000), uint128(200000))),
            gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _accountPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(ops[0])
        );
        ops[0].signature = abi.encodePacked(r, s, v);

        // Expect the upgrade event
        vm.expectEmit(true, true, true, true);
        emit IERC1967.Upgraded(address(newImplementation));

        // Execute the upgrade via EntryPoint
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the upgrade
        OpenAccountImplementationV2 upgradedAccount = OpenAccountImplementationV2(payable(address(_account)));
        assertEq(upgradedAccount.accountId(), "@openzeppelin/contracts.AccountERC7579.v2.0.0");

        // Verify modules are still installed
        assertTrue(upgradedAccount.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_validator), ""));
    }
}
