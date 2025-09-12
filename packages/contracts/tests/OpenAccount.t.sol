// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccount} from "../src/OpenAccount.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC7579Utils, Execution, Mode, ModeSelector, ModePayload} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock} from "./mocks/modules/ERC7579Mock.sol";
import {ReceiverMock} from "./mocks/ReceiverMock.sol";

contract AccountERC7702Test is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    ReceiverMock private _target;

    uint256 private _accountPrivateKey = 0x1234;
    address private _signer = vm.addr(_accountPrivateKey);
    OpenAccount private _account;
    ERC7579ValidatorMock private _validator;

    function setUp() public {
        // Deploy target contract
        _target = new ReceiverMock();

        // Setup account and install validator module
        _account = new OpenAccount();
        _validator = new ERC7579ValidatorMock();
        _account.initialize(
            MODULE_TYPE_VALIDATOR,
            address(_validator),
            abi.encodePacked(_signer)
        );
        vm.deal(address(_account), MAX_ETH);

        // Setup entrypoint
        address entrypoint = address(ERC4337Utils.ENTRYPOINT_V08);
        vm.deal(entrypoint, MAX_ETH);
        vm.etch(
            entrypoint,
            vm.readFileBinary(
                string.concat(
                    "node_modules/hardhat-predeploy/bin/",
                    Strings.toChecksumHexString(entrypoint),
                    ".bytecode"
                )
            )
        );
    }

    function testExecuteBatch(uint256 argA, uint256 argB) public {
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
            callData: abi.encodeCall(ReceiverMock.mockFunctionMsg, ())
        });
        execution[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(
                ReceiverMock.mockFunctionWithArgs,
                (argA, argB)
            )
        });

        // Pack the batch within a PackedUserOperation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(_account),
            nonce: uint256(uint160(bytes20(address(_validator)))) << 96, // Identify validator
            initCode: bytes(""),
            callData: abi.encodeCall(
                AccountERC7579.execute,
                (Mode.unwrap(mode), execution.encodeBatch())
            ),
            preVerificationGas: 100000,
            accountGasLimits: bytes32(
                abi.encodePacked(uint128(100000), uint128(100000))
            ),
            gasFees: bytes32(
                abi.encodePacked(uint128(1000000), uint128(1000000))
            ),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _accountPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08))
                .getUserOpHash(ops[0])
        );
        ops[0].signature = abi.encodePacked(r, s, v);

        // Expect the events to be emitted
        vm.expectEmit(true, true, true, true);
        emit ReceiverMock.MockFunctionCalledMsg(address(_account), 1 ether);
        vm.expectEmit(true, true, true, true);
        emit ReceiverMock.MockFunctionCalledWithArgs(argA, argB);

        // Execute the batch
        _account.entryPoint().handleOps(ops, payable(makeAddr("beneficiary")));
    }
}
