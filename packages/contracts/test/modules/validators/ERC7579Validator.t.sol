// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579ValidatorMock} from "../../../src/mocks/modules/ERC7579Mock.sol";
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
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579ValidatorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579ValidatorMock private _validator;
    OpenAccount private _account;
    uint256 private _signerPrivateKey = 0x1234;
    address private _signer = vm.addr(_signerPrivateKey);
    uint256 private _otherPrivateKey = 0x5678;
    address private _other = vm.addr(_otherPrivateKey);

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy validator
        _validator = new ERC7579ValidatorMock();

        // Deploy account
        _account = new OpenAccountMock();

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

    function testValidatorInstallation() public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));
        assertTrue(_validator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(_validator.isModuleType(999)); // Random invalid type
    }

    function testValidateUserOp() public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));

        PackedUserOperation memory userOp = _prepareUserOperation();

        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPrivateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function testValidateUserOpInvalidSignature() public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));

        PackedUserOperation memory userOp = _prepareUserOperation();

        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_otherPrivateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    function testIsValidSignatureWithSender(bytes32 messageHash, address sender) public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(sender, messageHash, signature);

        assertEq(result, IERC1271.isValidSignature.selector);
    }

    function testIsValidSignatureWithSenderInvalid(bytes32 messageHash, address sender) public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_otherPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(sender, messageHash, signature);

        assertEq(result, bytes4(0xffffffff));
    }

    function testModuleInstallUninstall() public {
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_validator), abi.encodePacked(_signer));

        vm.prank(address(_account));
        _validator.onUninstall(""); // Must not revert

        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(_signer)); // Must not revert
    }

    function _prepareUserOperation() private view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: uint256(uint160(bytes20(address(_validator)))) << 96,
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
                        abi.encodePacked(
                            address(_target),
                            uint256(0),
                            abi.encodeCall(CallReceiverMock.mockFunction, ())
                        )
                    )
                ),
                preVerificationGas: 100000,
                accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
                gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });
    }
}
