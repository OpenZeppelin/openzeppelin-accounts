// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579MultisigValidator} from "../../../src/modules/validators/ERC7579MultisigValidator.sol";
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

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579MultisigValidatorMock is ERC7579MultisigValidator {}

contract ERC7579MultisigValidatorTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579MultisigValidatorMock private _multisig;
    OpenAccount private _account;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy multisig
        _multisig = new ERC7579MultisigValidatorMock();

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

    function testValidateUserOp(uint256 numSigners) public {
        numSigners = bound(numSigners, 1, 10);
        (uint256[] memory keys, bytes[] memory signers) = _buildSigners(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(signers.length));
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        PackedUserOperation memory userOp = _prepareUserOperation();
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        bytes[] memory signatures = new bytes[](signers.length);

        for (uint256 i = 0; i < signers.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], userOpHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        bytes memory multisigSignature = abi.encode(signers, signatures);
        userOp.signature = multisigSignature;

        vm.prank(address(_account));
        uint256 result = _multisig.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function testValidateUserOpInsufficientSignatures(uint256 numSigners) public {
        numSigners = bound(numSigners, 1, 10);
        (, bytes[] memory signers) = _buildSigners(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(
                signers,
                // forge-lint: disable-next-line(unsafe-typecast)
                uint64(numSigners)
            );
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        PackedUserOperation memory userOp = _prepareUserOperation();
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        (uint256[] memory signingKeys, bytes[] memory signingSigners) = _buildSigners(numSigners - 1, 1);
        bytes[] memory signatures = new bytes[](signingSigners.length);

        for (uint256 i = 0; i < signingSigners.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKeys[i], userOpHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        bytes memory multisigSignature = abi.encode(signingSigners, signatures);
        userOp.signature = multisigSignature;

        vm.prank(address(_account));
        uint256 result = _multisig.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    function _buildSigners(uint256 numSigners) private pure returns (uint256[] memory keys, bytes[] memory signers) {
        return _buildSigners(numSigners, 0);
    }

    function _buildSigners(
        uint256 numSigners,
        uint256 start
    ) private pure returns (uint256[] memory keys, bytes[] memory signers) {
        keys = new uint256[](numSigners);
        signers = new bytes[](numSigners);
        for (uint256 i = 0; i < numSigners; i++) {
            keys[i] = i + start + 1;
            signers[i] = abi.encodePacked(vm.addr(keys[i]));
        }
        return (keys, signers);
    }

    function _prepareUserOperation() private view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: uint256(uint160(bytes20(address(_multisig)))) << 96,
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

    function _buildInstallationModules(
        bytes[] memory signers,
        uint64 threshold
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_multisig);
        initDatas[0] = abi.encode(signers, threshold);
    }
}
