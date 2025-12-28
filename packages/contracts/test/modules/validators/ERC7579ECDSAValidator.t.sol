// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579ECDSAValidator} from "../../../src/modules/validators/ERC7579ECDSAValidator.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";

contract ERC7579ECDSAValidatorMock is ERC7579ECDSAValidator {}

contract ERC7579ECDSAValidatorTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;

    uint256 private constant MAX_ETH = type(uint128).max;
    uint256 private constant SECP256K1_CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    CallReceiverMock private _target;
    ERC7579ECDSAValidatorMock private _validator;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy validator
        _validator = new ERC7579ECDSAValidatorMock();

        // Deploy factory
        _factory = new OpenAccountFactory();

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

    function testOnInstall(address signerAddr) public {
        vm.assume(signerAddr != address(0));

        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(signerAddr));

        assertEq(_validator.signer(address(_account)), signerAddr);
    }

    function testOnUninstall(address signerAddr) public {
        vm.assume(signerAddr != address(0));

        // Install first
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(signerAddr));
        assertEq(_validator.signer(address(_account)), signerAddr);

        // Uninstall
        vm.prank(address(_account));
        _validator.onUninstall("");
        assertEq(_validator.signer(address(_account)), address(0));
    }

    function testSetSigner(address initialSigner, address newSigner) public {
        vm.assume(newSigner != address(0) && initialSigner != address(0));

        // Install initial signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(initialSigner));

        // Set new signer
        vm.prank(address(_account));
        _validator.setSigner(address(_account), newSigner);

        assertEq(_validator.signer(address(_account)), newSigner);
    }

    function testIsValidSignatureWithSender(bytes32 messageHash, uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        address signerAddr = vm.addr(privateKey);

        // Install signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(signerAddr));

        // Sign message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Test validation through isValidSignatureWithSender
        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(address(this), messageHash, signature);

        assertEq(result, IERC1271.isValidSignature.selector);
    }

    function testIsValidSignatureWithSenderWrongSigner(
        bytes32 messageHash,
        uint256 correctKey,
        uint256 wrongKey
    ) public {
        correctKey = bound(correctKey, 1, SECP256K1_CURVE_ORDER - 1);
        wrongKey = bound(wrongKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(correctKey != wrongKey);

        address correctSigner = vm.addr(correctKey);

        // Install correct signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(correctSigner));

        // Sign with wrong key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Test validation should fail
        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(address(this), messageHash, signature);

        assertEq(result, bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderInvalidSignature(
        address initialSigner,
        bytes32 messageHash,
        bytes memory invalidSignature
    ) public {
        vm.assume(initialSigner != address(0));

        // Install signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(initialSigner));

        // Test validation with invalid signature
        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(address(this), messageHash, invalidSignature);

        assertEq(result, bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderNoSigner(bytes32 messageHash, uint256 privateKey) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);

        // Don't install any signer

        // Sign message
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Test validation should fail
        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(address(this), messageHash, signature);

        assertEq(result, bytes4(0xffffffff));
    }

    function testValidateUserOp(uint256 privateKey, uint256 nonce, uint256 value) public {
        privateKey = bound(privateKey, 1, SECP256K1_CURVE_ORDER - 1);
        value = bound(value, 0, MAX_ETH);
        address signerAddr = vm.addr(privateKey);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signerAddr);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
        vm.deal(address(_account), MAX_ETH);

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, value);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        // Sign with correct key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function testValidateUserOpWrongSigner(uint256 correctKey, uint256 wrongKey, uint256 nonce) public {
        correctKey = bound(correctKey, 1, SECP256K1_CURVE_ORDER - 1);
        wrongKey = bound(wrongKey, 1, SECP256K1_CURVE_ORDER - 1);
        vm.assume(correctKey != wrongKey);

        address correctSigner = vm.addr(correctKey);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(correctSigner);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, 0);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        // Sign with wrong key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        vm.prank(address(_account));
        uint256 result = _validator.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    function _prepareUserOperation(uint256 nonce, uint256 value) private view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: (uint256(uint160(bytes20(address(_validator)))) << 96) | nonce,
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
                        abi.encodePacked(address(_target), value, abi.encodeCall(CallReceiverMock.mockFunction, ()))
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
        address signer
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_validator);
        initDatas[0] = abi.encodePacked(signer);
    }
}
