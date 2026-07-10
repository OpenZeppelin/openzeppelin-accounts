// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579P256Validator} from "../../../src/modules/validators/ERC7579P256Validator.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";

contract ERC7579P256ValidatorMock is ERC7579P256Validator {}

contract ERC7579P256ValidatorTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579P256ValidatorMock private _validator;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy validator
        _validator = new ERC7579P256ValidatorMock();

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

    function testOnInstall(uint256 seed) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));

        (bytes32 _qx, bytes32 _qy) = _validator.signer(address(_account));
        assertEq(_qx, bytes32(qx));
        assertEq(_qy, bytes32(qy));
    }

    function testOnUninstall(uint256 seed) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        // Install first
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));
        (bytes32 _qx, bytes32 _qy) = _validator.signer(address(_account));
        assertEq(_qx, bytes32(qx));
        assertEq(_qy, bytes32(qy));

        // Uninstall
        vm.prank(address(_account));
        _validator.onUninstall("");
        (bytes32 _qx2, bytes32 _qy2) = _validator.signer(address(_account));
        assertEq(_qx2, bytes32(0));
        assertEq(_qy2, bytes32(0));
    }

    function testSetSigner(uint256 seedA, uint256 seedB) public {
        uint256 privateKeyA = bound(seedA, 1, P256.N - 1);
        (uint256 newQxA, uint256 newQyA) = vm.publicKeyP256(privateKeyA);

        // Install initial signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(newQxA, newQyA));

        // Set new signer
        uint256 privateKeyB = bound(seedB, 1, P256.N - 1);
        (uint256 newQxB, uint256 newQyB) = vm.publicKeyP256(privateKeyB);
        vm.prank(address(_account));
        _validator.setSigner(address(_account), bytes32(newQxB), bytes32(newQyB));

        (bytes32 _qx2, bytes32 _qy2) = _validator.signer(address(_account));
        assertEq(_qx2, bytes32(newQxB));
        assertEq(_qy2, bytes32(newQyB));
    }

    function testIsValidSignatureWithSender(bytes32 messageHash, uint256 seed) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        // Install signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));

        // Sign message
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s);

        // Test validation through isValidSignatureWithSender
        vm.prank(address(_account));
        assertEq(
            _validator.isValidSignatureWithSender(address(this), messageHash, signature),
            IERC1271.isValidSignature.selector
        );
    }

    function testIsValidSignatureWithSenderWrongSigner(
        bytes32 messageHash,
        uint256 correctSeed,
        uint256 wrongSeed
    ) public {
        uint256 correctKey = bound(correctSeed, 1, P256.N - 1);
        uint256 wrongKey = bound(wrongSeed, 1, P256.N - 1);
        vm.assume(correctKey != wrongKey);

        (uint256 correctQx, uint256 correctQy) = vm.publicKeyP256(correctKey);

        // Install correct signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(correctQx, correctQy));

        // Sign with wrong key
        (bytes32 r, bytes32 s) = vm.signP256(wrongKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s);

        // Test validation should fail
        vm.prank(address(_account));
        assertEq(_validator.isValidSignatureWithSender(address(this), messageHash, signature), bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderInvalidSignature(
        bytes32 messageHash,
        uint256 seed,
        bytes memory invalidSignature
    ) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        // Install signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));

        // Test validation with invalid signature
        vm.prank(address(_account));
        bytes4 result = _validator.isValidSignatureWithSender(address(this), messageHash, invalidSignature);

        assertEq(result, bytes4(0xffffffff));
    }

    function testIsValidSignatureWithSenderNoSigner(bytes32 messageHash, uint256 seed) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);

        // Don't install any signer

        // Sign message
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s);

        // Test validation should fail
        vm.prank(address(_account));
        assertEq(_validator.isValidSignatureWithSender(address(this), messageHash, signature), bytes4(0xffffffff));
    }

    function testValidateUserOp(uint256 seed, uint256 nonce, uint256 value) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        value = bound(value, 0, MAX_ETH);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(qx, qy);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, value);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        // Sign with correct key
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s);
        userOp.signature = signature;

        vm.prank(address(_account));
        assertEq(_validator.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function testValidateUserOpWrongSigner(uint256 correctKey, uint256 wrongKey, uint256 nonce) public {
        correctKey = bound(correctKey, 1, P256.N - 1);
        wrongKey = bound(wrongKey, 1, P256.N - 1);
        vm.assume(correctKey != wrongKey);

        (uint256 correctQx, uint256 correctQy) = vm.publicKeyP256(correctKey);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(correctQx, correctQy);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, 0);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        // Sign with wrong key
        (bytes32 r, bytes32 s) = vm.signP256(wrongKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s);
        userOp.signature = signature;

        vm.prank(address(_account));
        assertEq(_validator.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
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
        uint256 qx,
        uint256 qy
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_validator);
        initDatas[0] = abi.encodePacked(qx, qy);
    }
}
