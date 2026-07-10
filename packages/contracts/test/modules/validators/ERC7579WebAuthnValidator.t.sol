// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579WebAuthnValidator} from "../../../src/modules/validators/ERC7579WebAuthnValidator.sol";
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
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";

contract ERC7579WebAuthnValidatorMock is ERC7579WebAuthnValidator {}

contract ERC7579WebAuthnValidatorTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579WebAuthnValidatorMock private _validator;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy validator
        _validator = new ERC7579WebAuthnValidatorMock();

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

    function testIsValidSignatureWithSender(bytes32 messageHash, uint256 seed) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        // Install WebAuthn signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));

        // Prepare WebAuthn message
        (bytes32 hashToSign, bytes memory authenticatorData, string memory clientDataJSON) = _prepareWebAuthnMessage(
            messageHash
        );

        // Sign message
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, hashToSign);
        bytes memory signature = abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON);

        // Test validation through isValidSignatureWithSender
        vm.prank(address(_account));
        assertEq(
            _validator.isValidSignatureWithSender(address(this), messageHash, signature),
            IERC1271.isValidSignature.selector
        );
    }

    function testValidateUserOp(uint256 seed, uint256 nonce) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

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

        PackedUserOperation memory userOp = _prepareUserOperation(nonce);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);

        // Create WebAuthn assertion signature
        (bytes32 hashToSign, bytes memory authenticatorData, string memory clientDataJSON) = _prepareWebAuthnMessage(
            userOpHash
        );
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, hashToSign);
        userOp.signature = abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON);

        vm.prank(address(_account));
        assertEq(_validator.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function _prepareWebAuthnMessage(
        bytes32 hash
    ) private pure returns (bytes32 hashToSign, bytes memory authenticatorData, string memory clientDataJSON) {
        clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(hash)),
            '"}'
        );

        // Create authenticatorData (32 bytes rpIdHash + 1 byte flags + 4 bytes counter)
        // Flags 0x05 = AUTH_DATA_FLAGS_UP | AUTH_DATA_FLAGS_UV
        authenticatorData = abi.encodePacked(
            bytes32(0), // rpIdHash (zero for testing)
            bytes1(0x05), // flags
            bytes4(0) // counter
        );

        return (
            sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))),
            authenticatorData,
            clientDataJSON
        );
    }

    function _prepareUserOperation(uint256 nonce) private view returns (PackedUserOperation memory) {
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
