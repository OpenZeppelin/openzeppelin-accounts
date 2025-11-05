// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579WebAuthnValidator} from "../../src/modules/ERC7579WebAuthnValidator.sol";
import {CallReceiverMock} from "../../src/mocks/CallReceiverMock.sol";
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
import {OpenAccount} from "../../src/OpenAccount.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579WebAuthnValidatorMock is ERC7579WebAuthnValidator {}

contract ERC7579WebAuthnValidatorTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579WebAuthnValidatorMock private _validator;
    OpenAccount private _account;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy validator
        _validator = new ERC7579WebAuthnValidatorMock();

        // Deploy account
        _account = new OpenAccountMock();

        vm.deal(address(_account), MAX_ETH);

        // Setup entrypoint
        address entrypoint = address(ERC4337Utils.ENTRYPOINT_V08);
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

    function testValidateUserOp(uint256 seed, uint256 nonce) public {
        uint256 privateKey = bound(seed, 1, P256.N - 1);
        (uint256 qx, uint256 qy) = vm.publicKeyP256(privateKey);

        // Install WebAuthn signer
        vm.prank(address(_account));
        _validator.onInstall(abi.encodePacked(qx, qy));

        PackedUserOperation memory userOp = _prepareUserOperation(nonce);
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08)).getUserOpHash(userOp);

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
}
