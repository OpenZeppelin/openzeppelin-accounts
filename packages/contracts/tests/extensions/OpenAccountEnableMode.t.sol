// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccountEnableMode} from "../../src/extensions/OpenAccountEnableMode.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC7579Utils, Execution, Mode, ModeSelector, ModePayload} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock} from "../mocks/modules/ERC7579Mock.sol";
import {ReceiverMock} from "../mocks/ReceiverMock.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7579ModuleMock} from "../mocks/modules/ERC7579Mock.sol";
import {console} from "forge-std/console.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract OpenAccountEnableModeMock is OpenAccountEnableMode {
    constructor() EIP712("MyAccount", "1") {}
}

contract OpenAccountEnableModeTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;
    bytes1 private constant ENABLE_MODE_PREFIX = 0x01;
    bytes32 private constant INSTALL_MODULE_TYPEHASH =
        keccak256(
            "InstallModule(uint256 moduleTypeId,address module,bytes initData,uint256 nonce)"
        );
    string private constant NAME = "MyAccount";
    string private constant VERSION = "1";

    ReceiverMock private _target;

    uint256 private _accountPrivateKey = 0x1234;
    address private _signer = vm.addr(_accountPrivateKey);
    OpenAccountEnableMode private _account;
    ERC7579ValidatorMock private _initialValidator;
    ERC7579ValidatorMock private _newValidator;

    uint256 private _newValidatorPrivateKey = 0x5678;
    address private _newValidatorSigner = vm.addr(_newValidatorPrivateKey);

    bytes32 private _accountDomainSeparator;

    function setUp() public {
        // Deploy target contract
        _target = new ReceiverMock();

        // Setup account and install initial validator module
        _account = new OpenAccountEnableModeMock();
        _initialValidator = new ERC7579ValidatorMock();
        _account.initialize(
            MODULE_TYPE_VALIDATOR,
            address(_initialValidator),
            abi.encodePacked(_signer)
        );
        vm.deal(address(_account), MAX_ETH);

        // Deploy a new validator to install via enable mode
        _newValidator = new ERC7579ValidatorMock();

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

        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            ,

        ) = _account.eip712Domain();
        _accountDomainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    function testEnableMode() public {
        (
            uint256 nonce,
            bytes memory initData,
            bytes memory installationSignature
        ) = _prepareInstallationSignature(
                address(_newValidator),
                _newValidatorSigner,
                _accountPrivateKey
            );

        // Create user operation that will be validated by the newly installed validator
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with the new validator's signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08))
                .getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        userOp.signature = abi.encode(
            MODULE_TYPE_VALIDATOR,
            address(_newValidator),
            initData,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Expect the module installation event
        vm.expectEmit(true, true, false, false);
        emit ERC7579ModuleMock.ModuleInstalledReceived(
            address(_account),
            initData
        );

        // Expect the target function call event
        vm.expectEmit(true, true, true, false);
        emit ReceiverMock.MockFunctionCalledMsg(address(_account), 1 ether);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        _account.entryPoint().handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was installed
        assertTrue(
            _account.isModuleInstalled(
                MODULE_TYPE_VALIDATOR,
                address(_newValidator),
                bytes("")
            )
        );
    }

    function testEnableModeWithBatchExecution(
        uint256 argA,
        uint256 argB
    ) public {
        (
            uint256 nonce,
            bytes memory initData,
            bytes memory installationSignature
        ) = _prepareInstallationSignature(
                address(_newValidator),
                _newValidatorSigner,
                _accountPrivateKey
            );

        // Create batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: address(_target),
            value: 1 ether,
            callData: abi.encodeCall(ReceiverMock.mockFunctionMsg, ())
        });
        executions[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(
                ReceiverMock.mockFunctionWithArgs,
                (argA, argB)
            )
        });

        // Create user operation with batch execution
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);
        userOp.callData = abi.encodeCall(
            AccountERC7579.execute,
            (
                Mode.unwrap(
                    ERC7579Utils.CALLTYPE_BATCH.encodeMode(
                        ERC7579Utils.EXECTYPE_DEFAULT,
                        ModeSelector.wrap(0x00000000),
                        ModePayload.wrap(0x00000000)
                    )
                ),
                executions.encodeBatch()
            )
        );

        // Sign the user operation with the new validator's signer
        bytes32 userOpHash = IEntryPointExtra(
            address(ERC4337Utils.ENTRYPOINT_V08)
        ).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            userOpHash
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        userOp.signature = abi.encode(
            MODULE_TYPE_VALIDATOR,
            address(_newValidator),
            initData,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Expect the module installation event
        vm.expectEmit(true, true, false, false);
        emit ERC7579ModuleMock.ModuleInstalledReceived(
            address(_account),
            initData
        );

        // Expect the batch execution events
        vm.expectEmit(true, true, true, false);
        emit ReceiverMock.MockFunctionCalledMsg(address(_account), 1 ether);
        vm.expectEmit(true, true, true, false);
        emit ReceiverMock.MockFunctionCalledWithArgs(argA, argB);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        _account.entryPoint().handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was installed
        assertTrue(
            _account.isModuleInstalled(
                MODULE_TYPE_VALIDATOR,
                address(_newValidator),
                bytes("")
            )
        );
    }

    function testEnableModeWithInvalidInstallationSignature(
        uint256 wrongKey
    ) public {
        // secp256k1 order
        wrongKey = bound(
            wrongKey,
            1,
            0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 -
                1
        );
        (
            uint256 nonce,
            bytes memory initData,
            bytes memory installationSignature
        ) = _prepareInstallationSignature(
                address(_newValidator),
                _newValidatorSigner,
                wrongKey
            );

        // Create user operation that will be validated by the newly installed validator
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with the new validator's signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08))
                .getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        userOp.signature = abi.encode(
            MODULE_TYPE_VALIDATOR,
            address(_newValidator),
            initData,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Execute should fail due to invalid installation signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        IEntryPoint entrypoint = _account.entryPoint();
        vm.expectRevert(); // Should revert due to signature validation failure
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was NOT installed
        assertFalse(
            _account.isModuleInstalled(
                MODULE_TYPE_VALIDATOR,
                address(_newValidator),
                bytes("")
            )
        );
    }

    function testEnableModeWithMalformedSignature(
        bytes memory malformedSignature
    ) public {
        // Create user operation with malformed signature (too short)
        PackedUserOperation memory userOp = _prepareUserOperation(
            _prepareNonce(address(_newValidator))
        );
        userOp.signature = malformedSignature;

        // Execute should fail due to malformed signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        IEntryPoint entrypoint = _account.entryPoint();
        vm.expectRevert(); // Should revert due to signature decoding failure
        entrypoint.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function testNormalOperationWithoutEnableMode(bytes1 prefix) public {
        vm.assume(prefix != ENABLE_MODE_PREFIX);
        // Create normal nonce (without enable mode prefix);
        uint256 nonce = (uint256(uint8(prefix)) << 248) |
            (uint256(uint160(address(_initialValidator))) << 88);

        // Create user operation
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign with initial validator's signer
        bytes32 userOpHash = IEntryPointExtra(
            address(ERC4337Utils.ENTRYPOINT_V08)
        ).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _accountPrivateKey,
            userOpHash
        );
        userOp.signature = abi.encodePacked(r, s, v);

        // Expect the target function call event
        vm.expectEmit(true, true, true, false);
        emit ReceiverMock.MockFunctionCalledMsg(address(_account), 1 ether);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        _account.entryPoint().handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the new validator was NOT installed (since enable mode wasn't triggered)
        assertFalse(
            _account.isModuleInstalled(
                MODULE_TYPE_VALIDATOR,
                address(_newValidator),
                bytes("")
            )
        );
    }

    function _prepareNonce(address validator) internal returns (uint256 nonce) {
        return
            (uint256(uint8(ENABLE_MODE_PREFIX)) << 248) |
            (uint256(uint160(address(validator))) << 88);
    }

    function _prepareInstallationSignature(
        address newValidator,
        address newSigner,
        uint256 signerPrivateKey
    )
        internal
        returns (
            uint256 nonce,
            bytes memory initData,
            bytes memory installationSignature
        )
    {
        // Create nonce with enable mode prefix followed by the userOp validator address
        nonce = _prepareNonce(newValidator);

        // Create init data for the new validator
        initData = abi.encodePacked(newSigner);

        // Create EIP-712 signature for module installation
        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    INSTALL_MODULE_TYPEHASH,
                    MODULE_TYPE_VALIDATOR,
                    address(newValidator),
                    keccak256(initData),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            signerPrivateKey,
            typedDataHash
        );
        return (nonce, initData, abi.encodePacked(r, s, v));
    }

    function _prepareUserOperation(
        uint256 nonce
    ) internal returns (PackedUserOperation memory userOp) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: nonce,
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
                            uint256(1 ether),
                            abi.encodeCall(ReceiverMock.mockFunctionMsg, ())
                        )
                    )
                ),
                preVerificationGas: 100000,
                accountGasLimits: bytes32(
                    abi.encodePacked(uint128(200000), uint128(200000))
                ),
                gasFees: bytes32(
                    abi.encodePacked(uint128(1000000), uint128(1000000))
                ),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });
    }
}
