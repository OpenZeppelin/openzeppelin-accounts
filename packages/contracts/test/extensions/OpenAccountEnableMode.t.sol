// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccountEnableMode} from "../../src/extensions/OpenAccountEnableMode.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock} from "../../src/mocks/modules/ERC7579Mock.sol";
import {CallReceiverMock} from "../../src/mocks/CallReceiverMock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract OpenAccountEnableModeMock is OpenAccountEnableMode {
    constructor() EIP712("MyAccount", "1") {}
}

contract OpenAccountEnableModeTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;
    bytes1 private constant ENABLE_MODE_PREFIX = 0x01;
    bytes32 private constant ENABLE_MODULES_TYPEHASH =
        keccak256("EnableModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)");
    string private constant NAME = "MyAccount";
    string private constant VERSION = "1";

    CallReceiverMock private _target;

    uint256 private _initialValidatorPrivateKey = 0x1234;
    address private _initialValidatorSigner = vm.addr(_initialValidatorPrivateKey);
    OpenAccountEnableMode private _account;
    ERC7579ValidatorMock private _initialValidator;
    ERC7579ValidatorMock private _newValidator;

    uint256 private _newValidatorPrivateKey = 0x5678;
    address private _newValidatorSigner = vm.addr(_newValidatorPrivateKey);

    bytes32 private _accountDomainSeparator;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Setup account and install initial validator module
        _account = new OpenAccountEnableModeMock();
        _initialValidator = new ERC7579ValidatorMock();
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(address(_initialValidator), _initialValidatorSigner);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
        vm.deal(address(_account), MAX_ETH);

        // Deploy a new validator to install via enable mode
        _newValidator = new ERC7579ValidatorMock();

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

        (, string memory name, string memory version, uint256 chainId, address verifyingContract, , ) = _account
            .eip712Domain();
        _accountDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    function testEnableMode(address bundler) public {
        vm.assume(bundler.code.length == 0);

        (uint256 nonce, bytes memory initData, bytes memory installationSignature) = _prepareInstallationSignature(
            address(_newValidator),
            _newValidatorSigner,
            _initialValidatorPrivateKey
        );

        // Create user operation that will be validated by the newly installed validator
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with the new validator's signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_newValidator);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        userOp.signature = abi.encode(
            moduleTypeIds,
            modules,
            initDatas,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Expect the target function call event
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was installed
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testEnableModeWithBatchExecution(address bundler, uint256 argA, uint256 argB) public {
        vm.assume(bundler.code.length == 0);

        (uint256 nonce, bytes memory initData, bytes memory installationSignature) = _prepareInstallationSignature(
            address(_newValidator),
            _newValidatorSigner,
            _initialValidatorPrivateKey
        );

        // Create batch execution
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: address(_target),
            value: 1 ether,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionExtra, ())
        });
        executions[1] = Execution({
            target: address(_target),
            value: 0,
            callData: abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (argA, argB))
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
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_newValidatorPrivateKey, userOpHash);
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_newValidator);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        userOp.signature = abi.encode(
            moduleTypeIds,
            modules,
            initDatas,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Expect the batch execution events
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledWithArgs(argA, argB);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was installed
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testEnableModeWithInvalidInstallationSignature(address bundler, uint256 wrongKey) public {
        vm.assume(bundler.code.length == 0);
        vm.assume(wrongKey != _initialValidatorPrivateKey);

        // secp256k1 order
        wrongKey = bound(wrongKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1);
        (uint256 nonce, bytes memory initData, bytes memory installationSignature) = _prepareInstallationSignature(
            address(_newValidator),
            _newValidatorSigner,
            wrongKey
        );

        // Create user operation that will be validated by the newly installed validator
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with the new validator's signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_newValidator);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        userOp.signature = abi.encode(
            moduleTypeIds,
            modules,
            initDatas,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Execute should fail due to invalid installation signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectRevert(); // Should revert due to signature validation failure
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was NOT installed
        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testEnableModeWithInvalidUserOpSignature(address bundler, uint256 wrongKey) public {
        vm.assume(wrongKey != _newValidatorPrivateKey);
        vm.assume(bundler.code.length == 0);

        // secp256k1 order
        wrongKey = bound(wrongKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1);

        // Get a valid installation signature from the owner
        (uint256 nonce, bytes memory initData, bytes memory installationSignature) = _prepareInstallationSignature(
            address(_newValidator),
            _newValidatorSigner,
            _initialValidatorPrivateKey
        );

        // Create user operation
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with wrong key
        // This simulates an attacker trying to execute arbitrary calls with just an installation signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            wrongKey, // WRONG KEY!
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Encode the enable mode signature
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_newValidator);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        userOp.signature = abi.encode(
            moduleTypeIds,
            modules,
            initDatas,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Execute should fail due to invalid UserOp signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectRevert(); // Should revert due to UserOp signature validation failure
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the module was NOT installed
        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testEnableModeWithMalformedSignature(address bundler, bytes memory malformedSignature) public {
        vm.assume(bundler.code.length == 0);

        // Create user operation with malformed signature (too short)
        PackedUserOperation memory userOp = _prepareUserOperation(_prepareNonce(address(_newValidator)));
        userOp.signature = malformedSignature;

        // Execute should fail due to malformed signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectRevert(); // Should revert due to signature decoding failure
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function testNormalOperationWithoutEnableMode(address bundler, bytes1 prefix) public {
        vm.assume(bundler.code.length == 0);
        vm.assume(prefix != ENABLE_MODE_PREFIX);

        // Create normal nonce (without enable mode prefix);
        uint256 nonce = (uint256(uint8(prefix)) << 248) | (uint256(uint160(address(_initialValidator))) << 88);

        // Create user operation
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign with initial validator's signer
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_initialValidatorPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        // Expect the target function call event
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify the new validator was NOT installed (since enable mode wasn't triggered)
        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testEnableModeWithMultipleModules(address bundler) public {
        vm.assume(bundler.code.length == 0);

        // Deploy additional validators
        ERC7579ValidatorMock validator2 = new ERC7579ValidatorMock();
        ERC7579ValidatorMock validator3 = new ERC7579ValidatorMock();

        uint256 validator2PrivateKey = 0x9999;
        address validator2Signer = vm.addr(validator2PrivateKey);

        uint256 validator3PrivateKey = 0xaaaa;
        address validator3Signer = vm.addr(validator3PrivateKey);

        // Create nonce with enable mode prefix followed by the first validator address
        uint256 nonce = _prepareNonce(address(_newValidator));

        // Create init data for all validators
        bytes memory initData1 = abi.encodePacked(_newValidatorSigner);
        bytes memory initData2 = abi.encodePacked(validator2Signer);
        bytes memory initData3 = abi.encodePacked(validator3Signer);

        // Create arrays for multiple modules
        uint256[] memory moduleTypeIds = new uint256[](3);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[2] = MODULE_TYPE_VALIDATOR;

        address[] memory modules = new address[](3);
        modules[0] = address(_newValidator);
        modules[1] = address(validator2);
        modules[2] = address(validator3);

        bytes[] memory initDatas = new bytes[](3);
        initDatas[0] = initData1;
        initDatas[1] = initData2;
        initDatas[2] = initData3;

        // Create EIP-712 signature for multiple module installation
        bytes32[] memory initDataHashes = new bytes32[](3);
        initDataHashes[0] = keccak256(initData1);
        initDataHashes[1] = keccak256(initData2);
        initDataHashes[2] = keccak256(initData3);

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    ENABLE_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_initialValidatorPrivateKey, typedDataHash);
        bytes memory installationSignature = abi.encodePacked(r, s, v);

        // Create user operation that will be validated by the first newly installed validator
        PackedUserOperation memory userOp = _prepareUserOperation(nonce);

        // Sign the user operation with the first new validator's signer
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        bytes memory userOpSignature = abi.encodePacked(r2, s2, v2);

        // Encode the enable mode signature for multiple modules
        userOp.signature = abi.encode(
            moduleTypeIds,
            modules,
            initDatas,
            abi.encodePacked(_initialValidator, installationSignature),
            userOpSignature
        );

        // Expect the target function call event
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        // Execute the user operation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // Verify all modules were installed
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator2), bytes("")));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator3), bytes("")));
    }

    function _prepareNonce(address validator) internal pure returns (uint256 nonce) {
        return (uint256(uint8(ENABLE_MODE_PREFIX)) << 248) | (uint256(uint160(address(validator))) << 88);
    }

    function _prepareInstallationSignature(
        address newValidator,
        address newSigner,
        uint256 signerPrivateKey
    ) internal view returns (uint256 nonce, bytes memory initData, bytes memory installationSignature) {
        // Create nonce with enable mode prefix followed by the userOp validator address
        nonce = _prepareNonce(newValidator);

        // Create init data for the new validator
        initData = abi.encodePacked(newSigner);

        // Create EIP-712 signature for module installation
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(newValidator);
        bytes32[] memory initDataHashes = new bytes32[](1);
        initDataHashes[0] = keccak256(initData);

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    ENABLE_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, typedDataHash);
        return (nonce, initData, abi.encodePacked(r, s, v));
    }

    function _prepareUserOperation(uint256 nonce) internal view returns (PackedUserOperation memory userOp) {
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
                            abi.encodeCall(CallReceiverMock.mockFunctionExtra, ())
                        )
                    )
                ),
                preVerificationGas: 100000,
                accountGasLimits: bytes32(abi.encodePacked(uint128(500000), uint128(200000))),
                gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });
    }

    function _buildInstallationModules(
        address validator,
        address validatorSigner
    ) private pure returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(validator);
        initDatas[0] = abi.encodePacked(validatorSigner);
    }
}
