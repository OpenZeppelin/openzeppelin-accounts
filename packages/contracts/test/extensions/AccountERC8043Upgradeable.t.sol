// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {OpenAccountFactory, OpenAccountImplementation} from "../../src/OpenAccountFactory.sol";
import {
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579ValidatorMock} from "../../src/mocks/modules/ERC7579Mock.sol";
import {ERC7579NativeSpender} from "../../src/modules/executors/ERC7579NativeSpender.sol";
import {CallReceiverMock} from "../../src/mocks/CallReceiverMock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract AccountERC8043UpgradeableTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;

    uint256 private constant MAX_ETH = type(uint128).max;
    bytes4 private constant INIT_MODE_MAGIC_VALUE = 0x80438043;
    bytes32 private constant INIT_MODULES_TYPEHASH =
        keccak256("InitModules(uint256[] moduleTypeIds,address[] modules,bytes[] initDatas,uint256 nonce)");

    CallReceiverMock private _target;

    uint256 private _initialValidatorPrivateKey = 0x1234;
    address private _initialValidatorSigner = vm.addr(_initialValidatorPrivateKey);

    OpenAccountFactory private _factory;
    OpenAccountImplementation private _account;
    ERC7579ValidatorMock private _initialValidator;
    ERC7579ValidatorMock private _newValidator;

    uint256 private _newValidatorPrivateKey = 0x5678;
    address private _newValidatorSigner = vm.addr(_newValidatorPrivateKey);

    bytes32 private _accountDomainSeparator;

    function setUp() public {
        _target = new CallReceiverMock();

        _factory = new OpenAccountFactory();
        _initialValidator = new ERC7579ValidatorMock();

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(address(_initialValidator), _initialValidatorSigner);

        _account = OpenAccountImplementation(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
        vm.deal(address(_account), MAX_ETH);

        _newValidator = new ERC7579ValidatorMock();

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

    function testInitMode(address bundler) public {
        vm.assume(bundler.code.length == 0);

        uint256 nonce = _prepareNonce(address(_newValidator));
        bytes memory initData = abi.encodePacked(_newValidatorSigner);
        bytes memory initCode = _buildInitModeInitCode(
            nonce,
            address(_newValidator),
            initData,
            _initialValidatorPrivateKey
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithBatchExecution(address bundler, uint256 argA, uint256 argB) public {
        vm.assume(bundler.code.length == 0);

        uint256 nonce = _prepareNonce(address(_newValidator));
        bytes memory initData = abi.encodePacked(_newValidatorSigner);
        bytes memory initCode = _buildInitModeInitCode(
            nonce,
            address(_newValidator),
            initData,
            _initialValidatorPrivateKey
        );

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

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
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

        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_newValidatorPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);
        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledWithArgs(argA, argB);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithInvalidInstallationSignature(address bundler, uint256 wrongKey) public {
        vm.assume(bundler.code.length == 0);
        vm.assume(wrongKey != _initialValidatorPrivateKey);
        wrongKey = bound(wrongKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1);

        uint256 nonce = _prepareNonce(address(_newValidator));
        bytes memory initData = abi.encodePacked(_newValidatorSigner);
        bytes memory initCode = _buildInitModeInitCode(nonce, address(_newValidator), initData, wrongKey);

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert();
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithInvalidUserOpSignature(address bundler, uint256 wrongKey) public {
        vm.assume(bundler.code.length == 0);
        vm.assume(wrongKey != _newValidatorPrivateKey);
        wrongKey = bound(wrongKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1);

        uint256 nonce = _prepareNonce(address(_newValidator));
        bytes memory initData = abi.encodePacked(_newValidatorSigner);
        bytes memory initCode = _buildInitModeInitCode(
            nonce,
            address(_newValidator),
            initData,
            _initialValidatorPrivateKey
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            wrongKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert();
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithMalformedInitCode(address bundler, bytes memory malformedPayload) public {
        vm.assume(bundler.code.length == 0);

        // Prepend the magic so init mode is triggered, but ABI decoding will fail.
        bytes memory initCode = abi.encodePacked(INIT_MODE_MAGIC_VALUE, malformedPayload);

        PackedUserOperation memory userOp = _prepareUserOperation(_prepareNonce(address(_newValidator)), initCode);
        userOp.signature = bytes("irrelevant");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.expectRevert();
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function testNormalOperationWithoutInitMode(address bundler) public {
        vm.assume(bundler.code.length == 0);

        // Empty initCode means init mode is not triggered; normal validation applies.
        uint256 nonce = _prepareNonce(address(_initialValidator));
        PackedUserOperation memory userOp = _prepareUserOperation(nonce, bytes(""));

        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_initialValidatorPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithEmptyInstallationSignature(address bundler) public {
        vm.assume(bundler.code.length == 0);

        // Route through the already-installed _initialValidator because _newValidator won't be installed.
        uint256 nonce = _prepareNonce(address(_initialValidator));

        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_newValidator);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = abi.encodePacked(_newValidatorSigner);

        // Empty installationSignature: installation block is skipped entirely.
        bytes memory initCode = abi.encodePacked(
            INIT_MODE_MAGIC_VALUE,
            abi.encode(moduleTypeIds, modules, initDatas, bytes(""))
        );

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _initialValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        // No module was installed: empty installationSignature skips the installation block.
        assertFalse(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
    }

    function testInitModeWithMultipleModules(address bundler) public {
        vm.assume(bundler.code.length == 0);

        ERC7579ValidatorMock validator2 = new ERC7579ValidatorMock();
        ERC7579ValidatorMock validator3 = new ERC7579ValidatorMock();

        uint256 nonce = _prepareNonce(address(_newValidator));
        bytes memory initCode = _buildMultiModuleInitModeInitCode(nonce, address(validator2), address(validator3));

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _newValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CallReceiverMock.MockFunctionCalledExtra(address(_account), 1 ether);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_newValidator), bytes("")));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator2), bytes("")));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(validator3), bytes("")));
    }

    function testInitModeInstallsSpender(address bundler) public {
        vm.assume(bundler.code.length == 0);

        ERC7579NativeSpender spender = new ERC7579NativeSpender();
        address sessionKey = makeAddr("session-key");
        address recipient = makeAddr("recipient");
        bytes memory key = abi.encodePacked(sessionKey);

        // The owner only authorizes the executor install. The spender installs its validator role itself
        // during validation. The operation is validated by the initial validator and spends from the account
        // through the freshly installed executor role.
        uint256 nonce = _prepareNonce(address(_initialValidator));
        bytes memory initCode = _buildSpenderInitModeInitCode(nonce, address(spender), _spenderBundle(key));

        PackedUserOperation memory userOp = _prepareUserOperation(nonce, initCode);
        userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(1_000_000), uint128(300_000)));
        userOp.callData = abi.encodeCall(
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
                    address(spender),
                    uint256(0),
                    abi.encodeCall(ERC7579NativeSpender.transferFrom, (address(_account), key, recipient, 0.4 ether))
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            _initialValidatorPrivateKey,
            IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V09)).getUserOpHash(userOp)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        vm.prank(bundler, bundler);
        ERC4337Utils.ENTRYPOINT_V09.handleOps(ops, payable(makeAddr("beneficiary")));

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(spender), bytes("")));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(spender), bytes("")));
        assertEq(recipient.balance, 0.4 ether);
        assertEq(spender.spent(address(_account), key, 0), 0.4 ether);
    }

    /// @dev Spender install bundle: abi.encode(sessionKeysInitData, spendingInitData)
    function _spenderBundle(bytes memory key) private pure returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = key;
        uint48[] memory zero = new uint48[](1);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        return abi.encode(abi.encode(keys, zero, zero), abi.encode(keys, limits, renewPeriods));
    }

    function _buildSpenderInitModeInitCode(
        uint256 nonce,
        address spender,
        bytes memory bundle
    ) private view returns (bytes memory) {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](1);
        modules[0] = spender;
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = bundle;
        bytes32[] memory initDataHashes = new bytes32[](1);
        initDataHashes[0] = keccak256(bundle);

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    INIT_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_initialValidatorPrivateKey, typedDataHash);
        bytes memory installationSignature = abi.encodePacked(address(_initialValidator), abi.encodePacked(r, s, v));

        return
            abi.encodePacked(
                INIT_MODE_MAGIC_VALUE,
                abi.encode(moduleTypeIds, modules, initDatas, installationSignature)
            );
    }

    function _buildMultiModuleInitModeInitCode(
        uint256 nonce,
        address validator2,
        address validator3
    ) private view returns (bytes memory) {
        uint256[] memory moduleTypeIds = new uint256[](3);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[2] = MODULE_TYPE_VALIDATOR;

        address[] memory modules = new address[](3);
        modules[0] = address(_newValidator);
        modules[1] = validator2;
        modules[2] = validator3;

        bytes[] memory initDatas = new bytes[](3);
        initDatas[0] = abi.encodePacked(_newValidatorSigner);
        initDatas[1] = abi.encodePacked(vm.addr(0x9999));
        initDatas[2] = abi.encodePacked(vm.addr(0xaaaa));

        bytes32[] memory initDataHashes = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) initDataHashes[i] = keccak256(initDatas[i]);

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    INIT_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_initialValidatorPrivateKey, typedDataHash);
        bytes memory installationSignature = abi.encodePacked(address(_initialValidator), abi.encodePacked(r, s, v));

        return
            abi.encodePacked(
                INIT_MODE_MAGIC_VALUE,
                abi.encode(moduleTypeIds, modules, initDatas, installationSignature)
            );
    }

    function _prepareNonce(address validator) internal pure returns (uint256) {
        return uint256(uint160(validator)) << 96;
    }

    function _buildInitModeInitCode(
        uint256 nonce,
        address newValidator,
        bytes memory initData,
        uint256 installationSignerKey
    ) internal view returns (bytes memory) {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = newValidator;
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = initData;

        bytes32[] memory initDataHashes = new bytes32[](1);
        initDataHashes[0] = keccak256(initData);

        bytes32 typedDataHash = MessageHashUtils.toTypedDataHash(
            _accountDomainSeparator,
            keccak256(
                abi.encode(
                    INIT_MODULES_TYPEHASH,
                    keccak256(abi.encodePacked(moduleTypeIds)),
                    keccak256(abi.encodePacked(modules)),
                    keccak256(abi.encodePacked(initDataHashes)),
                    nonce
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(installationSignerKey, typedDataHash);

        // Prefix with the validator module address so the account's `isValidSignature` routes correctly.
        bytes memory installationSignature = abi.encodePacked(address(_initialValidator), abi.encodePacked(r, s, v));

        return
            abi.encodePacked(
                INIT_MODE_MAGIC_VALUE,
                abi.encode(moduleTypeIds, modules, initDatas, installationSignature)
            );
    }

    function _prepareUserOperation(
        uint256 nonce,
        bytes memory initCode
    ) internal view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: nonce,
                initCode: initCode,
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
        modules[0] = validator;
        initDatas[0] = abi.encodePacked(validatorSigner);
    }
}
