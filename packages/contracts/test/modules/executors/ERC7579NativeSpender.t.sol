// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579NativeSpender} from "../../../src/modules/executors/ERC7579NativeSpender.sol";
import {ERC7579SessionKeysValidator} from "../../../src/modules/validators/ERC7579SessionKeysValidator.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {IERC7579Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {BytesDecoderReference} from "../../helpers/BytesDecoderReference.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579NativeSpenderHarness is ERC7579NativeSpender {
    function validateSingleExecutionCalldata(
        bytes calldata callData
    ) external pure returns (bool isSingleAndValid, bytes calldata exec) {
        return _validateSingleExecutionCalldata(callData);
    }

    function validateTransferKey(bytes calldata exec) external view returns (bool success, bytes calldata callDataKey) {
        return _validateTransferKey(exec);
    }
}

contract ERC7579NativeSpenderTest is Test {
    using ERC7579Utils for *;

    uint256 private constant MAX_ETH = type(uint128).max;
    uint48 private constant MAX_TIMEPOINT = type(uint48).max >> 1;
    uint256 private constant GAS_BUDGET = 1 ether;

    ERC7579NativeSpenderHarness private _spender;
    OpenAccount private _account;

    address private _eoa;
    uint256 private _eoaKey;
    bytes private _key;

    address private _recipient;

    function setUp() public {
        _spender = new ERC7579NativeSpenderHarness();
        _account = new OpenAccountMock();

        vm.deal(address(_account), MAX_ETH);
        (_eoa, _eoaKey) = makeAddrAndKey("session-key-eoa");
        _key = abi.encodePacked(_eoa);
        _recipient = makeAddr("recipient");
    }

    function testIsModuleType() public view {
        assertTrue(_spender.isModuleType(MODULE_TYPE_VALIDATOR));
        assertTrue(_spender.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_spender.isModuleType(0));
        assertFalse(_spender.isModuleType(3));
    }

    function testInstallation(uint48 startOffset, uint160 limit, uint48 renewPeriod) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        limit = uint160(bound(limit, 1, MAX_ETH));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT - uint48(block.timestamp)));

        uint48 from = uint48(block.timestamp) + startOffset;

        _installSpenderBoth(from, 0, limit, renewPeriod);

        assertEq(_spender.limit(address(_account), _key), limit);
        assertEq(_spender.renewPeriod(address(_account), _key), renewPeriod);
        (uint48 storedFrom, ) = _spender.validity(address(_account), _key);
        assertEq(storedFrom, from);
    }

    function testEoaSelfCallTransferWithinLimit(uint160 limit, uint160 amount, uint48 renewPeriod) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        limit = uint160(bound(limit, 1, MAX_ETH));
        amount = uint160(bound(amount, 0, limit));

        _installSpenderBoth(uint48(block.timestamp), 0, limit, renewPeriod);

        uint256 recipientBalanceBefore = _recipient.balance;
        uint256 accountBalanceBefore = address(_account).balance;

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, amount);

        assertEq(_recipient.balance, recipientBalanceBefore + amount);
        assertEq(address(_account).balance, accountBalanceBefore - amount);
        assertEq(_spender.spent(address(_account), _key, 0), amount);
    }

    function testEoaSelfCallRevertsWhenExceedingLimit(uint160 limit, uint256 amount) public {
        limit = uint160(bound(limit, 1, MAX_ETH - 1));
        amount = bound(amount, limit + 1, MAX_ETH);

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        vm.prank(_eoa);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC7579NativeInsufficientAvailable(address,bytes,uint256)",
                address(_account),
                _key,
                amount
            )
        );
        _spender.transferFrom(address(_account), _key, _recipient, amount);
    }

    function testEoaSelfCallRevertsForWrongCaller(address wrongCaller) public {
        vm.assume(wrongCaller != _eoa && wrongCaller != address(_account) && wrongCaller != address(0));

        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        vm.prank(wrongCaller);
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderUnauthorized(address,bytes)", wrongCaller, _key));
        _spender.transferFrom(address(_account), _key, _recipient, 1);
    }

    function testEoaSelfCallRevertsForUnregisteredKey() public {
        // No install at all
        vm.prank(_eoa);
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderUnauthorized(address,bytes)", _eoa, _key));
        _spender.transferFrom(address(_account), _key, _recipient, 1);
    }

    function testPeriodCalculation(uint48 startOffset, uint48 renewPeriod, uint48 elapsed) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT / 2));
        elapsed = uint48(bound(elapsed, 0, MAX_TIMEPOINT - uint48(block.timestamp) - startOffset));

        uint48 from = uint48(block.timestamp) + startOffset;
        _installSpenderBoth(from, 0, 1 ether, renewPeriod);

        uint48 timepoint = from + elapsed;
        vm.warp(timepoint);

        (uint256 returnedStart, uint256 period) = _spender.periodAt(address(_account), _key, timepoint);
        assertEq(returnedStart, from);
        assertEq(period, elapsed / renewPeriod);
    }

    function testBatchTransferWithinLimit(uint160 limit, uint8 numRecipients) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        numRecipients = uint8(bound(numRecipients, 1, 10));

        uint160 amountPerRecipient = limit / numRecipients;

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        address[] memory recipients = new address[](numRecipients);
        uint256[] memory amounts = new uint256[](numRecipients);
        uint256 totalAmount = 0;

        for (uint256 i = 0; i < numRecipients; i++) {
            recipients[i] = makeAddr(string(abi.encodePacked("recipient", i)));
            amounts[i] = amountPerRecipient;
            totalAmount += amounts[i];
        }

        vm.prank(_eoa);
        _spender.batchTransferFrom(address(_account), _key, recipients, amounts);

        assertEq(_spender.spent(address(_account), _key, 0), totalAmount);

        for (uint256 i = 0; i < numRecipients; i++) {
            assertEq(recipients[i].balance, amounts[i]);
        }
    }

    function testSpendingAcrossPeriods(uint160 limit, uint8 numPeriods, uint48 renewPeriod) public {
        numPeriods = uint8(bound(numPeriods, 1, 5));
        limit = uint160(bound(limit, 2, MAX_ETH / numPeriods));
        renewPeriod = uint48(bound(renewPeriod, 1, MAX_TIMEPOINT / numPeriods));

        uint160 amountPerPeriod = limit / 2;

        _installSpenderBoth(uint48(block.timestamp), 0, limit, renewPeriod);

        for (uint256 i = 0; i < numPeriods; i++) {
            vm.prank(_eoa);
            _spender.transferFrom(address(_account), _key, _recipient, amountPerPeriod);
            assertEq(_spender.spent(address(_account), _key, i), amountPerPeriod);

            vm.warp(block.timestamp + renewPeriod);
        }
    }

    function testThirdInstallReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 2 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 2 days;
        bytes memory configBundle = abi.encode(keys, limits, renewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderAlreadyInstalled()"));
        _spender.onInstall(configBundle);
    }

    function testSecondInstallWithEmptyKeysReverts() public {
        // Validator install registers `_key`
        bytes[] memory keysOne = new bytes[](1);
        keysOne[0] = _key;
        uint48[] memory startsOne = new uint48[](1);
        startsOne[0] = uint48(block.timestamp);
        uint48[] memory endsOne = new uint48[](1);
        endsOne[0] = 0;

        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_spender);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = abi.encode(keysOne, startsOne, endsOne, _gasBudgets(keysOne.length, GAS_BUDGET));
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        // Executor install with zero keys must revert
        bytes[] memory emptyKeys = new bytes[](0);
        uint160[] memory emptyLimits = new uint160[](0);
        uint48[] memory emptyRenewPeriods = new uint48[](0);
        bytes memory emptyConfig = abi.encode(emptyKeys, emptyLimits, emptyRenewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderEmptyKeys()"));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), emptyConfig);
    }

    function testAddKeysWithPastStartReverts() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        // Move time forward so we have a real "past" timepoint to point at
        vm.warp(block.timestamp + 1 days);
        uint48 pastStart = uint48(block.timestamp - 1);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key2;
        uint48[] memory starts = new uint48[](1);
        starts[0] = pastStart;
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579NativeSpenderInvalidStart(uint256)", pastStart));
        _spender.addKeysWithConfig(keys, starts, ends, limits, renewPeriods);
    }

    function testReAddRemovedKey() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);
        assertFalse(_spender.isKey(address(_account), _key));

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = 0; // resolves to clock()
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 2 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 2 days;

        vm.prank(address(_account));
        _spender.addKeysWithConfig(keys, starts, ends, limits, renewPeriods);

        assertTrue(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 2 ether);
        assertEq(_spender.gasBudget(address(_account), _key), 0);
    }

    function testRemoveKeysClearsConfig() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;

        vm.prank(address(_account));
        _spender.removeKeys(keys);

        assertFalse(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 0);
        assertEq(_spender.renewPeriod(address(_account), _key), 0);
    }

    function testRemoveKeysPreservesHistoryAtHistoricalStart() public {
        uint48 from = uint48(block.timestamp);
        _installSpenderBoth(from, 0, 1 ether, 1 days);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, 0.5 ether);
        assertEq(_spender.spent(address(_account), _key, 0, from), 0.5 ether);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(keys);

        // Convenience accessor reads from validity().from which is now 0
        assertEq(_spender.spent(address(_account), _key, 0), 0);
        // Explicit-start overload still returns the history
        assertEq(_spender.spent(address(_account), _key, 0, from), 0.5 ether);
    }

    function testMultipleKeysIndependence(uint160 limit, uint160 amount1, uint160 amount2) public {
        limit = uint160(bound(limit, 2, MAX_ETH / 2));
        amount1 = uint160(bound(amount1, 0, limit));
        amount2 = uint160(bound(amount2, 0, limit));

        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        bytes[] memory keys = new bytes[](2);
        keys[0] = _key;
        keys[1] = key2;
        uint48[] memory starts = new uint48[](2);
        starts[0] = uint48(block.timestamp);
        starts[1] = uint48(block.timestamp);
        uint48[] memory ends = new uint48[](2);
        ends[0] = 0;
        ends[1] = 0;
        uint160[] memory limits = new uint160[](2);
        limits[0] = limit;
        limits[1] = limit;
        uint48[] memory renewPeriods = new uint48[](2);
        renewPeriods[0] = 1 days;
        renewPeriods[1] = 1 days;

        bytes memory initData = abi.encode(keys, starts, ends, limits, renewPeriods);
        _installAccountBoth(initData);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, _recipient, amount1);

        vm.prank(eoa2);
        _spender.transferFrom(address(_account), key2, _recipient, amount2);

        assertEq(_spender.spent(address(_account), _key, 0), amount1);
        assertEq(_spender.spent(address(_account), key2, 0), amount2);
    }

    function testUninstallClearsData(uint160 limit, uint160 spentAmount) public {
        limit = uint160(bound(limit, 1, MAX_ETH));
        spentAmount = uint160(bound(spentAmount, 0, limit));

        _installSpenderBoth(uint48(block.timestamp), 0, limit, 1 days);

        if (spentAmount > 0) {
            vm.prank(_eoa);
            _spender.transferFrom(address(_account), _key, _recipient, spentAmount);
        }

        uint256 nonceBefore = _spender.installation(address(_account));

        // Uninstalling the validator role bumps the nonce; the executor uninstall is a no-op for storage
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");
        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");

        assertGt(_spender.installation(address(_account)), nonceBefore);
        assertEq(_spender.spent(address(_account), _key, 0), 0);
        assertFalse(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key), 0);
    }

    // ----- Gas budget -----

    function testInstallSetsGasBudget(uint256 gasBudget) public {
        vm.expectEmit(address(_spender));
        emit ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorGasBudgetSet(address(_account), _key, gasBudget);
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days, gasBudget);
        assertEq(_spender.gasBudget(address(_account), _key), gasBudget);
    }

    function testValidatorInstallRevertsOnMismatchedGasBudgets(uint8 numGasBudgets) public {
        vm.assume(numGasBudgets != 1);
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorMismatchedGasBudgetsLength.selector,
                1,
                numGasBudgets
            )
        );
        _spender.onInstall(abi.encode(keys, new uint48[](1), new uint48[](1), new uint256[](numGasBudgets)));
    }

    function testValidateUserOpGasBudget(
        uint256 gasBudget,
        uint64 preVerificationGas,
        uint64 maxFeePerGas,
        bool withPaymaster
    ) public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days, gasBudget);

        PackedUserOperation memory userOp = _spendUserOp(preVerificationGas, maxFeePerGas);
        if (withPaymaster) {
            userOp.paymasterAndData = abi.encodePacked(makeAddr("paymaster"), uint128(100000), uint128(100000));
        }
        bytes32 userOpHash = _signUserOp(userOp);

        // Operations with a paymaster are charged as well.
        uint256 cost = (uint256(preVerificationGas) + 100000 + 100000 + (withPaymaster ? 200000 : 0)) * maxFeePerGas;

        vm.prank(address(_account));
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_spender.validateUserOp(userOp, userOpHash));
        assertEq(authorizer == address(0), cost <= gasBudget);
        assertEq(_spender.gasBudget(address(_account), _key), cost <= gasBudget ? gasBudget - cost : gasBudget);
    }

    function testValidateUserOpFromThirdPartyDoesNotDeduct(address caller) public {
        vm.assume(caller != address(_account));
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        PackedUserOperation memory userOp = _spendUserOp(100000, 1000000);
        bytes32 userOpHash = _signUserOp(userOp);

        vm.prank(caller);
        assertEq(_spender.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_spender.gasBudget(address(_account), _key), GAS_BUDGET);
    }

    function testAddKeysWithConfigStartsWithoutGasBudget() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);
        assertEq(_spender.gasBudget(address(_account), _key), 0);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        vm.prank(address(_account));
        _spender.addKeysWithConfig(keys, new uint48[](1), new uint48[](1), limits, renewPeriods);
        assertEq(_spender.gasBudget(address(_account), _key), 0);

        PackedUserOperation memory userOp = _spendUserOp(100000, 1000000);
        bytes32 userOpHash = _signUserOp(userOp);
        vm.prank(address(_account));
        assertEq(_spender.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);

        vm.prank(address(_account));
        _spender.setGasBudget(_key, GAS_BUDGET);
        vm.prank(address(_account));
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_spender.validateUserOp(userOp, userOpHash));
        assertEq(authorizer, address(0));
    }

    function testValidateUserOpRejectsSetGasBudgetCall() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        // A spending key cannot raise its own budget: the callData gate only allows spender transfers.
        PackedUserOperation memory userOp = _spendUserOp(100000, 1000000);
        userOp.callData = abi.encodeCall(
            IERC7579Execution.execute,
            (_singleMode(), _encodeSingle(abi.encodeCall(_spender.setGasBudget, (_key, type(uint256).max))))
        );
        bytes32 userOpHash = _signUserOp(userOp);

        vm.prank(address(_account));
        assertEq(_spender.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_spender.gasBudget(address(_account), _key), GAS_BUDGET);
    }

    // ----- CallData shape decoding -----

    function testValidateSingleExecutionCalldata(bytes memory exec) public view {
        (bool success, bytes memory decoded) = _spender.validateSingleExecutionCalldata(
            abi.encodeCall(IERC7579Execution.execute, (_singleMode(), exec))
        );
        assertTrue(success);
        assertEq(decoded, exec);
    }

    function testValidateSingleExecutionCalldataArbitraryWords(
        uint256 execOffset,
        uint256 execLength,
        bytes memory tail
    ) public view {
        _assertValidateSingleExecutionCalldataMatchesReference(_executeCalldata(execOffset, execLength, tail));
    }

    function testValidateSingleExecutionCalldataArbitraryLength(uint256 execLength, bytes memory tail) public view {
        _assertValidateSingleExecutionCalldataMatchesReference(_executeCalldata(0x40, execLength, tail));
    }

    function testValidateSingleExecutionCalldataOverflowingOffsetsAndLengths() public view {
        bytes[] memory callDatas = _overflowingExecuteCalldatas();
        for (uint256 i = 0; i < callDatas.length; ++i) {
            (bool success, bytes memory exec) = _spender.validateSingleExecutionCalldata(callDatas[i]);
            assertFalse(success);
            assertEq(exec.length, 0);
            _assertValidateSingleExecutionCalldataMatchesReference(callDatas[i]);
        }
    }

    function testValidateTransferKey(address account, bytes memory key, address to, uint256 amount) public view {
        (bool success, bytes memory decoded) = _spender.validateTransferKey(
            _encodeSingle(abi.encodeCall(_spender.transferFrom, (account, key, to, amount)))
        );
        assertTrue(success);
        assertEq(decoded, key);

        (success, decoded) = _spender.validateTransferKey(
            _encodeSingle(
                abi.encodeCall(_spender.batchTransferFrom, (account, key, new address[](0), new uint256[](0)))
            )
        );
        assertTrue(success);
        assertEq(decoded, key);
    }

    function testValidateTransferKeyArbitraryWords(
        uint256 keyOffset,
        uint256 keyLength,
        bytes memory tail
    ) public view {
        _assertValidateTransferKeyMatchesReference(_transferFromCalldata(keyOffset, keyLength, tail));
    }

    function testValidateTransferKeyArbitraryLength(uint256 keyLength, bytes memory tail) public view {
        _assertValidateTransferKeyMatchesReference(_transferFromCalldata(0x40, keyLength, tail));
    }

    function testValidateTransferKeyOverflowingOffsetsAndLengths() public view {
        bytes[] memory innerDatas = _overflowingTransferFromCalldatas();
        for (uint256 i = 0; i < innerDatas.length; ++i) {
            (bool success, bytes memory key) = _spender.validateTransferKey(_encodeSingle(innerDatas[i]));
            assertFalse(success);
            assertEq(key.length, 0);
            _assertValidateTransferKeyMatchesReference(innerDatas[i]);
        }
    }

    function testValidateUserOpOverflowingCalldata() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        PackedUserOperation memory userOp;
        userOp.sender = address(_account);
        userOp.signature = abi.encode(_key, "");

        bytes[] memory callDatas = _overflowingExecuteCalldatas();
        for (uint256 i = 0; i < callDatas.length; ++i) {
            userOp.callData = callDatas[i];
            vm.prank(address(_account));
            assertEq(_spender.validateUserOp(userOp, bytes32(0)), ERC4337Utils.SIG_VALIDATION_FAILED);
        }

        bytes[] memory innerDatas = _overflowingTransferFromCalldatas();
        for (uint256 i = 0; i < innerDatas.length; ++i) {
            userOp.callData = abi.encodeCall(IERC7579Execution.execute, (_singleMode(), _encodeSingle(innerDatas[i])));
            vm.prank(address(_account));
            assertEq(_spender.validateUserOp(userOp, bytes32(0)), ERC4337Utils.SIG_VALIDATION_FAILED);
        }
    }

    function testValidateUserOpOverflowingSignature() public {
        _installSpenderBoth(uint48(block.timestamp), 0, 1 ether, 1 days);

        PackedUserOperation memory userOp;
        userOp.sender = address(_account);
        userOp.callData = abi.encodeCall(
            IERC7579Execution.execute,
            (
                _singleMode(),
                _encodeSingle(abi.encodeCall(_spender.transferFrom, (address(_account), _key, _recipient, 1)))
            )
        );

        uint256 max = type(uint256).max;
        bytes[] memory signatures = new bytes[](4);
        signatures[0] = abi.encode(max, 0x60, 0, 0); // keyOffset + 0x20 overflows
        signatures[1] = abi.encode(0x40, max - 0x1f, 0, 0); // signatureOffset + 0x20 wraps to 0
        signatures[2] = abi.encode(0x40, 0x60, max, 0); // keyDataOffset + keyLength overflows
        signatures[3] = abi.encode(0x40, 0x60, 0, max - 0x7f); // signatureDataOffset + signatureLength wraps to 0
        for (uint256 i = 0; i < signatures.length; ++i) {
            userOp.signature = signatures[i];
            vm.prank(address(_account));
            assertEq(_spender.validateUserOp(userOp, bytes32(0)), ERC4337Utils.SIG_VALIDATION_FAILED);
        }
    }

    function _assertValidateSingleExecutionCalldataMatchesReference(bytes memory callData) private view {
        (bool success, bytes memory exec) = _spender.validateSingleExecutionCalldata(callData);
        (bool expectedSuccess, bytes memory expectedExec) = BytesDecoderReference.tryDecode(callData, 36, 4);
        assertEq(success, expectedSuccess);
        assertEq(exec, expectedExec);
    }

    function _assertValidateTransferKeyMatchesReference(bytes memory innerData) private view {
        (bool success, bytes memory key) = _spender.validateTransferKey(_encodeSingle(innerData));
        (bool expectedSuccess, bytes memory expectedKey) = BytesDecoderReference.tryDecode(innerData, 0x24, 4);
        assertEq(success, expectedSuccess);
        assertEq(key, expectedKey);
    }

    function _singleMode() private pure returns (bytes32) {
        return
            Mode.unwrap(
                ERC7579Utils.encodeMode(
                    ERC7579Utils.CALLTYPE_SINGLE,
                    ERC7579Utils.EXECTYPE_DEFAULT,
                    ModeSelector.wrap(0x00000000),
                    ModePayload.wrap(0x00000000)
                )
            );
    }

    /// @dev Encodes a single execution targeting the spender with zero value.
    function _encodeSingle(bytes memory innerData) private view returns (bytes memory) {
        return abi.encodePacked(address(_spender), uint256(0), innerData);
    }

    function _executeCalldata(
        uint256 execOffset,
        uint256 execLength,
        bytes memory tail
    ) private pure returns (bytes memory) {
        return abi.encodePacked(IERC7579Execution.execute.selector, _singleMode(), execOffset, execLength, tail);
    }

    function _transferFromCalldata(
        uint256 keyOffset,
        uint256 keyLength,
        bytes memory tail
    ) private view returns (bytes memory) {
        return
            abi.encodePacked(
                _spender.transferFrom.selector,
                uint256(uint160(address(_account))),
                keyOffset,
                keyLength,
                tail
            );
    }

    /// @dev `execute` calldata where the offset or length words make the bounds arithmetic overflow.
    function _overflowingExecuteCalldatas() private pure returns (bytes[] memory callDatas) {
        uint256 max = type(uint256).max;
        callDatas = new bytes[](5);
        callDatas[0] = _executeCalldata(max, 0, ""); // 4 + execOffset overflows
        callDatas[1] = _executeCalldata(max - 3, 0, ""); // 4 + execOffset wraps to 0
        callDatas[2] = _executeCalldata(max - 0x23, 0, ""); // execLenPos + 32 wraps to 0
        callDatas[3] = _executeCalldata(0x40, max, ""); // execStart + execLen overflows
        callDatas[4] = _executeCalldata(0x40, max - 0x63, ""); // execStart + execLen wraps to 0
    }

    /// @dev `transferFrom` calldata where the offset or length words make the bounds arithmetic overflow.
    function _overflowingTransferFromCalldatas() private view returns (bytes[] memory innerDatas) {
        uint256 max = type(uint256).max;
        innerDatas = new bytes[](5);
        innerDatas[0] = _transferFromCalldata(max, 0, ""); // 4 + keyOffset overflows
        innerDatas[1] = _transferFromCalldata(max - 3, 0, ""); // 4 + keyOffset wraps to 0
        innerDatas[2] = _transferFromCalldata(max - 0x23, 0, ""); // keyLenPos + 0x20 wraps to 0
        innerDatas[3] = _transferFromCalldata(0x40, max, ""); // keyDataStart + keyLen overflows
        innerDatas[4] = _transferFromCalldata(0x40, max - 0x63, ""); // keyDataStart + keyLen wraps to 0
    }

    // ----- Helpers -----

    function _spendUserOp(
        uint256 preVerificationGas,
        uint128 maxFeePerGas
    ) private view returns (PackedUserOperation memory userOp) {
        userOp.sender = address(_account);
        userOp.callData = abi.encodeCall(
            IERC7579Execution.execute,
            (
                _singleMode(),
                _encodeSingle(abi.encodeCall(_spender.transferFrom, (address(_account), _key, _recipient, 1)))
            )
        );
        userOp.preVerificationGas = preVerificationGas;
        userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(100000), uint128(100000)));
        userOp.gasFees = bytes32(abi.encodePacked(maxFeePerGas, maxFeePerGas));
    }

    /// @dev Signs `userOp` with the session key over an arbitrary hash, since the module is called directly.
    function _signUserOp(PackedUserOperation memory userOp) private view returns (bytes32 userOpHash) {
        userOpHash = keccak256(abi.encode(userOp.callData, userOp.paymasterAndData));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, userOpHash);
        userOp.signature = abi.encode(_key, abi.encodePacked(r, s, v));
    }

    function _gasBudgets(uint256 n, uint256 gasBudget) private pure returns (uint256[] memory gasBudgets) {
        gasBudgets = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            gasBudgets[i] = gasBudget;
        }
    }

    function _installSpenderBoth(uint48 from, uint48 until, uint160 limit, uint48 renewPeriod) private {
        _installSpenderBoth(from, until, limit, renewPeriod, GAS_BUDGET);
    }

    function _installSpenderBoth(
        uint48 from,
        uint48 until,
        uint160 limit,
        uint48 renewPeriod,
        uint256 gasBudget
    ) private {
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = from;
        uint48[] memory ends = new uint48[](1);
        ends[0] = until;
        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;

        bytes memory initData = abi.encode(keys, starts, ends, limits, renewPeriods);
        _installAccountBoth(initData, gasBudget);
    }

    function _installAccountBoth(bytes memory initData) private {
        _installAccountBoth(initData, GAS_BUDGET);
    }

    function _installAccountBoth(bytes memory initData, uint256 gasBudget) private {
        // The combined install bundle is split: keys/starts/ends go to the first install (validator),
        // and a matching keys/limits/renewPeriods bundle goes to the second install (executor).
        (
            bytes[] memory keys,
            uint48[] memory starts,
            uint48[] memory ends,
            uint160[] memory limits,
            uint48[] memory renewPeriods
        ) = abi.decode(initData, (bytes[], uint48[], uint48[], uint160[], uint48[]));

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](2);
        modules[0] = address(_spender);
        modules[1] = address(_spender);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = abi.encode(keys, starts, ends, _gasBudgets(keys.length, gasBudget));
        initDatas[1] = abi.encode(keys, limits, renewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }
}
