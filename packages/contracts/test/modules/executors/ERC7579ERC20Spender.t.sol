// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "../../../../../lib/@openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ERC7579ERC20Spender} from "../../../src/modules/executors/ERC7579ERC20Spender.sol";
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

contract ERC7579ERC20SpenderHarness is ERC7579ERC20Spender {
    function validateSingleExecutionCalldata(
        bytes calldata callData
    ) external pure returns (bool isSingleAndValid, bytes calldata exec) {
        return _validateSingleExecutionCalldata(callData);
    }

    function validateTransferKey(bytes calldata exec) external view returns (bool success, bytes calldata callDataKey) {
        return _validateTransferKey(exec);
    }
}

contract ERC7579ERC20SpenderTest is Test {
    uint256 private constant MAX_TOKENS = type(uint128).max;
    uint48 private constant MAX_TIMEPOINT = type(uint48).max >> 1;
    uint256 private constant GAS_BUDGET = 1 ether;

    ERC7579ERC20SpenderHarness private _spender;
    OpenAccount private _account;
    ERC20Mock private _token1;
    ERC20Mock private _token2;

    address private _eoa;
    uint256 private _eoaKey;
    bytes private _key;

    address private _recipient;

    function setUp() public {
        _spender = new ERC7579ERC20SpenderHarness();
        _account = new OpenAccountMock();
        _token1 = new ERC20Mock();
        _token2 = new ERC20Mock();

        _token1.mint(address(_account), MAX_TOKENS);
        _token2.mint(address(_account), MAX_TOKENS);

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
        limit = uint160(bound(limit, 1, MAX_TOKENS));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT - uint48(block.timestamp)));
        uint48 from = uint48(block.timestamp) + startOffset;

        _installSpender(from, address(_token1), limit, renewPeriod);

        assertEq(_spender.limit(address(_account), _key, address(_token1)), limit);
        assertEq(_spender.renewPeriod(address(_account), _key, address(_token1)), renewPeriod);
        assertEq(_spender.tokensCount(address(_account)), 1);
    }

    function testEoaSelfCallTransferWithinLimit(uint160 limit, uint160 amount, uint48 renewPeriod) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        limit = uint160(bound(limit, 1, MAX_TOKENS));
        amount = uint160(bound(amount, 0, limit));

        _installSpender(uint48(block.timestamp), address(_token1), limit, renewPeriod);

        uint256 recipientBefore = _token1.balanceOf(_recipient);
        uint256 accountBefore = _token1.balanceOf(address(_account));

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, amount);

        assertEq(_token1.balanceOf(_recipient), recipientBefore + amount);
        assertEq(_token1.balanceOf(address(_account)), accountBefore - amount);
        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), amount);
    }

    function testEoaSelfCallRevertsForWrongCaller(address wrongCaller) public {
        vm.assume(wrongCaller != _eoa && wrongCaller != address(_account) && wrongCaller != address(0));
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(wrongCaller);
        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderUnauthorized(address,bytes)", wrongCaller, _key));
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, 1);
    }

    function testEoaSelfCallRevertsWhenExceedingLimit(uint160 limit, uint256 amount) public {
        limit = uint160(bound(limit, 1, MAX_TOKENS - 1));
        amount = bound(amount, limit + 1, MAX_TOKENS);

        _installSpender(uint48(block.timestamp), address(_token1), limit, 1 days);

        vm.prank(_eoa);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC7579ERC20InsufficientAvailable(address,bytes,address,uint256)",
                address(_account),
                _key,
                address(_token1),
                amount
            )
        );
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, amount);
    }

    function testPeriodCalculation(uint48 startOffset, uint48 renewPeriod, uint48 elapsed) public {
        renewPeriod = uint48(bound(renewPeriod, 1, type(uint48).max));
        startOffset = uint48(bound(startOffset, 0, MAX_TIMEPOINT / 2));
        elapsed = uint48(bound(elapsed, 0, MAX_TIMEPOINT - uint48(block.timestamp) - startOffset));

        uint48 from = uint48(block.timestamp) + startOffset;
        _installSpender(from, address(_token1), 1 ether, renewPeriod);

        uint48 timepoint = from + elapsed;
        vm.warp(timepoint);

        (uint256 returnedStart, uint256 period) = _spender.periodAt(
            address(_account),
            _key,
            address(_token1),
            timepoint
        );
        assertEq(returnedStart, from);
        assertEq(period, elapsed / renewPeriod);
    }

    function testBatchTransferWithinLimit(uint160 limit, uint8 numRecipients) public {
        limit = uint160(bound(limit, 1, MAX_TOKENS));
        numRecipients = uint8(bound(numRecipients, 1, 10));
        uint160 amountPerRecipient = limit / numRecipients;

        _installSpender(uint48(block.timestamp), address(_token1), limit, 1 days);

        address[] memory recipients = new address[](numRecipients);
        uint256[] memory amounts = new uint256[](numRecipients);
        uint256 totalAmount;
        for (uint256 i = 0; i < numRecipients; i++) {
            recipients[i] = makeAddr(string(abi.encodePacked("recipient", i)));
            amounts[i] = amountPerRecipient;
            totalAmount += amountPerRecipient;
        }

        vm.prank(_eoa);
        _spender.batchTransferFrom(address(_account), _key, address(_token1), recipients, amounts);

        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), totalAmount);
        for (uint256 i = 0; i < numRecipients; i++) {
            assertEq(_token1.balanceOf(recipients[i]), amounts[i]);
        }
    }

    function testThirdInstallReverts() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        address[] memory tokens = new address[](1);
        tokens[0] = address(_token2);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        bytes memory configBundle = abi.encode(keys, tokens, limits, renewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderAlreadyInstalled()"));
        _spender.onInstall(configBundle);
    }

    function testSecondInstallWithEmptyKeysReverts() public {
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

        bytes[] memory emptyKeys = new bytes[](0);
        address[] memory emptyTokens = new address[](0);
        uint160[] memory emptyLimits = new uint160[](0);
        uint48[] memory emptyRenewPeriods = new uint48[](0);
        bytes memory empty = abi.encode(emptyKeys, emptyTokens, emptyLimits, emptyRenewPeriods);

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderEmptyKeys()"));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), empty);
    }

    function testAddKeysWithPastStartReverts() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        (address eoa2, ) = makeAddrAndKey("session-key-eoa-2");
        bytes memory key2 = abi.encodePacked(eoa2);

        vm.warp(block.timestamp + 1 days);
        uint48 pastStart = uint48(block.timestamp - 1);

        bytes[] memory keys = new bytes[](1);
        keys[0] = key2;
        uint48[] memory starts = new uint48[](1);
        starts[0] = pastStart;
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        address[] memory tokens = new address[](1);
        tokens[0] = address(_token1);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderInvalidStart(uint256)", pastStart));
        _spender.addKeysWithConfig(keys, starts, ends, tokens, limits, renewPeriods);
    }

    function testMultipleTokensPerKey() public {
        // Validator install registers `_key`
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = uint48(block.timestamp);
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;

        // Executor install configures TWO tokens for the same key
        bytes[] memory configKeys = new bytes[](2);
        configKeys[0] = _key;
        configKeys[1] = _key;
        address[] memory configTokens = new address[](2);
        configTokens[0] = address(_token1);
        configTokens[1] = address(_token2);
        uint160[] memory configLimits = new uint160[](2);
        configLimits[0] = 1 ether;
        configLimits[1] = 2 ether;
        uint48[] memory configRenewPeriods = new uint48[](2);
        configRenewPeriods[0] = 1 days;
        configRenewPeriods[1] = 1 days;

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](2);
        modules[0] = address(_spender);
        modules[1] = address(_spender);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = abi.encode(keys, starts, ends, _gasBudgets(keys.length, GAS_BUDGET));
        initDatas[1] = abi.encode(configKeys, configTokens, configLimits, configRenewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));

        assertEq(_spender.tokensCount(address(_account)), 2);
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 1 ether);
        assertEq(_spender.limit(address(_account), _key, address(_token2)), 2 ether);

        // Spend from both tokens
        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, 0.5 ether);
        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token2), _recipient, 1.5 ether);

        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), 0.5 ether);
        assertEq(_spender.spent(address(_account), _key, address(_token2), 0), 1.5 ether);
    }

    function testRemoveKeysClearsConfigs() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(address(_account));
        _spender.removeKeys(_singleKey());

        assertFalse(_spender.isKey(address(_account), _key));
        assertEq(_spender.keyGeneration(address(_account), _key), 1);
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 0);
        assertEq(_spender.renewPeriod(address(_account), _key, address(_token1)), 0);
    }

    function testReAddKeyWithAddKeysStartsWithoutConfig() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(address(_account));
        _spender.removeKeys(_singleKey());

        // Re-register via parent's addKeys (no config writes).
        vm.prank(address(_account));
        _spender.addKeys(_singleKey(), new uint48[](1), new uint48[](1));

        assertTrue(_spender.isKey(address(_account), _key));
        assertEq(_spender.keyGeneration(address(_account), _key), 1);
        // The previous generation's gas budget is unreachable.
        assertEq(_spender.gasBudget(address(_account), _key), 0);
        // The previous generation's config is unreachable.
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 0);

        bytes32 currentKeyId = _currentKeyId();

        vm.prank(_eoa);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579ERC20Spender.ERC7579ERC20SpendingConfigNotSet.selector,
                address(_account),
                currentKeyId,
                address(_token1)
            )
        );
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, 1);
    }

    function testReAddKeyWithConfigOnlyHasNewPolicies(uint160 spentAmount) public {
        spentAmount = uint160(bound(spentAmount, 1, 1 ether));
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, spentAmount);
        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), spentAmount);

        vm.prank(address(_account));
        _spender.removeKeys(_singleKey());

        address[] memory tokens = new address[](1);
        tokens[0] = address(_token2);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 2 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        vm.prank(address(_account));
        _spender.addKeysWithConfig(_singleKey(), new uint48[](1), new uint48[](1), tokens, limits, renewPeriods);

        // Only the new (key, token2) policy exists, with an empty spending period.
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 0);
        assertEq(_spender.limit(address(_account), _key, address(_token2)), 2 ether);
        assertEq(_spender.spent(address(_account), _key, address(_token2), 0), 0);
        (, uint256 available) = _spender.spendingAt(address(_account), _key, address(_token2), 0);
        assertEq(available, 2 ether);

        bytes32 currentKeyId = _currentKeyId();

        vm.prank(_eoa);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579ERC20Spender.ERC7579ERC20SpendingConfigNotSet.selector,
                address(_account),
                currentKeyId,
                address(_token1)
            )
        );
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, 1);
    }

    function testReAddKeyResetsSpentAmount(uint160 spentAmount) public {
        spentAmount = uint160(bound(spentAmount, 1, 1 ether));
        uint48 from = uint48(block.timestamp);
        _installSpender(from, address(_token1), 1 ether, 1 days);

        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, spentAmount);

        vm.prank(address(_account));
        _spender.removeKeys(_singleKey());
        // Spent amounts of the previous generation are unreachable, even at the historical start.
        assertEq(_spender.spent(address(_account), _key, address(_token1), 0, from), 0);

        // Same key, token, limit and start timepoint as the removed registration.
        address[] memory tokens = new address[](1);
        tokens[0] = address(_token1);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        vm.prank(address(_account));
        _spender.addKeysWithConfig(_singleKey(), new uint48[](1), new uint48[](1), tokens, limits, renewPeriods);

        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), 0);
        vm.prank(_eoa);
        _spender.transferFrom(address(_account), _key, address(_token1), _recipient, 1 ether);
        assertEq(_spender.spent(address(_account), _key, address(_token1), 0), 1 ether);
    }

    function testRemovedKeyValidatedOperationCannotExecute() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        // A user operation of the key is validated before the key is removed.
        PackedUserOperation memory userOp;
        userOp.sender = address(_account);
        userOp.callData = abi.encodeCall(
            IERC7579Execution.execute,
            (
                _singleMode(),
                _encodeSingle(
                    abi.encodeCall(_spender.transferFrom, (address(_account), _key, address(_token1), _recipient, 1))
                )
            )
        );
        bytes32 userOpHash = keccak256("userOpHash");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_eoaKey, userOpHash);
        userOp.signature = abi.encode(_key, abi.encodePacked(r, s, v));
        vm.prank(address(_account));
        (address authorizer, , , ) = ERC4337Utils.parseValidationData(_spender.validateUserOp(userOp, userOpHash));
        assertEq(authorizer, address(0));

        // An earlier operation in the same bundle removes the key.
        vm.prank(address(_account));
        _spender.removeKeys(_singleKey());

        // The validated operation then executes and finds no policy.
        bytes32 currentKeyId = _currentKeyId();
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V09));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579ERC20Spender.ERC7579ERC20SpendingConfigNotSet.selector,
                address(_account),
                currentKeyId,
                address(_token1)
            )
        );
        (bool success, ) = address(_account).call(userOp.callData);
        success; // The revert is asserted by `expectRevert`.
    }

    function testRemoveKeysGasIndependentOfTokenCount() public {
        uint256 gasOneToken = _removeKeyGas(1);
        uint256 gasManyTokens = _removeKeyGas(50);
        assertEq(gasOneToken, gasManyTokens);
    }

    // ----- Gas budget -----

    function testInstallSetsGasBudget(uint256 gasBudget) public {
        vm.expectEmit(address(_spender));
        emit ERC7579SessionKeysValidator.ERC7579SessionKeysValidatorGasBudgetSet(address(_account), _key, gasBudget);
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days, gasBudget);
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
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days, gasBudget);

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
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days, GAS_BUDGET);

        PackedUserOperation memory userOp = _spendUserOp(100000, 1000000);
        bytes32 userOpHash = _signUserOp(userOp);

        vm.prank(caller);
        assertEq(_spender.validateUserOp(userOp, userOpHash), ERC4337Utils.SIG_VALIDATION_FAILED);
        assertEq(_spender.gasBudget(address(_account), _key), GAS_BUDGET);
    }

    function testAddKeysWithConfigStartsWithoutGasBudget() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);
        assertEq(_spender.gasBudget(address(_account), _key), 0);

        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        address[] memory tokens = new address[](1);
        tokens[0] = address(_token1);
        uint160[] memory limits = new uint160[](1);
        limits[0] = 1 ether;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = 1 days;
        vm.prank(address(_account));
        _spender.addKeysWithConfig(keys, new uint48[](1), new uint48[](1), tokens, limits, renewPeriods);
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
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

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

    function testValidateTransferKey(
        address account,
        bytes memory key,
        address token,
        address to,
        uint256 amount
    ) public view {
        (bool success, bytes memory decoded) = _spender.validateTransferKey(
            _encodeSingle(abi.encodeCall(_spender.transferFrom, (account, key, token, to, amount)))
        );
        assertTrue(success);
        assertEq(decoded, key);

        (success, decoded) = _spender.validateTransferKey(
            _encodeSingle(
                abi.encodeCall(_spender.batchTransferFrom, (account, key, token, new address[](0), new uint256[](0)))
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
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

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
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        PackedUserOperation memory userOp;
        userOp.sender = address(_account);
        userOp.callData = abi.encodeCall(
            IERC7579Execution.execute,
            (
                _singleMode(),
                _encodeSingle(
                    abi.encodeCall(_spender.transferFrom, (address(_account), _key, address(_token1), _recipient, 1))
                )
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
                _encodeSingle(
                    abi.encodeCall(_spender.transferFrom, (address(_account), _key, address(_token1), _recipient, 1))
                )
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

    function _installSpender(uint48 from, address token, uint160 limit, uint48 renewPeriod) private {
        _installSpender(from, token, limit, renewPeriod, GAS_BUDGET);
    }

    function _installSpender(uint48 from, address token, uint160 limit, uint48 renewPeriod, uint256 gasBudget) private {
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = from;
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;

        bytes[] memory configKeys = new bytes[](1);
        configKeys[0] = _key;
        address[] memory configTokens = new address[](1);
        configTokens[0] = token;
        uint160[] memory configLimits = new uint160[](1);
        configLimits[0] = limit;
        uint48[] memory configRenewPeriods = new uint48[](1);
        configRenewPeriods[0] = renewPeriod;

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](2);
        modules[0] = address(_spender);
        modules[1] = address(_spender);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = abi.encode(keys, starts, ends, _gasBudgets(keys.length, gasBudget));
        initDatas[1] = abi.encode(configKeys, configTokens, configLimits, configRenewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    function _singleKey() private view returns (bytes[] memory keys) {
        keys = new bytes[](1);
        keys[0] = _key;
    }

    /// @dev Installs `_key` with `tokenCount` token policies on a fresh account and returns the gas used to remove it.
    function _removeKeyGas(uint256 tokenCount) private returns (uint256) {
        _account = new OpenAccountMock();

        bytes[] memory configKeys = new bytes[](tokenCount);
        address[] memory configTokens = new address[](tokenCount);
        uint160[] memory configLimits = new uint160[](tokenCount);
        uint48[] memory configRenewPeriods = new uint48[](tokenCount);
        for (uint256 i = 0; i < tokenCount; ++i) {
            configKeys[i] = _key;
            configTokens[i] = address(new ERC20Mock());
            configLimits[i] = 1 ether;
            configRenewPeriods[i] = 1 days;
        }

        uint256[] memory moduleTypeIds = new uint256[](2);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        moduleTypeIds[1] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](2);
        modules[0] = address(_spender);
        modules[1] = address(_spender);
        bytes[] memory initDatas = new bytes[](2);
        initDatas[0] = abi.encode(_singleKey(), new uint48[](1), new uint48[](1), _gasBudgets(1, GAS_BUDGET));
        initDatas[1] = abi.encode(configKeys, configTokens, configLimits, configRenewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
        assertEq(_spender.tokensCount(address(_account)), tokenCount);

        bytes[] memory keys = _singleKey();
        vm.prank(address(_account));
        uint256 gasBefore = gasleft();
        _spender.removeKeys(keys);
        return gasBefore - gasleft();
    }

    /// @dev Generation-scoped identifier of `_key` on `_account`. See {ERC7579SessionKeys-_keyId}.
    function _currentKeyId() private view returns (bytes32) {
        return keccak256(abi.encode(keccak256(_key), _spender.keyGeneration(address(_account), _key)));
    }
}
