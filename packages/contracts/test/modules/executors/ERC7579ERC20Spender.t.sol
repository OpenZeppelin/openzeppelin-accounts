// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "../../../../../lib/@openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import {ERC7579ERC20Spender} from "../../../src/modules/executors/ERC7579ERC20Spender.sol";
import {ERC7579Utils, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579ERC20SpenderTest is Test {
    uint256 private constant MAX_TOKENS = type(uint128).max;
    uint48 private constant MAX_TIMEPOINT = type(uint48).max >> 1;

    ERC7579ERC20Spender private _spender;
    OpenAccount private _account;
    ERC20Mock private _token1;
    ERC20Mock private _token2;

    address private _eoa;
    bytes private _key;

    address private _recipient;

    function setUp() public {
        _spender = new ERC7579ERC20Spender();
        _account = new OpenAccountMock();
        _token1 = new ERC20Mock();
        _token2 = new ERC20Mock();

        _token1.mint(address(_account), MAX_TOKENS);
        _token2.mint(address(_account), MAX_TOKENS);

        (_eoa, ) = makeAddrAndKey("session-key-eoa");
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
        initDatas[0] = abi.encode(keysOne, startsOne, endsOne);
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
        initDatas[0] = abi.encode(keys, starts, ends);
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

    function testRemoveKeysLeavesConfigsIntact() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);

        assertFalse(_spender.isKey(address(_account), _key));
        // Configs are deliberately NOT cleared on removeKeys (documented in NatSpec).
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 1 ether);
    }

    function testReAddKeyWithAddKeysInheritsConfig() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        bytes[] memory rm = new bytes[](1);
        rm[0] = _key;
        vm.prank(address(_account));
        _spender.removeKeys(rm);

        // Re-register via parent's addKeys (no config writes).
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = 0;
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;
        vm.prank(address(_account));
        _spender.addKeys(keys, starts, ends);

        assertTrue(_spender.isKey(address(_account), _key));
        // Previous config is still in place.
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 1 ether);
    }

    // ----- Helpers -----

    function _installSpender(uint48 from, address token, uint160 limit, uint48 renewPeriod) private {
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
        initDatas[0] = abi.encode(keys, starts, ends);
        initDatas[1] = abi.encode(configKeys, configTokens, configLimits, configRenewPeriods);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }
}
