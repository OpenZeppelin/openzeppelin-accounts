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
        startOffset = uint48(bound(startOffset, 0, type(uint48).max - uint48(block.timestamp)));
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
        startOffset = uint48(bound(startOffset, 0, type(uint48).max / 2));
        elapsed = uint48(bound(elapsed, 0, type(uint48).max - uint48(block.timestamp) - startOffset));

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

    function testSingleCallInstallsBothRoles() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        assertTrue(_account.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(_spender), ""));
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));
        assertTrue(_spender.installed(address(_account)));
        assertTrue(_spender.isKey(address(_account), _key));
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 1 ether);
    }

    function testDirectValidatorInstallReverts() public {
        _initializeWithoutSpender();

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _bundle(address(_token1), 1 ether, 1 days));

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _keysInitData(uint48(block.timestamp)));
    }

    function testDirectValidatorInstallRevertsWithExecutorInstalled() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_VALIDATOR, address(_spender), _keysInitData(uint48(block.timestamp)));
    }

    function testReinstallReverts() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Utils.ERC7579AlreadyInstalledModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(_spender)
            )
        );
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(address(_token2), 1 ether, 1 days));
    }

    function testReconfigurationThroughOnInstallReverts() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _spender.onInstall(_bundle(address(_token2), 1 ether, 1 days));

        // The old executor-schema bundle is rejected as well.
        (, bytes memory spendingInitData) = abi.decode(_bundle(address(_token2), 1 ether, 1 days), (bytes, bytes));
        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _spender.onInstall(spendingInitData);

        assertEq(_spender.limit(address(_account), _key, address(_token2)), 0);
        assertEq(_spender.tokensCount(address(_account)), 1);
    }

    function testInstallWithEmptySessionKeysReverts() public {
        bytes[] memory emptyKeys = new bytes[](0);
        uint48[] memory empty48 = new uint48[](0);
        (, bytes memory spendingInitData) = abi.decode(_bundle(address(_token1), 1 ether, 1 days), (bytes, bytes));

        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderEmptyKeys()"));
        _installExecutor(abi.encode(abi.encode(emptyKeys, empty48, empty48), spendingInitData));
    }

    function testInstallWithEmptySpendingPoliciesReverts() public {
        bytes[] memory emptyKeys = new bytes[](0);
        address[] memory emptyTokens = new address[](0);
        uint160[] memory emptyLimits = new uint160[](0);
        uint48[] memory emptyRenewPeriods = new uint48[](0);
        bytes memory empty = abi.encode(emptyKeys, emptyTokens, emptyLimits, emptyRenewPeriods);

        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderEmptyKeys()"));
        _installExecutor(abi.encode(_keysInitData(uint48(block.timestamp)), empty));
    }

    function testInstallWithMalformedBundleReverts() public {
        vm.expectRevert(abi.encodeWithSignature("ERC7579ERC20SpenderInvalidInitData()"));
        _installExecutor(new bytes(0x7f));
    }

    function testUninstallExecutorOnlyBlocksReinstall() public {
        _installSpender(uint48(block.timestamp), address(_token1), 1 ether, 1 days);
        uint256 nonceBefore = _spender.installation(address(_account));

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_EXECUTOR, address(_spender), "");
        assertEq(_spender.installation(address(_account)), nonceBefore + 1);
        assertEq(_spender.tokensCount(address(_account)), 0);
        assertTrue(_account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(_spender), ""));

        vm.prank(address(_account));
        vm.expectPartialRevert(ERC7579ERC20Spender.ERC7579ERC20SpenderInvalidInstallFlow.selector);
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(address(_token2), 2 ether, 2 days));

        vm.prank(address(_account));
        _account.uninstallModule(MODULE_TYPE_VALIDATOR, address(_spender), "");
        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_spender), _bundle(address(_token2), 2 ether, 2 days));
        assertEq(_spender.limit(address(_account), _key, address(_token1)), 0);
        assertEq(_spender.limit(address(_account), _key, address(_token2)), 2 ether);
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
        // Session keys bundle registers `_key`
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = uint48(block.timestamp);
        uint48[] memory ends = new uint48[](1);
        ends[0] = 0;

        // Spending policies configure TWO tokens for the same key
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

        _installExecutor(
            abi.encode(
                abi.encode(keys, starts, ends),
                abi.encode(configKeys, configTokens, configLimits, configRenewPeriods)
            )
        );

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
        (, bytes memory spendingInitData) = abi.decode(_bundle(token, limit, renewPeriod), (bytes, bytes));
        _installExecutor(abi.encode(_keysInitData(from), spendingInitData));
    }

    /// @dev Initializes the account with the spender as its only module, installed as an executor.
    function _installExecutor(bytes memory bundle) private {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](1);
        modules[0] = address(_spender);
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = bundle;
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    /// @dev Initializes the account with an unrelated executor so the spender can be installed afterwards.
    function _initializeWithoutSpender() private {
        uint256[] memory moduleTypeIds = new uint256[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        address[] memory modules = new address[](1);
        modules[0] = address(new ERC7579ERC20Spender());
        bytes[] memory initDatas = new bytes[](1);
        initDatas[0] = _bundle(address(_token1), 1 ether, 1 days);
        _account.initialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""));
    }

    function _keysInitData(uint48 from) private view returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        uint48[] memory starts = new uint48[](1);
        starts[0] = from;
        uint48[] memory ends = new uint48[](1);
        return abi.encode(keys, starts, ends);
    }

    function _bundle(address token, uint160 limit, uint48 renewPeriod) private view returns (bytes memory) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = _key;
        address[] memory tokens = new address[](1);
        tokens[0] = token;
        uint160[] memory limits = new uint160[](1);
        limits[0] = limit;
        uint48[] memory renewPeriods = new uint48[](1);
        renewPeriods[0] = renewPeriod;
        return abi.encode(_keysInitData(0), abi.encode(keys, tokens, limits, renewPeriods));
    }
}
