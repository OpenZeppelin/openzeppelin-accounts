// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    ERC7579Utils,
    ModeSelector,
    ModePayload,
    Mode,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

contract ERC7579ERC20Spender is ERC7579Executor, Nonces {
    using EnumerableMap for EnumerableMap.UintToUintMap;

    error ERC7579ERC20InsufficientAvailable(address account, address token, address spender, uint256 amount);

    error ERC7579ERC20SpenderInvalidInitData();

    error ERC7579ERC20SpenderMismatchedInitDataLengths(
        uint256 tokens,
        uint256 spenders,
        uint256 limits,
        uint256 renewPeriods
    );

    error ERC7579ERC20SpenderMismatchedBatchLengths(address token, uint256 tos, uint256 amounts);

    error ERC7579ERC20SpenderInvalidLimit(address token, uint256 limit);

    error ERC7579ERC20SpenderInvalidRenewPeriod(address token, uint256 renewPeriod);

    error ERC7579ERC20SpenderInvalidToken(address token);

    error ERC7579ERC20SpenderInvalidStart(address token, uint256 start);

    error ERC7579ERC20TransferFailed(address account, address token, address spender, address to, uint256 amount);

    event ERC7579ERC20SpendingConfigCleared(address indexed account);

    event ERC7579ERC20SpendingConfigSet(
        address indexed account,
        address indexed token,
        address indexed spender,
        uint256 start,
        uint256 limit,
        uint256 renewPeriod
    );

    struct SpendingConfig {
        // Slot 1
        uint48 start; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint48 renewPeriod; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint160 limit; // Up to 1.4615016373e30 with 18 decimals (2**160 / 1e18)
        // Slot 2
        mapping(uint256 start => EnumerableMap.UintToUintMap) spent;
    }

    mapping(address account => mapping(uint256 nonce => mapping(address token => mapping(address spender => SpendingConfig))))
        private _config;

    function start(address account, address token, address spender) public view virtual returns (uint256) {
        return _start(account, nonces(account), token, spender);
    }

    function renewPeriod(address account, address token, address spender) public view virtual returns (uint256) {
        return _renewPeriod(account, nonces(account), token, spender);
    }

    function limit(address account, address token, address spender) public view virtual returns (uint256) {
        return _limit(account, nonces(account), token, spender);
    }

    function spent(
        address account,
        address token,
        address spender,
        uint256 period
    ) public view virtual returns (uint256) {
        uint256 nonce = nonces(account);
        return _spent(account, nonce, token, spender, period, _start(account, nonce, token, spender));
    }

    function spendingAt(
        address account,
        address token,
        address spender,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 nonce = nonces(account);
        return _spendingAt(account, nonce, token, spender, period, _start(account, nonce, token, spender));
    }

    function periodAt(
        address account,
        address token,
        address spender,
        uint48 timepoint
    ) public view virtual returns (uint256 start_, uint256 period) {
        return _periodAt(account, nonces(account), token, spender, timepoint);
    }

    function periodsSpent(
        address account,
        address token,
        address spender,
        uint64 startIdx,
        uint64 endIdx
    ) public view virtual returns (uint256[] memory periods, uint256[] memory spendings) {
        uint256 nonce = nonces(account);
        uint256 start_ = _start(account, nonce, token, spender);
        periods = _config[account][nonce][token][spender].spent[start_].keys(startIdx, endIdx);
        spendings = new uint256[](periods.length);
        for (uint256 i = 0; i < periods.length; ++i) {
            spendings[i] = _spent(account, nonce, token, spender, periods[i], start_);
        }
        return (periods, spendings);
    }

    function onInstall(bytes calldata initData) public virtual {
        (
            address[] calldata tokens,
            address[] calldata spenders,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        ) = _decodeERC20SpenderInitData(initData);
        require(
            tokens.length == spenders.length &&
                spenders.length == starts.length &&
                spenders.length == limits.length &&
                spenders.length == renewPeriods.length,
            ERC7579ERC20SpenderMismatchedInitDataLengths(
                tokens.length,
                spenders.length,
                limits.length,
                renewPeriods.length
            )
        );
        address account = msg.sender;
        uint256 nonce = nonces(account);
        for (uint256 i = 0; i < spenders.length; ++i) {
            _setSpendingConfig(account, nonce, tokens[i], spenders[i], starts[i], limits[i], renewPeriods[i]);
        }
    }

    function onUninstall(bytes calldata) public virtual {
        // To properly clear the state we need to iterate over all spenders and clear the state of each one.
        // Although we can track the list of spenders, the list may grow too large to ensure cleanup is effective.
        // Notoriously, ERC-7579 accounts do not check the result of the `onUninstall` function to avoid being
        // unable to uninstall modules that always revert, so, in the case that the list of spenders is too large,
        // the module will not clean up the state of spenders, which will be preserved after reinstallation.
        // To avoid this, we use a nonce to discard the previous configuration safely.
        _useNonce(msg.sender);
        emit ERC7579ERC20SpendingConfigCleared(msg.sender);
    }

    function transferFrom(address account, address token, address to, uint256 amount) public virtual {
        address spender = msg.sender;
        uint256 nonce = nonces(account);
        (uint256 start_, uint256 period) = _periodAt(account, nonce, token, spender, Time.timestamp());
        (uint256 spending, uint256 available) = _spendingAt(account, nonce, token, spender, period, start_);
        require(amount <= available, ERC7579ERC20InsufficientAvailable(account, token, spender, amount));
        _config[account][nonce][token][spender].spent[start_].set(period, spending + amount);
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_SINGLE,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        bytes[] memory returndatas = _execute(
            account,
            bytes32(0),
            Mode.unwrap(mode),
            abi.encodePacked(token, uint256(0), abi.encodeCall(IERC20.transfer, (to, amount)))
        );
        require(
            returndatas[0].length == 0 || (returndatas[0].length == 32 && _toBool(bytes32(returndatas[0]))),
            ERC7579ERC20TransferFailed(account, token, spender, to, amount)
        );
    }

    function batchTransferFrom(
        address account,
        address token,
        address[] calldata tos,
        uint256[] calldata amounts
    ) public virtual {
        require(
            tos.length == amounts.length,
            ERC7579ERC20SpenderMismatchedBatchLengths(token, tos.length, amounts.length)
        );
        address spender = msg.sender;
        uint256 nonce = nonces(account);
        (uint256 start_, uint256 period) = _periodAt(account, nonce, token, spender, Time.timestamp());
        (uint256 spending, uint256 available) = _spendingAt(account, nonce, token, spender, period, start_);
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= available, ERC7579ERC20InsufficientAvailable(account, token, spender, totalAmount));
        _config[account][nonce][token][spender].spent[start_].set(period, spending + totalAmount);
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_BATCH,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        Execution[] memory executions = new Execution[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            executions[i] = Execution(token, 0, abi.encodeCall(IERC20.transfer, (tos[i], amounts[i])));
        }
        bytes[] memory returndatas = _execute(
            account,
            bytes32(0),
            Mode.unwrap(mode),
            ERC7579Utils.encodeBatch(executions)
        );
        for (uint256 i = 0; i < returndatas.length; ++i) {
            require(
                returndatas[i].length == 0 || (returndatas[i].length == 32 && _toBool(bytes32(returndatas[i]))),
                ERC7579ERC20TransferFailed(account, token, spender, tos[i], amounts[i])
            );
        }
    }

    function setSpendingConfig(
        address token,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) public virtual {
        _setSpendingConfig(msg.sender, nonces(msg.sender), token, spender, newStart, newLimit, newRenewPeriod);
    }

    function _start(
        address account,
        uint256 nonce,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][nonce][token][spender].start;
    }

    function _renewPeriod(
        address account,
        uint256 nonce,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][nonce][token][spender].renewPeriod;
    }

    function _limit(
        address account,
        uint256 nonce,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][nonce][token][spender].limit;
    }

    function _spent(
        address account,
        uint256 nonce,
        address token,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256) {
        (bool exists, uint256 amountSpent) = _config[account][nonce][token][spender].spent[start_].tryGet(period);
        return Math.ternary(exists, amountSpent, 0);
    }

    function _spendingAt(
        address account,
        uint256 nonce,
        address token,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, nonce, token, spender, period, start_);
        unchecked {
            // spending <= _limit since the spent amount cannot exceed the limit
            available = _limit(account, nonce, token, spender) - spending;
        }
        return (spending, available);
    }

    function _periodAt(
        address account,
        uint256 nonce,
        address token,
        address spender,
        uint48 timepoint
    ) internal view virtual returns (uint256 start_, uint256 period) {
        start_ = _start(account, nonce, token, spender);
        return (start_, (timepoint - start_) / _renewPeriod(account, nonce, token, spender));
    }

    function _setSpendingConfig(
        address account,
        uint256 nonce,
        address token,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        require(newLimit > 0, ERC7579ERC20SpenderInvalidLimit(token, newLimit));
        require(newRenewPeriod > 0, ERC7579ERC20SpenderInvalidRenewPeriod(token, newRenewPeriod));
        require(address(token).code.length > 0, ERC7579ERC20SpenderInvalidToken(token));
        require(
            _start(account, nonce, token, spender) != newStart || newStart >= Time.timestamp(),
            ERC7579ERC20SpenderInvalidStart(token, newStart)
        );
        _config[account][nonce][token][spender].start = newStart;
        _config[account][nonce][token][spender].renewPeriod = newRenewPeriod;
        _config[account][nonce][token][spender].limit = newLimit;
        emit ERC7579ERC20SpendingConfigSet(account, token, spender, newStart, newLimit, newRenewPeriod);
    }

    function _decodeERC20SpenderInitData(
        bytes calldata initData
    )
        internal
        virtual
        returns (
            address[] calldata tokens,
            address[] calldata spenders,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        )
    {
        // Minimum length:
        // tokens offset (32 bytes) + tokens length (32 bytes) + spenders offset (32 bytes) +
        // spenders length (32 bytes) + starts offset (32 bytes) + starts length (32 bytes) +
        // limits offset (32 bytes) + limits length (32 bytes) + renewPeriods offset (32 bytes) +
        // renewPeriods length (32 bytes) = 320 bytes
        require(initData.length > 0x140, ERC7579ERC20SpenderInvalidInitData());

        uint256 tokensOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 spendersOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 startsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 limitsOffset = uint256(bytes32(initData[0x60:0x80]));
        uint256 renewPeriodsOffset = uint256(bytes32(initData[0x80:0xa0]));

        uint256 tokensDataOffset = tokensOffset + 0x20;
        uint256 spendersDataOffset = spendersOffset + 0x20;
        uint256 startsDataOffset = startsOffset + 0x20;
        uint256 limitsDataOffset = limitsOffset + 0x20;
        uint256 renewPeriodsDataOffset = renewPeriodsOffset + 0x20;

        require(
            tokensDataOffset <= initData.length &&
                spendersDataOffset <= initData.length &&
                startsDataOffset <= initData.length &&
                limitsDataOffset <= initData.length &&
                renewPeriodsDataOffset <= initData.length,
            ERC7579ERC20SpenderInvalidInitData()
        );

        uint256 tokensLength = uint256(bytes32(initData[tokensOffset:tokensDataOffset]));
        uint256 spendersLength = uint256(bytes32(initData[spendersOffset:spendersDataOffset]));
        uint256 startsLength = uint256(bytes32(initData[startsOffset:startsDataOffset]));
        uint256 limitsLength = uint256(bytes32(initData[limitsOffset:limitsDataOffset]));
        uint256 renewPeriodsLength = uint256(bytes32(initData[renewPeriodsOffset:renewPeriodsDataOffset]));

        assembly ("memory-safe") {
            tokens.offset := add(initData.offset, tokensDataOffset)
            tokens.length := tokensLength
            spenders.offset := add(initData.offset, spendersDataOffset)
            spenders.length := spendersLength
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
            limits.offset := add(initData.offset, limitsDataOffset)
            limits.length := limitsLength
            renewPeriods.offset := add(initData.offset, renewPeriodsDataOffset)
            renewPeriods.length := renewPeriodsLength
        }

        return (tokens, spenders, starts, limits, renewPeriods);
    }

    function _toBool(bytes32 result) internal pure returns (bool success) {
        assembly ("memory-safe") {
            success := result
        }
    }
}
