// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {
    ERC7579Utils,
    ModeSelector,
    ModePayload,
    Mode,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

contract ERC7579NativeSpender is ERC7579Executor, Nonces {
    using EnumerableMap for EnumerableMap.UintToUintMap;

    error ERC7579NativeInsufficientAvailable(address account, address spender, uint256 amount);

    error ERC7579NativeSpenderInvalidInitData();

    error ERC7579NativeSpenderMismatchedInitDataLengths(uint256 spenders, uint256 limits, uint256 renewPeriods);

    error ERC7579NativeSpenderMismatchedBatchLengths(uint256 tos, uint256 amounts);

    error ERC7579NativeSpenderInvalidLimit(uint256 limit);

    error ERC7579NativeSpenderInvalidRenewPeriod(uint256 renewPeriod);

    error ERC7579NativeSpenderInvalidStart(uint256 start);

    event ERC7579NativeSpendingConfigCleared(address indexed account);

    event SpendingConfigSet(
        address indexed account,
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

    mapping(address account => mapping(uint256 nonce => mapping(address spender => SpendingConfig))) private _config;

    function start(address account, address spender) public view virtual returns (uint256) {
        return _start(account, nonces(account), spender);
    }

    function renewPeriod(address account, address spender) public view virtual returns (uint256) {
        return _renewPeriod(account, nonces(account), spender);
    }

    function limit(address account, address spender) public view virtual returns (uint256) {
        return _limit(account, nonces(account), spender);
    }

    function spent(address account, address spender, uint256 period) public view virtual returns (uint256) {
        uint256 nonce = nonces(account);
        return _spent(account, nonce, spender, period, _start(account, nonce, spender));
    }

    function spendingAt(
        address account,
        address spender,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 nonce = nonces(account);
        return _spendingAt(account, nonce, spender, period, _start(account, nonce, spender));
    }

    function periodAt(
        address account,
        address spender,
        uint48 timepoint
    ) public view virtual returns (uint256 start_, uint256 period) {
        return _periodAt(account, nonces(account), spender, timepoint);
    }

    function periodsSpent(
        address account,
        address spender,
        uint64 startIdx,
        uint64 endIdx
    ) public view virtual returns (uint256[] memory periods, uint256[] memory spendings) {
        uint256 nonce = nonces(account);
        uint256 start_ = _start(account, nonce, spender);
        periods = _config[account][nonce][spender].spent[start_].keys(startIdx, endIdx);
        spendings = new uint256[](periods.length);
        for (uint256 i = 0; i < periods.length; ++i) {
            spendings[i] = _spent(account, nonce, spender, periods[i], start_);
        }
        return (periods, spendings);
    }

    function onInstall(bytes calldata initData) public virtual {
        (
            address[] calldata spenders,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        ) = _decodeNativeSpenderInitData(initData);
        require(
            spenders.length == starts.length &&
                spenders.length == limits.length &&
                spenders.length == renewPeriods.length,
            ERC7579NativeSpenderMismatchedInitDataLengths(spenders.length, limits.length, renewPeriods.length)
        );
        address account = msg.sender;
        uint256 nonce = nonces(account);
        for (uint256 i = 0; i < spenders.length; ++i) {
            _setSpendingConfig(account, nonce, spenders[i], starts[i], limits[i], renewPeriods[i]);
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
        emit ERC7579NativeSpendingConfigCleared(msg.sender);
    }

    function transferFrom(address account, address to, uint256 amount) public virtual {
        address spender = msg.sender;
        uint256 nonce = nonces(account);
        (uint256 start_, uint256 period) = _periodAt(account, nonce, spender, Time.timestamp());
        (uint256 spending, uint256 available) = _spendingAt(account, nonce, spender, period, start_);
        require(amount <= available, ERC7579NativeInsufficientAvailable(account, spender, amount));
        _config[account][nonce][spender].spent[start_].set(period, spending + amount);
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_SINGLE,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        _execute(account, bytes32(0), Mode.unwrap(mode), ERC7579Utils.encodeSingle(to, amount, Calldata.emptyBytes()));
    }

    function batchTransferFrom(address account, address[] calldata tos, uint256[] calldata amounts) public virtual {
        require(tos.length == amounts.length, ERC7579NativeSpenderMismatchedBatchLengths(tos.length, amounts.length));
        address spender = msg.sender;
        uint256 nonce = nonces(account);
        (uint256 start_, uint256 period) = _periodAt(account, nonce, spender, Time.timestamp());
        (uint256 spending, uint256 available) = _spendingAt(account, nonce, spender, period, start_);
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= available, ERC7579NativeInsufficientAvailable(account, spender, totalAmount));
        _config[account][nonce][spender].spent[start_].set(period, spending + totalAmount);
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_BATCH,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        Execution[] memory executions = new Execution[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            executions[i] = Execution(tos[i], amounts[i], Calldata.emptyBytes());
        }
        _execute(account, bytes32(0), Mode.unwrap(mode), ERC7579Utils.encodeBatch(executions));
    }

    function setSpendingConfig(
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) public virtual {
        _setSpendingConfig(msg.sender, nonces(msg.sender), spender, newStart, newLimit, newRenewPeriod);
    }

    function _start(address account, uint256 nonce, address spender) internal view virtual returns (uint256) {
        return _config[account][nonce][spender].start;
    }

    function _renewPeriod(address account, uint256 nonce, address spender) internal view virtual returns (uint256) {
        return _config[account][nonce][spender].renewPeriod;
    }

    function _limit(address account, uint256 nonce, address spender) internal view virtual returns (uint256) {
        return _config[account][nonce][spender].limit;
    }

    function _spent(
        address account,
        uint256 nonce,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256) {
        (bool exists, uint256 amountSpent) = _config[account][nonce][spender].spent[start_].tryGet(period);
        return Math.ternary(exists, amountSpent, 0);
    }

    function _spendingAt(
        address account,
        uint256 nonce,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, nonce, spender, period, start_);
        unchecked {
            // spending <= _limit since the spent amount cannot exceed the limit
            available = _limit(account, nonce, spender) - spending;
        }
        return (spending, available);
    }

    function _periodAt(
        address account,
        uint256 nonce,
        address spender,
        uint48 timepoint
    ) internal view virtual returns (uint256 start_, uint256 period) {
        start_ = _start(account, nonce, spender);
        return (start_, (timepoint - start_) / _renewPeriod(account, nonce, spender));
    }

    function _setSpendingConfig(
        address account,
        uint256 nonce,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        require(newLimit > 0, ERC7579NativeSpenderInvalidLimit(newLimit));
        require(newRenewPeriod > 0, ERC7579NativeSpenderInvalidRenewPeriod(newRenewPeriod));
        require(
            _start(account, nonce, spender) != newStart || newStart >= Time.timestamp(),
            ERC7579NativeSpenderInvalidStart(newStart)
        );
        _config[account][nonce][spender].start = newStart;
        _config[account][nonce][spender].renewPeriod = newRenewPeriod;
        _config[account][nonce][spender].limit = newLimit;
        emit SpendingConfigSet(account, spender, newStart, newLimit, newRenewPeriod);
    }

    function _decodeNativeSpenderInitData(
        bytes calldata initData
    )
        internal
        virtual
        returns (
            address[] calldata spenders,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        )
    {
        // Minimum length:
        // starts offset (32 bytes) + starts length (32 bytes) + spenders offset (32 bytes) +
        // spenders length (32 bytes) + limits offset (32 bytes) + limits length (32 bytes) +
        // renewPeriods offset (32 bytes) + renewPeriods length (32 bytes) = 256 bytes
        require(initData.length > 0x100, ERC7579NativeSpenderInvalidInitData());

        uint256 spendersOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 startsOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 limitsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 renewPeriodsOffset = uint256(bytes32(initData[0x60:0x80]));

        uint256 spendersDataOffset = spendersOffset + 0x20;
        uint256 startsDataOffset = startsOffset + 0x20;
        uint256 limitsDataOffset = limitsOffset + 0x20;
        uint256 renewPeriodsDataOffset = renewPeriodsOffset + 0x20;

        require(
            spendersDataOffset <= initData.length &&
                startsDataOffset <= initData.length &&
                limitsDataOffset <= initData.length &&
                renewPeriodsDataOffset <= initData.length,
            ERC7579NativeSpenderInvalidInitData()
        );

        uint256 spendersLength = uint256(bytes32(initData[spendersOffset:spendersDataOffset]));
        uint256 startsLength = uint256(bytes32(initData[startsOffset:startsDataOffset]));
        uint256 limitsLength = uint256(bytes32(initData[limitsOffset:limitsDataOffset]));
        uint256 renewPeriodsLength = uint256(bytes32(initData[renewPeriodsOffset:renewPeriodsDataOffset]));

        assembly ("memory-safe") {
            spenders.offset := add(initData.offset, spendersDataOffset)
            spenders.length := spendersLength
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
            limits.offset := add(initData.offset, limitsDataOffset)
            limits.length := limitsLength
            renewPeriods.offset := add(initData.offset, renewPeriodsDataOffset)
            renewPeriods.length := renewPeriodsLength
        }

        return (spenders, starts, limits, renewPeriods);
    }
}
