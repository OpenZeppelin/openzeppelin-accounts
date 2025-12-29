// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {
    ERC7579Utils,
    ModeSelector,
    ModePayload,
    Mode,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

/**
 * @dev Extension of {ERC7579Executor} that provides native token (ETH) spending limits
 * with automatic renewal periods for ERC-7579 smart accounts.
 *
 * This module allows accounts to configure spending allowances for external spenders,
 * enabling use cases like subscription services, recurring payments, or delegated spending
 * with predefined limits. Each spender gets a renewable spending limit that automatically
 * resets at the end of each period, allowing the same spending capacity to be used again
 * without requiring manual intervention.
 *
 * The module implements ERC-6372 clock functions. See {clock} and {CLOCK_MODE}.
 *
 * See {SpendingConfig} for the configuration details.
 *
 * TIP: Set {start} to a future timepoint to schedule a spending limit that activates later.
 * TIP: Set {renewPeriod} to {type(uint48).max} to disable the renewal period.
 */
contract ERC7579NativeSpender is ERC7579Executor, Nonces {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev The account already has spenders installed.
    error ERC7579NativeSpenderAlreadyInstalled();

    /// @dev The requested `amount` exceeds the `available` spending limit for the `spender`.
    error ERC7579NativeInsufficientAvailable(address account, address spender, uint256 amount);

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579NativeSpenderInvalidInitData();

    /// @dev The spending config is not set for the `spender`.
    error ERC7579NativeSpendingConfigNotSet(address account, address spender);

    /// @dev The arrays in `initData` have mismatched lengths.
    error ERC7579NativeSpenderMismatchedInitDataLengths(uint256 spenders, uint256 limits, uint256 renewPeriods);

    /// @dev The `account` module is left with no spenders.
    error ERC7579NativeSpenderEmptySpenders();

    /// @dev The `tos` and `amounts` arrays have mismatched lengths in batch transfer.
    error ERC7579NativeSpenderMismatchedBatchLengths(uint256 tos, uint256 amounts);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579NativeSpenderInvalidRenewPeriod(uint256 renewPeriod);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579NativeSpenderInvalidLimit(uint256 limit);

    /// @dev The `start` time is invalid (cannot reuse a past start time).
    error ERC7579NativeSpenderInvalidStart(uint256 start);

    /// @dev The spending config has not started yet for the given `timepoint`.
    error ERC7579NativeSpendingConfigNotStarted(address account, address spender, uint256 timepoint, uint256 start);

    /// @dev The account has not installed the module.
    error ERC7579NativeSpenderUninstalled();

    /// @dev Emitted when all spending configurations are cleared for an account.
    event ERC7579NativeSpendingConfigCleared(address indexed account);

    /// @dev Emitted when a spending configuration is set for a spender.
    event ERC7579NativeSpendingConfigSet(
        address indexed account,
        address indexed spender,
        uint256 start,
        uint256 limit,
        uint256 renewPeriod
    );

    /// @dev Emitted when a spending configuration is unset for a spender.
    event ERC7579NativeSpendingConfigUnset(address indexed account, address indexed spender);

    /**
     * @dev Spending configuration for a specific account-spender pair.
     *
     * The configuration includes:
     *
     * * `start`: When the spending limit becomes active (in the clock's timepoint)
     * * `renewPeriod`: Duration of each spending period (in the clock's units)
     * * `limit`: Maximum spendable amount per period
     */
    struct SpendingConfig {
        // Slot 1
        uint48 start; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint48 renewPeriod; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint160 limit; // Up to 1.4615016373e30 with 18 decimals (2**160 / 1e18)
    }

    mapping(address account => mapping(uint256 installation => mapping(address spender => SpendingConfig)))
        private _config;
    mapping(address account => mapping(uint256 installation => mapping(address spender => mapping(uint256 start => mapping(uint256 period => uint256)))))
        private _spentFor;
    mapping(address account => mapping(uint256 installation => EnumerableSet.AddressSet)) private _spenders;

    /**
     * @dev Clock used for flagging checkpoints. Defaults to timestamp but can be overridden
     * to use block numbers if needed.
     */
    function clock() public view virtual returns (uint48) {
        return Time.timestamp();
    }

    /**
     * @dev Machine-readable description of the clock as specified in ERC-6372.
     * Can be overridden to return `"mode=blocknumber&from=default"` if using block numbers.
     */
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() public view virtual returns (string memory) {
        return "mode=timestamp";
    }

    /// @dev Returns whether the module is installed for an `account`.
    function installed(address account) public view virtual returns (bool) {
        return spendersCount(account) > 0;
    }

    /// @dev Returns the installation nonce for an `account`. See {onUninstall}.
    function installation(address account) public view virtual returns (uint256) {
        return nonces(account);
    }

    /// @dev Returns the start timepoint for the spending configuration of a `spender` on an `account`.
    function start(address account, address spender) public view virtual returns (uint256) {
        return _start(account, installation(account), spender);
    }

    /// @dev Returns the renewal period (in seconds) for the spending configuration of a `spender` on an `account`.
    function renewPeriod(address account, address spender) public view virtual returns (uint256) {
        return _renewPeriod(account, installation(account), spender);
    }

    /// @dev Returns the spending limit per period for a `spender` on an `account`.
    function limit(address account, address spender) public view virtual returns (uint256) {
        return _limit(account, installation(account), spender);
    }

    /// @dev Returns the amount spent by a `spender` during a specific `period` for an `account`.
    function spent(address account, address spender, uint256 period) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _spent(account, installation_, spender, period, _start(account, installation_, spender));
    }

    /// @dev Same as {spent} but receives a `start_` timepoint.
    function spent(
        address account,
        address spender,
        uint256 period,
        uint256 start_
    ) public view virtual returns (uint256) {
        return _spent(account, installation(account), spender, period, start_);
    }

    /// @dev Returns the number of spenders installed for an `account`.
    function spendersCount(address account) public view virtual returns (uint256) {
        return _spenders[account][installation(account)].length();
    }

    /**
     * @dev Returns a slice of the set of spenders installed for an `account`.
     *
     * Using `startIdx = 0` and `endIdx = type(uint256).max` will return the entire set of spenders.
     *
     * WARNING: Depending on the `startIdx` and `endIdx`, this operation can copy a large amount of data to memory, which
     * can be expensive. This is designed for view accessors queried without gas fees. Using it in state-changing
     * functions may become uncallable if the slice grows too large.
     */
    function spenders(
        address account,
        uint256 startIdx,
        uint256 endIdx
    ) public view virtual returns (address[] memory spenders_) {
        return _spenders[account][installation(account)].values(startIdx, endIdx);
    }

    /// @dev Returns the spending information for a `spender` at a specific `period` for an `account`.
    function spendingAt(
        address account,
        address spender,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 installation_ = installation(account);
        return _spendingAt(account, installation_, spender, period, _start(account, installation_, spender));
    }

    /**
     * @dev Returns the period information for a `spender` at a specific `timepoint` for an `account`.
     *
     * Requirements:
     *
     * * The `timepoint` must be greater or equal than {start} for the current spending configuration.
     *   Reverts with {ERC7579NativeSpendingConfigNotStarted} if not.
     */
    function periodAt(
        address account,
        address spender,
        uint48 timepoint
    ) public view virtual returns (uint256 start_, uint256 period) {
        return _periodAt(account, installation(account), spender, timepoint);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * See {IERC7579Module-onInstall}. The `initData` encodes arrays of spenders and their
     * corresponding spending configurations.
     *
     * See {_decodeNativeSpenderInitData} for the encoding details.
     *
     * Requirements:
     *
     * * The account must have no spenders installed. Reverts with {ERC7579NativeSpenderAlreadyInstalled} if not.
     * * The `spenders_` array must not be empty. Reverts with {ERC7579NativeSpenderEmptySpenders} if not.
     * * Those from {_decodeNativeSpenderInitData} for the decoding requirements.
     * * All arrays must have equal length. Reverts with {ERC7579NativeSpenderMismatchedInitDataLengths} if not.
     * * Those from {_setSpendingConfig} for the configuration requirements.
     */
    function onInstall(bytes calldata initData) public virtual {
        address account = msg.sender;
        require(!installed(account), ERC7579NativeSpenderAlreadyInstalled());
        (
            address[] calldata spenders_,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        ) = _decodeNativeSpenderInitData(initData);
        require(
            spenders_.length == starts.length &&
                spenders_.length == limits.length &&
                spenders_.length == renewPeriods.length,
            ERC7579NativeSpenderMismatchedInitDataLengths(spenders_.length, limits.length, renewPeriods.length)
        );
        require(spenders_.length > 0, ERC7579NativeSpenderEmptySpenders());
        uint256 installation_ = installation(account);
        for (uint256 i = 0; i < spenders_.length; ++i) {
            _setSpendingConfig(account, installation_, spenders_[i], starts[i], limits[i], renewPeriods[i]);
        }
    }

    /**
     * @dev Cleans up the module's configuration when uninstalled from an account.
     * Increments the account's nonce to invalidate all previous spending configurations.
     *
     * See {IERC7579Module-onUninstall}.
     *
     * NOTE: This approach avoids unbounded gas costs by not iterating over spenders.
     * Previous spending data remains in storage but becomes inaccessible due to the nonce increment.
     * Upon reinstallation, the module will use a new nonce and ignore old configurations.
     */
    function onUninstall(bytes calldata) public virtual {
        _useNonce(msg.sender);
        emit ERC7579NativeSpendingConfigCleared(msg.sender);
    }

    /**
     * @dev Transfers native tokens from an `account` to a recipient on behalf of a `msg.sender`.
     *
     * This function tracks the spending limit for the `msg.sender` on the `account` and updates
     * the spent amount for the current period before executing the transfer through the account's
     * {IERC7579Execution-executeFromExecutor} function.
     *
     * Requirements:
     *
     * * The `amount` must not exceed the available spending limit for the current period.
     *   Reverts with {ERC7579NativeInsufficientAvailable} if it does.
     * * The `account` must have sufficient native token balance. Reverts if transfer fails.
     * * Those of {_periodAt} for the current timepoint.
     */
    function transferFrom(address account, address to, uint256 amount) public virtual {
        _transferFrom(account, installation(account), msg.sender, to, amount);
    }

    /**
     * @dev Transfers native tokens from an `account` to multiple recipients in a single transaction.
     *
     * It calculates the total amount, checks against the limit once, and executes all transfers in batch.
     *
     * Requirements:
     *
     * * The `tos` and `amounts` arrays must have equal length. Reverts with
     *   {ERC7579NativeSpenderMismatchedBatchLengths} if not.
     * * The sum of all `amounts` must not exceed the available spending limit for the current period.
     *   Reverts with {ERC7579NativeInsufficientAvailable} if it does.
     * * The `account` must have sufficient native token balance for all transfers. Reverts if any transfer fails.
     * * Those of {_periodAt} for the current timepoint.
     */
    function batchTransferFrom(address account, address[] calldata tos, uint256[] calldata amounts) public virtual {
        _batchTransferFrom(account, installation(account), msg.sender, tos, amounts);
    }

    /**
     * @dev Updates the spending configuration for a `spender`.
     *
     * This function allows an account to modify spending {limit}, {renewPeriod}, or {start} time
     * for a specific spender. Can be called directly by the account.
     *
     * Requirements:
     *
     * * The module must be installed. Reverts with {ERC7579NativeSpenderUninstalled} if not.
     * * Those from {_setSpendingConfig}.
     */
    function setSpendingConfig(
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) public virtual {
        require(installed(msg.sender), ERC7579NativeSpenderUninstalled());
        _setSpendingConfig(msg.sender, installation(msg.sender), spender, newStart, newLimit, newRenewPeriod);
    }

    /// @dev Same as {setSpendingConfig} but sets a configuration that starts immediately.
    function setSpendingConfig(address spender, uint160 newLimit, uint48 newRenewPeriod) public virtual {
        setSpendingConfig(spender, clock(), newLimit, newRenewPeriod);
    }

    /**
     * @dev Removes the spending configuration for a `spender`.
     *
     * This function allows an account to completely remove a spender's configuration, freeing up storage
     * and removing the spender from the account's spender set. Can be called directly by the account.
     *
     * Requirements:
     *
     * * Those from {_unsetSpendingConfig}.
     */
    function unsetSpendingConfig(address spender) public virtual {
        _unsetSpendingConfig(msg.sender, installation(msg.sender), spender);
    }

    /// @dev Internal version of {start} that receives an `installation_` nonce.
    function _start(address account, uint256 installation_, address spender) internal view virtual returns (uint256) {
        return _config[account][installation_][spender].start;
    }

    /// @dev Internal version of {renewPeriod} that receives an `installation_` nonce.
    function _renewPeriod(
        address account,
        uint256 installation_,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][spender].renewPeriod;
    }

    /// @dev Internal version of {limit} that receives an `installation_` nonce.
    function _limit(address account, uint256 installation_, address spender) internal view virtual returns (uint256) {
        return _config[account][installation_][spender].limit;
    }

    /// @dev Internal version of {spent} that receives an `installation_` nonce and a `start_` timepoint.
    function _spent(
        address account,
        uint256 installation_,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256) {
        return _spentFor[account][installation_][spender][start_][period];
    }

    /// @dev Internal version of {spendingAt} that receives an `installation_` nonce and a `start_` timepoint.
    function _spendingAt(
        address account,
        uint256 installation_,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, installation_, spender, period, start_);
        (bool success, uint256 available_) = Math.trySub(_limit(account, installation_, spender), spending);
        return (spending, Math.ternary(success, available_, 0));
    }

    /**
     * @dev Internal version of {periodAt} that receives an `installation_` nonce.
     *
     * Requirements:
     *
     * * The `timepoint` must be greater or equal than {start} for the current spending configuration.
     *   Reverts with {ERC7579NativeSpendingConfigNotStarted} if not.
     * * The {renewPeriod} must be greater than zero. Reverts with {ERC7579NativeSpendingConfigNotSet} if not.
     */
    function _periodAt(
        address account,
        uint256 installation_,
        address spender,
        uint48 timepoint
    ) internal view virtual returns (uint256 start_, uint256 period) {
        start_ = _start(account, installation_, spender);
        (bool success, uint256 ellapsed) = Math.trySub(timepoint, start_);
        require(success, ERC7579NativeSpendingConfigNotStarted(account, spender, timepoint, start_));
        uint256 renewPeriod_ = _renewPeriod(account, installation_, spender);
        require(renewPeriod_ > 0, ERC7579NativeSpendingConfigNotSet(account, spender));
        return (start_, ellapsed / renewPeriod_); // Division error is ok here
    }

    /// @dev Internal version of {transferFrom} without access control.
    function _transferFrom(
        address account,
        uint256 installation_,
        address spender,
        address to,
        uint256 amount
    ) internal virtual {
        (uint256 start_, uint256 period) = _periodAt(account, installation_, spender, clock());
        (, uint256 available) = _spendingAt(account, installation_, spender, period, start_);
        require(amount <= available, ERC7579NativeInsufficientAvailable(account, spender, amount));
        _spentFor[account][installation_][spender][start_][period] += amount;
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_SINGLE,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        _execute(account, bytes32(0), Mode.unwrap(mode), ERC7579Utils.encodeSingle(to, amount, Calldata.emptyBytes()));
    }

    /// @dev Internal version of {batchTransferFrom} without access control.
    function _batchTransferFrom(
        address account,
        uint256 installation_,
        address spender,
        address[] calldata tos,
        uint256[] calldata amounts
    ) internal virtual {
        require(tos.length == amounts.length, ERC7579NativeSpenderMismatchedBatchLengths(tos.length, amounts.length));
        (uint256 start_, uint256 period) = _periodAt(account, installation_, spender, clock());
        (, uint256 available) = _spendingAt(account, installation_, spender, period, start_);
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= available, ERC7579NativeInsufficientAvailable(account, spender, totalAmount));
        _spentFor[account][installation_][spender][start_][period] += totalAmount;
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_BATCH,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        Execution[] memory executions = new Execution[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            executions[i] = Execution({target: tos[i], value: amounts[i], callData: Calldata.emptyBytes()});
        }
        _execute(account, bytes32(0), Mode.unwrap(mode), ERC7579Utils.encodeBatch(executions));
    }

    /**
     * @dev Internal function to set or update spending configuration for a spender.
     *
     * This function validates all parameters and stores the configuration. It implements
     * the logic to prevent reuse of past start times while allowing updates to active
     * configurations.
     *
     * Requirements:
     *
     * * Each renewal period must be greater than zero. Reverts with {ERC7579NativeSpenderInvalidRenewPeriod} if not.
     * * Each limit must be greater than zero. Reverts with {ERC7579NativeSpenderInvalidLimit} if not.
     * * If keeping the same start time (to update limit/renewPeriod), no timestamp validation is performed.
     * * If changing the start time, the new start must be >= current timepoint. Reverts with
     *   {ERC7579NativeSpenderInvalidStart} if attempting to set a different past start time
     *   (this prevents reusing old start times that might have existing spending data).
     *
     * Emits a {ERC7579NativeSpendingConfigSet} event.
     *
     * NOTE: Reducing the limit to an amount that exceeds the spending during the current
     * period will result in the available amount becoming 0 but won't change the spent amount.
     */
    function _setSpendingConfig(
        address account,
        uint256 installation_,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        require(newRenewPeriod > 0, ERC7579NativeSpenderInvalidRenewPeriod(newRenewPeriod));
        require(newLimit > 0, ERC7579NativeSpenderInvalidLimit(newLimit));
        require(newStart >= clock(), ERC7579NativeSpenderInvalidStart(newStart));
        _spenders[account][installation_].add(spender);
        _config[account][installation_][spender].start = newStart;
        _config[account][installation_][spender].renewPeriod = newRenewPeriod;
        _config[account][installation_][spender].limit = newLimit;
        emit ERC7579NativeSpendingConfigSet(account, spender, newStart, newLimit, newRenewPeriod);
    }

    /**
     * @dev Internal function to remove a spender's configuration.
     *
     * This function removes the spender from the account's spender set and deletes all configuration
     * data, freeing up storage. Unlike setting the limit to 0, this completely removes the spender
     * from the module's tracking.
     *
     * Requirements:
     *
     * * At least one spender must remain after removal. Reverts with {ERC7579NativeSpenderEmptySpenders} if not.
     *
     * Emits a {ERC7579NativeSpendingConfigUnset} event.
     *
     * NOTE: This function does not validate whether the spender was previously configured. Attempting to
     * unset a non-existent spender will succeed but have no effect (besides potentially triggering the
     * empty spenders check if no other spenders exist).
     */
    function _unsetSpendingConfig(address account, uint256 installation_, address spender) internal virtual {
        _spenders[account][installation_].remove(spender);
        require(spendersCount(account) > 0, ERC7579NativeSpenderEmptySpenders());
        delete _config[account][installation_][spender].start;
        delete _config[account][installation_][spender].renewPeriod;
        delete _config[account][installation_][spender].limit;
        emit ERC7579NativeSpendingConfigUnset(account, spender);
    }

    /**
     * @dev Internal function to decode the initialization data for the native spender module.
     *
     * The `initData` should be encoded as: `abi.encode(spenders, starts, limits, renewPeriods)`
     * where each parameter is an array of equal length.
     *
     * Requirements:
     *
     * * `initData` must be at least 256 bytes (8 x 32 bytes for offsets and lengths)
     * * All offsets must point within the `initData` bounds
     *
     * Reverts with {ERC7579NativeSpenderInvalidInitData} if the `initData` is invalid.
     */
    function _decodeNativeSpenderInitData(
        bytes calldata initData
    )
        internal
        virtual
        returns (
            address[] calldata spenders_,
            uint48[] calldata starts,
            uint160[] calldata limits,
            uint48[] calldata renewPeriods
        )
    {
        // Minimum length:
        // starts offset (32 bytes) + starts length (32 bytes) + spenders offset (32 bytes) +
        // spenders length (32 bytes) + limits offset (32 bytes) + limits length (32 bytes) +
        // renewPeriods offset (32 bytes) + renewPeriods length (32 bytes) = 256 bytes
        require(initData.length > 0x99, ERC7579NativeSpenderInvalidInitData());

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
            spenders_.offset := add(initData.offset, spendersDataOffset)
            spenders_.length := spendersLength
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
            limits.offset := add(initData.offset, limitsDataOffset)
            limits.length := limitsLength
            renewPeriods.offset := add(initData.offset, renewPeriodsDataOffset)
            renewPeriods.length := renewPeriodsLength
        }

        return (spenders_, starts, limits, renewPeriods);
    }
}
