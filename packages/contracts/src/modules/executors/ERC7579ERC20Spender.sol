// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC6372} from "@openzeppelin/contracts/interfaces/IERC6372.sol";
import {
    ERC7579Utils,
    ModeSelector,
    ModePayload,
    Mode,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

/**
 * @dev Extension of {ERC7579Executor} that provides ERC20 token spending limits
 * with automatic renewal periods for ERC-7579 smart accounts.
 *
 * This module allows accounts to configure spending allowances for external spenders,
 * enabling use cases like subscription services, recurring payments, or delegated spending
 * with predefined limits. Each spender gets a renewable spending limit that automatically
 * resets at the end of each period, allowing the same spending capacity to be used again
 * without requiring manual intervention.
 *
 * The module implements ERC-6372 to use the token's clock when available. See {clock}
 * and {CLOCK_MODE}.
 *
 * See {SpendingConfig} for the configuration details.
 *
 * TIP: Set {start} to a future timepoint to schedule a spending limit that activates later.
 * TIP: Set {renewPeriod} to {type(uint48).max} to disable the renewal period.
 */
contract ERC7579ERC20Spender is ERC7579Executor, Nonces {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev The account already has tokens with spending configurations installed.
    error ERC7579ERC20SpenderAlreadyInstalled();

    /// @dev The requested `amount` exceeds the `available` spending limit for the `spender`.
    error ERC7579ERC20InsufficientAvailable(address account, address token, address spender, uint256 amount);

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579ERC20SpenderInvalidInitData();

    /// @dev The spending config is not set for the `spender` on the `token`.
    error ERC7579ERC20SpendingConfigNotSet(address account, address token, address spender);

    /// @dev The arrays in `initData` have mismatched lengths.
    error ERC7579ERC20SpenderMismatchedInitDataLengths(
        uint256 tokens,
        uint256 spenders,
        uint256 limits,
        uint256 renewPeriods
    );

    /// @dev The `account` module is left with no spenders.
    error ERC7579ERC20SpenderEmptySpenders();

    /// @dev The `tos` and `amounts` arrays have mismatched lengths in batch transfer.
    error ERC7579ERC20SpenderMismatchedBatchLengths(uint256 tos, uint256 amounts);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579ERC20SpenderInvalidRenewPeriod(uint256 renewPeriod);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579ERC20SpenderInvalidLimit(uint256 limit);

    /// @dev The `token` address is invalid (not a contract).
    error ERC7579ERC20SpenderInvalidToken(address token);

    /// @dev The `start` time is invalid (cannot reuse a past start time).
    error ERC7579ERC20SpenderInvalidStart(uint256 start);

    /// @dev The spending config has not started yet for the given `timepoint`.
    error ERC7579ERC20SpendingConfigNotStarted(
        address account,
        address token,
        address spender,
        uint256 timepoint,
        uint256 start
    );

    /// @dev The account has not installed the module.
    error ERC7579ERC20SpenderUninstalled();

    /// @dev The ERC20 `transfer` call on `token` returned false.
    error ERC7579ERC20SpenderFailedTransfer(address token);

    /// @dev Emitted when all spending configurations are cleared for an account.
    event ERC7579ERC20SpendingConfigCleared(address indexed account);

    /// @dev Emitted when a spending configuration is set for a token-spender pair.
    event ERC7579ERC20SpendingConfigSet(
        address indexed account,
        address indexed token,
        address indexed spender,
        uint256 start,
        uint256 limit,
        uint256 renewPeriod
    );

    /// @dev Emitted when a spending configuration is unset for a token-spender pair.
    event ERC7579ERC20SpendingConfigUnset(address indexed account, address indexed token, address indexed spender);

    /**
     * @dev Spending configuration for a specific token-spender pair on an `account`.
     *
     * The configuration includes:
     *
     * * `start`: When the spending limit becomes active (in the token's clock timepoint)
     * * `renewPeriod`: Duration of each spending period (in the token's clock units)
     * * `limit`: Maximum spendable amount per period
     */
    struct SpendingConfig {
        // Slot 1
        uint48 start; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint48 renewPeriod; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint160 limit; // Up to 1.4615016373e30 with 18 decimals (2**160 / 1e18)
    }

    mapping(address account => mapping(uint256 installation => mapping(address token => mapping(address spender => SpendingConfig))))
        private _config;
    mapping(address account => mapping(uint256 installation => mapping(address token => mapping(address spender => mapping(uint256 start => mapping(uint256 period => uint256))))))
        private _spentFor;
    mapping(address account => mapping(uint256 installation => mapping(address token => EnumerableSet.AddressSet)))
        private _spenders;
    mapping(address account => mapping(uint256 installation => EnumerableSet.AddressSet)) private _tokens;

    /**
     * @dev Clock used for flagging checkpoints. Defaults to the token's clock if it implements
     * ERC-6372, otherwise falls back to timestamp.
     */
    function clock(address token) public view virtual returns (uint48) {
        try IERC6372(token).clock() returns (uint48 timepoint) {
            return timepoint;
        } catch {
            return Time.timestamp();
        }
    }

    /**
     * @dev Machine-readable description of the clock as specified in ERC-6372.
     */
    function CLOCK_MODE(address token) public view virtual returns (string memory) {
        try IERC6372(token).CLOCK_MODE() returns (string memory clockmode) {
            return clockmode;
        } catch {
            return "mode=timestamp";
        }
    }

    /// @dev Returns whether the module is installed for an `account`.
    function installed(address account) public view virtual returns (bool) {
        return tokensCount(account) > 0;
    }

    /// @dev Returns the installation nonce for an `account`. See {onUninstall}.
    function installation(address account) public view virtual returns (uint256) {
        return nonces(account);
    }

    /// @dev Returns the start timepoint for the spending configuration of a `spender` on an `account` for a `token`.
    function start(address account, address token, address spender) public view virtual returns (uint256) {
        return _start(account, installation(account), token, spender);
    }

    /// @dev Returns the renewal period (in seconds) for the spending configuration of a `spender` on an `account` for a `token`.
    function renewPeriod(address account, address token, address spender) public view virtual returns (uint256) {
        return _renewPeriod(account, installation(account), token, spender);
    }

    /// @dev Returns the spending limit per period for a `spender` on an `account` for a `token`.
    function limit(address account, address token, address spender) public view virtual returns (uint256) {
        return _limit(account, installation(account), token, spender);
    }

    /// @dev Returns the amount spent by a `spender` during a specific `period` for an `account` for a `token`.
    function spent(
        address account,
        address token,
        address spender,
        uint256 period
    ) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _spent(account, installation_, token, spender, period, _start(account, installation_, token, spender));
    }

    /// @dev Same as {spent} but receives a `start_` timepoint.
    function spent(
        address account,
        address token,
        address spender,
        uint256 period,
        uint256 start_
    ) public view virtual returns (uint256) {
        return _spent(account, installation(account), token, spender, period, start_);
    }

    /// @dev Returns the number of spenders installed for an `account` for a `token`.
    function spendersCount(address account, address token) public view virtual returns (uint256) {
        return _spenders[account][installation(account)][token].length();
    }

    /**
     * @dev Returns a slice of the set of spenders installed for an `account` for a `token`.
     *
     * Using `startIdx = 0` and `endIdx = type(uint256).max` will return the entire set of spenders.
     *
     * WARNING: Depending on the `startIdx` and `endIdx`, this operation can copy a large amount of data to memory, which
     * can be expensive. This is designed for view accessors queried without gas fees. Using it in state-changing
     * functions may become uncallable if the slice grows too large.
     */
    function spenders(
        address account,
        address token,
        uint256 startIdx,
        uint256 endIdx
    ) public view virtual returns (address[] memory spenders_) {
        return _spenders[account][installation(account)][token].values(startIdx, endIdx);
    }

    /// @dev Returns the number of tokens with spending configurations installed for an `account`.
    function tokensCount(address account) public view virtual returns (uint256) {
        return _tokens[account][installation(account)].length();
    }

    /**
     * @dev Returns a slice of the set of tokens with spending configurations installed for an `account`.
     *
     * Using `startIdx = 0` and `endIdx = type(uint256).max` will return the entire set of tokens.
     *
     * WARNING: Depending on the `startIdx` and `endIdx`, this operation can copy a large amount of data to memory, which
     * can be expensive. This is designed for view accessors queried without gas fees. Using it in state-changing
     * functions may become uncallable if the slice grows too large.
     */
    function tokens(
        address account,
        uint256 startIdx,
        uint256 endIdx
    ) public view virtual returns (address[] memory tokens_) {
        return _tokens[account][installation(account)].values(startIdx, endIdx);
    }

    /// @dev Returns the spending information for a `spender` at a specific `period` for an `account` for a `token`.
    function spendingAt(
        address account,
        address token,
        address spender,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 installation_ = installation(account);
        return
            _spendingAt(account, installation_, token, spender, period, _start(account, installation_, token, spender));
    }

    /**
     * @dev Returns the period information for a `spender` at a specific `timepoint` for an `account` for a `token`.
     *
     * Requirements:
     *
     * * The `timepoint` must be greater or equal than {start} for the current spending configuration.
     *   Reverts with {ERC7579ERC20SpendingConfigNotStarted} if not.
     */
    function periodAt(
        address account,
        address token,
        address spender,
        uint48 timepoint
    ) public view virtual returns (uint256 start_, uint256 period) {
        return _periodAt(account, installation(account), token, spender, timepoint);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * See {IERC7579Module-onInstall}. The `initData` encodes arrays of tokens, spenders and their
     * corresponding spending configurations.
     *
     * Requirements:
     *
     * * The `initData` must be encoded as: `abi.encode(tokens, spenders, starts, limits, renewPeriods)`.
     *   Reverts with {ERC7579ERC20SpenderInvalidInitData} if not.
     * * All arrays must have equal length. Reverts with {ERC7579ERC20SpenderMismatchedInitDataLengths} if not.
     * * Those from {_setSpendingConfig} for the configuration requirements.
     *
     * TIP: Each start will be set to the current timepoint if it's 0.
     */
    function onInstall(bytes calldata initData) public virtual {
        address account = msg.sender;
        require(!installed(account), ERC7579ERC20SpenderAlreadyInstalled());
        // Minimum length:
        // tokens offset (32 bytes) + tokens length (32 bytes) + spenders offset (32 bytes) +
        // spenders length (32 bytes) + starts offset (32 bytes) + starts length (32 bytes) +
        // limits offset (32 bytes) + limits length (32 bytes) + renewPeriods offset (32 bytes) +
        // renewPeriods length (32 bytes) = 320 bytes
        require(initData.length > 0x13f, ERC7579ERC20SpenderInvalidInitData());
        address[] calldata tokens_ = _decodeERC20SpenderInitDataTokens(initData);
        address[] calldata spenders_ = _decodeERC20SpenderInitDataSpenders(initData);
        uint48[] calldata starts = _decodeERC20SpenderInitDataStarts(initData);
        uint160[] calldata limits = _decodeERC20SpenderInitDataLimits(initData);
        uint48[] calldata renewPeriods = _decodeERC20SpenderInitDataRenewPeriods(initData);
        require(
            tokens_.length == spenders_.length &&
                spenders_.length == starts.length &&
                spenders_.length == limits.length &&
                spenders_.length == renewPeriods.length,
            ERC7579ERC20SpenderMismatchedInitDataLengths(
                tokens_.length,
                spenders_.length,
                limits.length,
                renewPeriods.length
            )
        );
        require(spenders_.length > 0, ERC7579ERC20SpenderEmptySpenders());
        uint256 installation_ = installation(account);
        for (uint256 i = 0; i < spenders_.length; ++i) {
            _setSpendingConfig(account, installation_, tokens_[i], spenders_[i], starts[i], limits[i], renewPeriods[i]);
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
        emit ERC7579ERC20SpendingConfigCleared(msg.sender);
    }

    /**
     * @dev Transfers ERC20 tokens from an `account` to a recipient on behalf of a `msg.sender`.
     *
     * This function tracks the spending limit for the `msg.sender` on the `account` for the given `token`
     * and updates the spent amount for the current period before executing the transfer through the account's
     * {IERC7579Execution-executeFromExecutor} function.
     *
     * Requirements:
     *
     * * The `amount` must not exceed the available spending limit for the current period.
     *   Reverts with {ERC7579ERC20InsufficientAvailable} if it does.
     * * The `account` must have sufficient token balance. Bubbles the revert reason if transfer fails.
     * * Those of {_periodAt} for the current timepoint.
     */
    function transferFrom(address account, address token, address to, uint256 amount) public virtual {
        _transferFrom(account, token, msg.sender, to, amount);
    }

    /**
     * @dev Transfers ERC20 tokens from an `account` to multiple recipients in a single transaction.
     *
     * It calculates the total amount, checks against the limit once, and executes all transfers in batch.
     *
     * Requirements:
     *
     * * The `tos` and `amounts` arrays must have equal length. Reverts with
     *   {ERC7579ERC20SpenderMismatchedBatchLengths} if not.
     * * The sum of all `amounts` must not exceed the available spending limit for the current period.
     *   Reverts with {ERC7579ERC20InsufficientAvailable} if it does.
     * * The `account` must have sufficient token balance for all transfers. Reverts with
     *   Bubbles the revert reason of the first failed transfer, if any.
     * * Those of {_periodAt} for the current timepoint.
     */
    function batchTransferFrom(
        address account,
        address token,
        address[] calldata tos,
        uint256[] calldata amounts
    ) public virtual {
        _batchTransferFrom(account, token, msg.sender, tos, amounts);
    }

    /**
     * @dev Updates the spending configuration for a `token`-`spender` pair.
     *
     * This function allows an account to modify spending {limit}, {renewPeriod}, or {start} time
     * for a specific token-spender pair. Can be called directly by the account.
     *
     * Requirements:
     *
     * * The module must be installed. Reverts with {ERC7579ERC20SpenderUninstalled} if not.
     * * Those from {_setSpendingConfig}.
     *
     * TIP: Setting `newStart` to 0 will resolve to the current timepoint.
     */
    function setSpendingConfig(
        address token,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) public virtual {
        require(installed(msg.sender), ERC7579ERC20SpenderUninstalled());
        _setSpendingConfig(msg.sender, installation(msg.sender), token, spender, newStart, newLimit, newRenewPeriod);
    }

    /// @dev Same as {setSpendingConfig} but sets a configuration that starts immediately.
    function setSpendingConfig(address token, address spender, uint160 newLimit, uint48 newRenewPeriod) public virtual {
        setSpendingConfig(token, spender, 0, newLimit, newRenewPeriod);
    }

    /**
     * @dev Removes the spending configuration for a `token`-`spender` pair.
     *
     * This function allows an account to completely remove a token-spender configuration, freeing up storage
     * and removing the spender from the account's spender set for that token. Can be called directly by the account.
     *
     * Requirements:
     *
     * * Those from {_unsetSpendingConfig}.
     */
    function unsetSpendingConfig(address token, address spender) public virtual {
        _unsetSpendingConfig(msg.sender, installation(msg.sender), token, spender);
    }

    /// @dev Internal version of {start} that receives an `installation_` nonce.
    function _start(
        address account,
        uint256 installation_,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][token][spender].start;
    }

    /// @dev Internal version of {renewPeriod} that receives an `installation_` nonce.
    function _renewPeriod(
        address account,
        uint256 installation_,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][token][spender].renewPeriod;
    }

    /// @dev Internal version of {limit} that receives an `installation_` nonce.
    function _limit(
        address account,
        uint256 installation_,
        address token,
        address spender
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][token][spender].limit;
    }

    /// @dev Internal version of {spent} that receives an `installation_` nonce and a `start_` timepoint.
    function _spent(
        address account,
        uint256 installation_,
        address token,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256) {
        return _spentFor[account][installation_][token][spender][start_][period];
    }

    /// @dev Internal version of {spendingAt} that receives an `installation_` nonce and a `start_` timepoint.
    function _spendingAt(
        address account,
        uint256 installation_,
        address token,
        address spender,
        uint256 period,
        uint256 start_
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, installation_, token, spender, period, start_);
        (bool success, uint256 available_) = Math.trySub(_limit(account, installation_, token, spender), spending);
        return (spending, Math.ternary(success, available_, 0));
    }

    /**
     * @dev Internal version of {periodAt} that receives an `installation_` nonce.
     *
     * Requirements:
     *
     * * The `timepoint` must be greater or equal than {start} for the current spending configuration.
     *   Reverts with {ERC7579ERC20SpendingConfigNotStarted} if not.
     * * The {renewPeriod} must be greater than zero. Reverts with {ERC7579ERC20SpendingConfigNotSet} if not.
     */
    function _periodAt(
        address account,
        uint256 installation_,
        address token,
        address spender,
        uint48 timepoint
    ) internal view virtual returns (uint256 start_, uint256 period) {
        start_ = _start(account, installation_, token, spender);
        (bool success, uint256 ellapsed) = Math.trySub(timepoint, start_);
        require(success, ERC7579ERC20SpendingConfigNotStarted(account, token, spender, timepoint, start_));
        uint256 renewPeriod_ = _renewPeriod(account, installation_, token, spender);
        require(renewPeriod_ > 0, ERC7579ERC20SpendingConfigNotSet(account, token, spender));
        return (start_, ellapsed / renewPeriod_); // Division error is ok here
    }

    /// @dev Internal version of {transferFrom} without access control.
    function _transferFrom(
        address account,
        address token,
        address spender,
        address to,
        uint256 amount
    ) internal virtual {
        uint256 installation_ = installation(account);
        (uint256 start_, uint256 period) = _periodAt(account, installation_, token, spender, clock(token));
        (, uint256 available) = _spendingAt(account, installation_, token, spender, period, start_);
        require(amount <= available, ERC7579ERC20InsufficientAvailable(account, token, spender, amount));
        _spentFor[account][installation_][token][spender][start_][period] += amount;
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
        bytes memory returndata = returndatas[0];
        bool standardReturn;
        // Accept empty returndata (non-standard ERC20 with no return value) or an explicit true.
        assembly ("memory-safe") {
            standardReturn := or(iszero(mload(returndata)), eq(mload(add(returndata, 0x20)), 1))
        }
        require(standardReturn, ERC7579ERC20SpenderFailedTransfer(token));
    }

    /// @dev Internal version of {batchTransferFrom} without access control.
    function _batchTransferFrom(
        address account,
        address token,
        address spender,
        address[] calldata tos,
        uint256[] calldata amounts
    ) internal virtual {
        require(tos.length == amounts.length, ERC7579ERC20SpenderMismatchedBatchLengths(tos.length, amounts.length));
        uint256 installation_ = installation(account);
        (uint256 start_, uint256 period) = _periodAt(account, installation_, token, spender, clock(token));
        (, uint256 available) = _spendingAt(account, installation_, token, spender, period, start_);
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= available, ERC7579ERC20InsufficientAvailable(account, token, spender, totalAmount));
        _spentFor[account][installation_][token][spender][start_][period] += totalAmount;
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_BATCH,
            ERC7579Utils.EXECTYPE_DEFAULT,
            ModeSelector.wrap(0),
            ModePayload.wrap(0)
        );
        Execution[] memory executions = new Execution[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            executions[i] = Execution({
                target: token,
                value: 0,
                callData: abi.encodeCall(IERC20.transfer, (tos[i], amounts[i]))
            });
        }
        bytes[] memory returndatas = _execute(
            account,
            bytes32(0),
            Mode.unwrap(mode),
            ERC7579Utils.encodeBatch(executions)
        );
        for (uint256 i = 0; i < returndatas.length; ++i) {
            bytes memory returndata = returndatas[i];
            bool standardReturn;
            // Accept empty returndata (non-standard ERC20 with no return value) or an explicit true.
            assembly ("memory-safe") {
                standardReturn := or(iszero(mload(returndata)), eq(mload(add(returndata, 0x20)), 1))
            }
            require(standardReturn, ERC7579ERC20SpenderFailedTransfer(executions[i].target));
        }
    }

    /**
     * @dev Internal function to set or update spending configuration for a token-spender pair.
     *
     * This function validates all parameters and stores the configuration. It implements
     * the logic to prevent reuse of past start times while allowing updates to active
     * configurations.
     *
     * Requirements:
     *
     * * Each renewal period must be greater than zero. Reverts with {ERC7579ERC20SpenderInvalidRenewPeriod} if not.
     * * Each limit must be greater than zero. Reverts with {ERC7579ERC20SpenderInvalidLimit} if not.
     * * The token must be a contract address. Reverts with {ERC7579ERC20SpenderInvalidToken} if not.
     * * If `newStart` is non-zero, it must be >= current timepoint. Setting 0 would resolve
     *   to the current timepoint. Reverts with {ERC7579ERC20SpenderInvalidStart} if attempting
     *   to set any other past start time.
     *   (this prevents reusing old start times that might have existing spending data).
     *
     * Emits a {ERC7579ERC20SpendingConfigSet} event.
     *
     * NOTE: Reducing the limit to an amount that exceeds the spending during the current
     * period will result in the available amount becoming 0 but won't change the spent amount.
     */
    function _setSpendingConfig(
        address account,
        uint256 installation_,
        address token,
        address spender,
        uint48 newStart,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        require(newRenewPeriod > 0, ERC7579ERC20SpenderInvalidRenewPeriod(newRenewPeriod));
        require(newLimit > 0, ERC7579ERC20SpenderInvalidLimit(newLimit));
        require(address(token).code.length > 0, ERC7579ERC20SpenderInvalidToken(token));
        uint48 currentTimepoint = clock(token);
        uint48 resolvedStart = uint48(Math.ternary(newStart == 0, currentTimepoint, newStart)); // Safe cast. Both are uint48.
        require(resolvedStart >= currentTimepoint, ERC7579ERC20SpenderInvalidStart(newStart));
        _spenders[account][installation_][token].add(spender);
        _tokens[account][installation_].add(token);
        _config[account][installation_][token][spender].start = resolvedStart;
        _config[account][installation_][token][spender].renewPeriod = newRenewPeriod;
        _config[account][installation_][token][spender].limit = newLimit;
        emit ERC7579ERC20SpendingConfigSet(account, token, spender, resolvedStart, newLimit, newRenewPeriod);
    }

    /**
     * @dev Internal function to remove a token-spender configuration.
     *
     * This function removes the spender from the account's spender set for the given token and deletes all
     * configuration data, freeing up storage. Unlike setting the limit to 0, this completely removes the spender
     * from the module's tracking for that token. If this was the last spender for the token, the token itself
     * is also removed from the account's token set.
     *
     * Requirements:
     *
     * * At least one token must remain after removal. Reverts with {ERC7579ERC20SpenderEmptySpenders} if not.
     *
     * Emits a {ERC7579ERC20SpendingConfigUnset} event.
     *
     * NOTE: This function does not validate whether the token-spender pair was previously configured. Attempting to
     * unset a non-existent configuration will succeed but have no effect (besides potentially triggering the
     * empty spenders check if no other tokens exist).
     */
    function _unsetSpendingConfig(
        address account,
        uint256 installation_,
        address token,
        address spender
    ) internal virtual {
        _spenders[account][installation_][token].remove(spender);
        // If no spenders left for this token, remove the token
        if (spendersCount(account, token) == 0) {
            _tokens[account][installation_].remove(token);
        }
        require(tokensCount(account) > 0, ERC7579ERC20SpenderEmptySpenders());
        delete _config[account][installation_][token][spender].start;
        delete _config[account][installation_][token][spender].renewPeriod;
        delete _config[account][installation_][token][spender].limit;
        emit ERC7579ERC20SpendingConfigUnset(account, token, spender);
    }

    /**
     * @dev Internal function to decode the tokens from the initialization data.
     *
     * Requirements:
     *
     * * The `initData` must be at least 32 bytes (1 x 32 bytes for the offset)
     * * The offset must point within the `initData` bounds
     * * The offset must be greater than 0
     * * The offset must be less than the length of the `initData`
     */
    function _decodeERC20SpenderInitDataTokens(
        bytes calldata initData
    ) private pure returns (address[] calldata tokens_) {
        uint256 tokensOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 tokensDataOffset = tokensOffset + 0x20;
        require(tokensDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 tokensLength = uint256(bytes32(initData[tokensOffset:tokensDataOffset]));
        require(tokensDataOffset + tokensLength * 0x20 <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        assembly ("memory-safe") {
            tokens_.offset := add(initData.offset, tokensDataOffset)
            tokens_.length := tokensLength
        }
        return tokens_;
    }

    /**
     * @dev Internal function to decode the spenders from the initialization data.
     *
     * Requirements:
     *
     * * The `initData` must be at least 32 bytes (1 x 32 bytes for the offset)
     * * The offset must point within the `initData` bounds
     * * The offset must be greater than 0
     * * The offset must be less than the length of the `initData`
     */
    function _decodeERC20SpenderInitDataSpenders(
        bytes calldata initData
    ) private pure returns (address[] calldata spenders_) {
        uint256 spendersOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 spendersDataOffset = spendersOffset + 0x20;
        require(spendersDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 spendersLength = uint256(bytes32(initData[spendersOffset:spendersDataOffset]));
        require(spendersDataOffset + spendersLength * 0x20 <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        assembly ("memory-safe") {
            spenders_.offset := add(initData.offset, spendersDataOffset)
            spenders_.length := spendersLength
        }
        return spenders_;
    }

    /**
     * @dev Internal function to decode the starts from the initialization data.
     *
     * Requirements:
     *
     * * The `initData` must be at least 32 bytes (1 x 32 bytes for the offset)
     * * The offset must point within the `initData` bounds
     * * The offset must be greater than 0
     * * The offset must be less than the length of the `initData`
     */
    function _decodeERC20SpenderInitDataStarts(
        bytes calldata initData
    ) private pure returns (uint48[] calldata starts) {
        uint256 startsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 startsDataOffset = startsOffset + 0x20;
        require(startsDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 startsLength = uint256(bytes32(initData[startsOffset:startsDataOffset]));
        require(startsDataOffset + startsLength * 0x20 <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        assembly ("memory-safe") {
            starts.offset := add(initData.offset, startsDataOffset)
            starts.length := startsLength
        }
        return starts;
    }

    /**
     * @dev Internal function to decode the limits from the initialization data.
     *
     * Requirements:
     *
     * * The `initData` must be at least 32 bytes (1 x 32 bytes for the offset)
     * * The offset must point within the `initData` bounds
     * * The offset must be greater than 0
     * * The offset must be less than the length of the `initData`
     */
    function _decodeERC20SpenderInitDataLimits(
        bytes calldata initData
    ) private pure returns (uint160[] calldata limits) {
        uint256 limitsOffset = uint256(bytes32(initData[0x60:0x80]));
        uint256 limitsDataOffset = limitsOffset + 0x20;
        require(limitsDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 limitsLength = uint256(bytes32(initData[limitsOffset:limitsDataOffset]));
        require(limitsDataOffset + limitsLength * 0x20 <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        assembly ("memory-safe") {
            limits.offset := add(initData.offset, limitsDataOffset)
            limits.length := limitsLength
        }
        return limits;
    }

    /**
     * @dev Internal function to decode the renew periods from the initialization data.
     *
     * Requirements:
     *
     * * The `initData` must be at least 32 bytes (1 x 32 bytes for the offset)
     * * The offset must point within the `initData` bounds
     * * The offset must be greater than 0
     * * The offset must be less than the length of the `initData`
     */
    function _decodeERC20SpenderInitDataRenewPeriods(
        bytes calldata initData
    ) private pure returns (uint48[] calldata renewPeriods) {
        uint256 renewPeriodsOffset = uint256(bytes32(initData[0x80:0xa0]));
        uint256 renewPeriodsDataOffset = renewPeriodsOffset + 0x20;
        require(renewPeriodsDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 renewPeriodsLength = uint256(bytes32(initData[renewPeriodsOffset:renewPeriodsDataOffset]));
        require(
            renewPeriodsDataOffset + renewPeriodsLength * 0x20 <= initData.length,
            ERC7579ERC20SpenderInvalidInitData()
        );
        assembly ("memory-safe") {
            renewPeriods.offset := add(initData.offset, renewPeriodsDataOffset)
            renewPeriods.length := renewPeriodsLength
        }
        return renewPeriods;
    }
}
