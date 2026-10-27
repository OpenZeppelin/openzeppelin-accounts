// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    IERC7579Module,
    IERC7579Execution,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {
    ERC7579Utils,
    ModeSelector,
    ModePayload,
    Mode,
    CallType,
    Execution
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {ERC7579SessionKeys} from "../ERC7579SessionKeys.sol";
import {ERC7579Validator} from "../validators/ERC7579Validator.sol";
import {ERC7579SessionKeysValidator} from "../validators/ERC7579SessionKeysValidator.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

/**
 * @dev Extension of {ERC7579SessionKeysValidator} that provides native token (ETH) spending
 * limits granted to session keys with automatic renewal periods for ERC-7579 smart accounts.
 *
 * This module allows accounts to configure spending allowances for external spenders,
 * enabling use cases like subscription services, recurring payments, or delegated spending
 * with predefined limits.
 *
 * The module is both a validator and an executor:
 *
 * * As a **validator**, it authorizes user operations signed by a registered session key whose
 *   `callData` is a single call into this module's {transferFrom} or {batchTransferFrom}. The
 *   key's validity range is packed into `validationData` so the EntryPoint enforces it natively.
 * * As an **executor**, it spends from the account through `executeFromExecutor`, decrementing
 *   the per-key, per-period limit.
 *
 * Each session key carries its own `(limit, renewPeriod)` spending policy. The start of the
 * spending periods is the session key's `from` timepoint. Periods automatically renew every
 * `renewPeriod` time units, allowing the same spending capacity to be used again without
 * requiring manual intervention. It implements ERC-6372 clock functions.
 *
 * > [!NOTE]
 * > The module should be installed under both module types, in this order:
 * >
 * > 1. **Validator install (first)**: `initData` is
 * >    `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends, uint256[] gasBudgets)`.
 * >    This registers session keys with their validity ranges through {ERC7579SessionKeys-_addKeys}.
 * >    At least one key must be registered, otherwise the install reverts.
 * > 2. **Executor install (second)**: `initData` is `abi.encode(bytes[] keys, uint160[] limits, uint48[] renewPeriods)`.
 * >    This writes a spending policy for each already-registered key. The `keys` array MUST be
 * >    non-empty and reconfiguration is banned: once a key has been configured, neither it nor any
 * >    other key can be reconfigured under the current installation. To change the spending policy,
 * >    the account must uninstall and reinstall the module (which bumps the installation nonce and
 * >    resets state).
 * >
 * > Install and uninstall both module types together. Uninstalling either one resets the whole
 * > installation (session keys and spending policies) for both roles.
 *
 * > [!NOTE]
 * > Gas fees are not counted against the spending limits. They are charged to the key's
 * > {ERC7579SessionKeysValidator-gasBudget} instead.
 *
 * > [!IMPORTANT]
 * > This module deliberately disables ERC-1271 signing
 * > ({isValidSignatureWithSender} always returns `0xffffffff`) so a spending session key cannot be
 * > repurposed to authorize arbitrary off-chain messages on behalf of the account.
 *
 * > [!TIP]
 * > Set {start} to a future timepoint to schedule a spending limit that activates later.
 *
 * > [!TIP]
 * > Set {renewPeriod} to `type(uint48).max` to disable the renewal period.
 */
contract ERC7579NativeSpender is ERC7579SessionKeysValidator, ERC7579Executor {
    /// @dev The account already has spenders installed.
    error ERC7579NativeSpenderAlreadyInstalled();

    /// @dev The requested `amount` exceeds the available spending limit for `key`.
    error ERC7579NativeInsufficientAvailable(address account, bytes key, uint256 amount);

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579NativeSpenderInvalidInitData();

    /// @dev The spending config is not set for `key`.
    error ERC7579NativeSpendingConfigNotSet(address account, bytes32 keyId);

    /// @dev The arrays in `initData` have mismatched lengths.
    error ERC7579NativeSpenderMismatchedInitDataLengths(uint256 keys, uint256 limits, uint256 renewPeriods);

    /// @dev The first install registered zero session keys.
    error ERC7579NativeSpenderEmptyKeys();

    /// @dev The `tos` and `amounts` arrays have mismatched lengths in batch transfer.
    error ERC7579NativeSpenderMismatchedBatchLengths(uint256 tos, uint256 amounts);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579NativeSpenderInvalidRenewPeriod(uint256 renewPeriod);

    /// @dev The `limit` is invalid (must be greater than zero).
    error ERC7579NativeSpenderInvalidLimit(uint256 limit);

    /// @dev The spending config has not started yet for `key` at `timepoint`.
    error ERC7579NativeSpendingConfigNotStarted(address account, bytes32 keyId, uint256 timepoint, uint256 start);

    /// @dev The caller is not authorized to spend on behalf of `key`.
    error ERC7579NativeSpenderUnauthorized(address caller, bytes key);

    /// @dev The `start` time is invalid (cannot reuse a past start time).
    error ERC7579NativeSpenderInvalidStart(uint256 start);

    /// @dev Emitted when the spending configuration is set or updated for a `key`.
    event ERC7579NativeSpendingConfigSet(
        address indexed account,
        bytes indexed key,
        uint256 limit,
        uint256 renewPeriod
    );

    /// @dev Emitted when the spending configuration is removed for a `key`.
    event ERC7579NativeSpendingConfigUnset(address indexed account, bytes indexed key);

    /**
     * @dev Spending configuration for a specific account-key pair.
     *
     * The configuration includes:
     *
     * * `renewPeriod`: Duration of each spending period (in the clock's units)
     * * `limit`: Maximum spendable amount per period
     */
    struct SpendingConfig {
        uint48 renewPeriod; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint160 limit; // Up to 1.4615016373e30 with 18 decimals (2**160 / 1e18)
    }

    // The account is the innermost key of mappings read or written during validation, so that their slots are
    // associated with the account (ERC-7562).
    mapping(uint256 installation => mapping(bytes32 keyId => mapping(address account => SpendingConfig)))
        private _config;
    mapping(address account => mapping(uint256 installation => mapping(bytes32 keyId => mapping(uint256 start => mapping(uint256 period => uint256)))))
        private _spentFor;

    /// @inheritdoc IERC7579Module
    function isModuleType(
        uint256 moduleTypeId
    ) public pure virtual override(ERC7579Validator, ERC7579Executor, IERC7579Module) returns (bool) {
        return ERC7579Validator.isModuleType(moduleTypeId) || ERC7579Executor.isModuleType(moduleTypeId);
    }

    /// @dev Returns whether the module's first-install step has completed for `account`.
    function installed(address account) public view virtual returns (bool) {
        return _installed(account, installation(account));
    }

    /// @dev Returns the renewal period for `key`'s spending config on `account`.
    function renewPeriod(address account, bytes calldata key) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _renewPeriod(account, installation_, _keyId(account, installation_, key));
    }

    /// @dev Returns the spending limit per period for `key` on `account`.
    function limit(address account, bytes calldata key) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _limit(account, installation_, _keyId(account, installation_, key));
    }

    /// @dev Returns the amount spent by `key` during `period` on `account`, anchored at the key's `from`.
    function spent(address account, bytes calldata key, uint256 period) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        bytes32 keyId = _keyId(account, installation_, key);
        (uint48 from, ) = _validity(account, installation_, keyId);
        return _spent(account, installation_, keyId, period, from);
    }

    /// @dev Same as {spent} but reads from an explicit `start` timepoint (useful for inspecting history).
    function spent(
        address account,
        bytes calldata key,
        uint256 period,
        uint256 start
    ) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        return _spent(account, installation_, _keyId(account, installation_, key), period, start);
    }

    /// @dev Returns `(spending, available)` for `key` at `period` on `account`.
    function spendingAt(
        address account,
        bytes calldata key,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 installation_ = installation(account);
        bytes32 keyId = _keyId(account, installation_, key);
        (uint48 from, ) = _validity(account, installation_, keyId);
        return _spendingAt(account, installation_, keyId, period, from);
    }

    /**
     * @dev Returns `(start, period)` for `key` on `account` at `timepoint`.
     *
     * Requirements:
     *
     * * `timepoint` must be `>=` the key's `from`. Reverts with {ERC7579NativeSpendingConfigNotStarted} otherwise.
     * * The spending config must be set. Reverts with {ERC7579NativeSpendingConfigNotSet} otherwise.
     */
    function periodAt(
        address account,
        bytes calldata key,
        uint48 timepoint
    ) public view virtual returns (uint256 start, uint256 period) {
        uint256 installation_ = installation(account);
        return _periodAt(account, installation_, _keyId(account, installation_, key), timepoint);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     *
     * This module is installed under BOTH module types and `onInstall` is called twice. The
     * shape of `initData` differs between the two calls:
     *
     * * **First call** (validator install, `installed(msg.sender) == false`):
     *   `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends, uint256[] gasBudgets)`.
     * * **Second call** (executor install, `installed(msg.sender) == true`):
     *   `abi.encode(bytes[] keys, uint160[] limits, uint48[] renewPeriods)`.
     *
     * First call requirements:
     *
     * * The `keys` array must be non-empty. Reverts with {ERC7579NativeSpenderEmptyKeys} otherwise.
     * * Those from the parent's {ERC7579SessionKeysValidator-onInstall} (key registration and gas budgets).
     *
     * Second call requirements:
     *
     * * The account must not have configured the keys yet. Reverts with {ERC7579NativeSpenderAlreadyInstalled} otherwise.
     * * Those of {_decodeKeyConfigsInitData} for the decoding requirements.
     * * All arrays must have equal length. Reverts with {ERC7579NativeSpenderMismatchedInitDataLengths} if not.
     * * The `keys` array must be non-empty. Reverts with {ERC7579NativeSpenderEmptyKeys} otherwise.
     * * Each key must be registered. Reverts with {ERC7579SessionKeysNonexistentKey} otherwise.
     * * Those from {_setConfig} for the spending config requirements.
     *
     * Emits {ERC7579SessionKeysERC7913KeySet} on the first call and {ERC7579NativeSpendingConfigSet}
     * for each entry on the second call.
     *
     * > [!TIP]
     * > Each start will be set to the current timepoint if it's 0.
     */
    function onInstall(bytes calldata initData) public virtual override(ERC7579SessionKeysValidator, IERC7579Module) {
        if (!installed(msg.sender)) {
            super.onInstall(initData);
            require(installed(msg.sender), ERC7579NativeSpenderEmptyKeys());
        } else {
            uint256 installation_ = installation(msg.sender);

            // After the second install, there must be at least one key with non-zero spending config.
            bytes[] memory keys = _keys(msg.sender, installation_, 0, 1);
            require(
                _limit(msg.sender, installation_, _keyId(msg.sender, installation_, keys[0])) == 0,
                /* && _renewPeriod(msg.sender, installation_, _keyId(msg.sender, installation_, keys[0])) == 0 */ ERC7579NativeSpenderAlreadyInstalled()
            );

            (
                bytes[] calldata keys_,
                uint160[] calldata limits,
                uint48[] calldata renewPeriods
            ) = _decodeKeyConfigsInitData(initData);
            require(
                keys_.length == limits.length && keys_.length == renewPeriods.length,
                ERC7579NativeSpenderMismatchedInitDataLengths(keys_.length, limits.length, renewPeriods.length)
            );
            require(keys_.length > 0, ERC7579NativeSpenderEmptyKeys());
            for (uint256 i = 0; i < keys_.length; ++i) {
                require(_isKey(msg.sender, installation_, keys_[i]), ERC7579SessionKeysNonexistentKey(keys_[i]));
                _setConfig(msg.sender, installation_, keys_[i], limits[i], renewPeriods[i]);
            }
        }
    }

    /**
     * @dev Adds new session keys with their spending configurations in a single call. Can only be
     * called by the account itself. See {_addKeysWithConfig} for requirements.
     *
     * > [!TIP]
     * > New keys have no gas budget. Set it with {ERC7579SessionKeysValidator-setGasBudget}, for example in
     * > the same batch.
     */
    function addKeysWithConfig(
        bytes[] calldata newKeys,
        uint48[] calldata starts,
        uint48[] calldata ends,
        uint160[] calldata limits,
        uint48[] calldata renewPeriods
    ) public virtual {
        _addKeysWithConfig(msg.sender, installation(msg.sender), newKeys, starts, ends, limits, renewPeriods);
    }

    /**
     * @dev Transfers native tokens from `account` to `to` on behalf of `key`.
     *
     * This function tracks the spending limit for the `key` on the `account` and updates
     * the spent amount for the current period before executing the transfer through the account's
     * {IERC7579Execution-executeFromExecutor} function.
     *
     * Two authorization paths are accepted:
     *
     * 1. **Executor flow**: `msg.sender == account`. The validator has already verified the session
     *    key's signature and the calldata shape, so no further checks are performed here.
     * 2. **EOA self-call**: `key.length == 20` and `address(bytes20(key)) == msg.sender`. The key's
     *    validity range is enforced manually.
     *
     * Requirements:
     *
     * * The caller is authorized via one of the two paths above. Reverts with
     *   {ERC7579NativeSpenderUnauthorized} otherwise.
     * * `amount` must not exceed the available limit for the current period. Reverts with
     *   {ERC7579NativeInsufficientAvailable} otherwise.
     * * Those from {_periodAt} for the current timepoint.
     *
     * > [!NOTE]
     * > The limit bounds the total value spent per period, not the number of calls. A zero `amount`
     * > is allowed and executes an empty call to `to`.
     */
    function transferFrom(address account, bytes calldata key, address to, uint256 amount) public virtual {
        uint256 installation_ = installation(account);
        _checkAccountOrKeySender(account, installation_, key);
        _transferFrom(account, installation_, key, to, amount);
    }

    /**
     * @dev Transfers native tokens from `account` to multiple recipients in a single batch.
     *
     * Same authorization paths as {transferFrom}. The available limit check is performed once
     * against the total of `amounts`.
     *
     * Requirements:
     *
     * * `tos.length == amounts.length`. Reverts with {ERC7579NativeSpenderMismatchedBatchLengths} otherwise.
     * * The caller is authorized via one of the two paths described in {transferFrom}.
     * * The sum of `amounts` must not exceed the available limit.
     * * Those from {_periodAt} for the current timepoint.
     *
     * > [!NOTE]
     * > As in {transferFrom}, the limit bounds the total value per period, not the number of calls.
     * > Zero-value entries are allowed and execute an empty call to their `tos[i]`.
     */
    function batchTransferFrom(
        address account,
        bytes calldata key,
        address[] calldata tos,
        uint256[] calldata amounts
    ) public virtual {
        uint256 installation_ = installation(account);
        _checkAccountOrKeySender(account, installation_, key);
        _batchTransferFrom(account, installation_, key, tos, amounts);
    }

    /**
     * @dev Disables ERC-1271 signing by session keys.
     *
     * A spending session key is scoped to authorize {transferFrom} / {batchTransferFrom} user
     * operations on this module. Letting it sign arbitrary ERC-1271 digests (e.g. EIP-2612
     * permits) would let a compromised key bypass the spending bound entirely.
     */
    function isValidSignatureWithSender(
        address /* sender */,
        bytes32 /* hash */,
        bytes calldata /* signature */
    ) public view virtual override(ERC7579SessionKeysValidator) returns (bytes4) {
        return bytes4(0xffffffff);
    }

    /**
     * @dev Validates a user operation. Adds a callData shape gate on top of session-key validation:
     *
     * `userOp.callData` MUST call `IERC7579Execution.execute(mode, executionCalldata)` where:
     *
     * * `mode` is `CALLTYPE_SINGLE` (other call types are rejected).
     * * `executionCalldata` decodes to `(target=address(this), value=0, data)`.
     * * `data` calls {transferFrom} or {batchTransferFrom}.
     * * The `key` parameter inside `data` matches the key in `userOp.signature` (prevents one key's
     *   signature from charging another key's allowance).
     *
     * Returns {ERC4337Utils.SIG_VALIDATION_FAILED} for any shape or key mismatch, otherwise delegates
     * to the parent for cryptographic verification and validity-range packing.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override(ERC7579SessionKeysValidator) returns (uint256) {
        if (!_isAuthorizedCallData(userOp)) return ERC4337Utils.SIG_VALIDATION_FAILED;
        return super._validateUserOp(userOp, userOpHash);
    }

    /**
     * @dev Override of {ERC7579SessionKeys-_addKeys} that disallows registering a key with a past
     * `start` timepoint.
     *
     * The spending bookkeeping in {_spentFor} is indexed by `(keyId, start, period)`. Letting a
     * removed-then-re-registered key pick a past `start` would let it inherit `_spentFor` slots
     * written under a previous validity range, which (combined with a different `renewPeriod`)
     * can collide with previously-used period slots. Strictly incremental `start` values keep
     * each registration's accounting in its own slot space.
     *
     * Requirements:
     *
     * * Each `starts[i]` must be either `0` or `>= clock()`. Reverts with
     *   {ERC7579NativeSpenderInvalidStart} otherwise.
     * * Those from {ERC7579SessionKeys-_addKeys}.
     *
     * > [!TIP]
     * > Pass `starts[i] == 0` to resolve the start to the current timepoint.
     */
    function _addKeys(
        address account,
        uint256 installation_,
        bytes[] calldata keys,
        uint48[] calldata starts,
        uint48[] calldata ends
    ) internal virtual override {
        super._addKeys(account, installation_, keys, starts, ends);
        uint48 currentTimepoint = clock();
        for (uint256 i = 0; i < keys.length; ++i) {
            require(starts[i] == 0 || starts[i] >= currentTimepoint, ERC7579NativeSpenderInvalidStart(starts[i]));
        }
    }

    /**
     * @dev Removes session keys from the calling account.
     *
     * The spending configuration and spending history of each key are indexed by its {_keyId}, so the
     * {keyGeneration} bump in the parent makes them unreachable. Registering the key again starts with no
     * spending configuration and empty spending periods.
     *
     * Emits {ERC7579SessionKeysERC7913KeyUnset} (via the parent) and {ERC7579NativeSpendingConfigUnset}
     * for each key.
     */
    function _removeKeys(address account, uint256 installation_, bytes[] calldata oldKeys) internal virtual override {
        super._removeKeys(account, installation_, oldKeys);
        for (uint256 i = 0; i < oldKeys.length; ++i) {
            emit ERC7579NativeSpendingConfigUnset(account, oldKeys[i]);
        }
    }

    /// @dev Internal version of {installed}.
    function _installed(address account, uint256 installation_) internal view virtual returns (bool) {
        return _keyCount(account, installation_) > 0;
    }

    /// @dev Internal version of {renewPeriod}.
    function _renewPeriod(
        address account,
        uint256 installation_,
        bytes32 keyId
    ) internal view virtual returns (uint256) {
        return _config[installation_][keyId][account].renewPeriod;
    }

    /// @dev Internal version of {limit}.
    function _limit(address account, uint256 installation_, bytes32 keyId) internal view virtual returns (uint256) {
        return _config[installation_][keyId][account].limit;
    }

    /// @dev Internal version of {spent} with explicit `start`.
    function _spent(
        address account,
        uint256 installation_,
        bytes32 keyId,
        uint256 period,
        uint256 start
    ) internal view virtual returns (uint256) {
        return _spentFor[account][installation_][keyId][start][period];
    }

    /// @dev Internal version of {spendingAt} with explicit `start`.
    function _spendingAt(
        address account,
        uint256 installation_,
        bytes32 keyId,
        uint256 period,
        uint256 start
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, installation_, keyId, period, start);
        (bool success, uint256 available_) = Math.trySub(_limit(account, installation_, keyId), spending);
        return (spending, Math.ternary(success, available_, 0));
    }

    /**
     * @dev Internal version of {periodAt} with explicit `installation_`.
     *
     * Requirements:
     *
     * * `timepoint` must be `>=` the key's `from`. Reverts with {ERC7579NativeSpendingConfigNotStarted} otherwise.
     * * The spending config must be set. Reverts with {ERC7579NativeSpendingConfigNotSet} otherwise.
     */
    function _periodAt(
        address account,
        uint256 installation_,
        bytes32 keyId,
        uint48 timepoint
    ) internal view virtual returns (uint256 start, uint256 period) {
        (uint48 from, ) = _validity(account, installation_, keyId);
        (bool ok, uint256 elapsed) = Math.trySub(timepoint, from);
        require(ok, ERC7579NativeSpendingConfigNotStarted(account, keyId, timepoint, from));
        uint256 renew = _renewPeriod(account, installation_, keyId);
        require(renew > 0, ERC7579NativeSpendingConfigNotSet(account, keyId));
        return (from, elapsed / renew);
    }

    /**
     * @dev Authorizes a {transferFrom} / {batchTransferFrom} call.
     *
     * Accepts msg.sender as the account itself (executor flow, validator already verified) or as
     * a 20-byte EOA matching `key` (EOA self-call, validity is checked manually).
     */
    function _checkAccountOrKeySender(
        address account,
        uint256 installation_,
        bytes calldata key
    ) internal view virtual {
        if (msg.sender == account) return;
        require(
            key.length == 20 && msg.sender == address(bytes20(key)) && _isValid(account, installation_, key),
            ERC7579NativeSpenderUnauthorized(msg.sender, key)
        );
    }

    /// @dev Internal version of {transferFrom} without access control.
    function _transferFrom(
        address account,
        uint256 installation_,
        bytes calldata key,
        address to,
        uint256 amount
    ) internal virtual {
        bytes32 kId = _keyId(account, installation_, key);
        (uint256 start, uint256 period) = _periodAt(account, installation_, kId, clock());
        (, uint256 available) = _spendingAt(account, installation_, kId, period, start);
        require(amount <= available, ERC7579NativeInsufficientAvailable(account, key, amount));
        _spentFor[account][installation_][kId][start][period] += amount;

        _execute(
            account,
            bytes32(0),
            Mode.unwrap(
                ERC7579Utils.encodeMode(
                    ERC7579Utils.CALLTYPE_SINGLE,
                    ERC7579Utils.EXECTYPE_DEFAULT,
                    ModeSelector.wrap(0),
                    ModePayload.wrap(0)
                )
            ),
            ERC7579Utils.encodeSingle(to, amount, Calldata.emptyBytes())
        );
    }

    /// @dev Internal version of {batchTransferFrom} without access control.
    function _batchTransferFrom(
        address account,
        uint256 installation_,
        bytes calldata key,
        address[] calldata tos,
        uint256[] calldata amounts
    ) internal virtual {
        require(tos.length == amounts.length, ERC7579NativeSpenderMismatchedBatchLengths(tos.length, amounts.length));
        bytes32 keyId = _keyId(account, installation_, key);
        (uint256 start, uint256 period) = _periodAt(account, installation_, keyId, clock());
        (, uint256 available) = _spendingAt(account, installation_, keyId, period, start);
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }
        require(totalAmount <= available, ERC7579NativeInsufficientAvailable(account, key, totalAmount));
        _spentFor[account][installation_][keyId][start][period] += totalAmount;

        Execution[] memory executions = new Execution[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            executions[i] = Execution({target: tos[i], value: amounts[i], callData: Calldata.emptyBytes()});
        }
        _execute(
            account,
            bytes32(0),
            Mode.unwrap(
                ERC7579Utils.encodeMode(
                    ERC7579Utils.CALLTYPE_BATCH,
                    ERC7579Utils.EXECTYPE_DEFAULT,
                    ModeSelector.wrap(0),
                    ModePayload.wrap(0)
                )
            ),
            ERC7579Utils.encodeBatch(executions)
        );
    }

    /**
     * @dev Internal function to set the spending configuration for a key.
     *
     * Reconfiguration is banned at the {onInstall} level, so this function is only ever invoked
     * with a freshly-registered (or freshly-reinstalled) key whose existing config slot is zero.
     *
     * Requirements:
     *
     * * Renewal periods must be greater than zero. Reverts with {ERC7579NativeSpenderInvalidRenewPeriod} if not.
     * * Limits must be greater than zero. Reverts with {ERC7579NativeSpenderInvalidLimit} if not.
     *
     * Emits a {ERC7579NativeSpendingConfigSet} event.
     */
    function _setConfig(
        address account,
        uint256 installation_,
        bytes calldata key,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        bytes32 keyId = _keyId(account, installation_, key);
        require(newRenewPeriod > 0, ERC7579NativeSpenderInvalidRenewPeriod(newRenewPeriod));
        require(newLimit > 0, ERC7579NativeSpenderInvalidLimit(newLimit));
        _config[installation_][keyId][account].renewPeriod = newRenewPeriod;
        _config[installation_][keyId][account].limit = newLimit;
        emit ERC7579NativeSpendingConfigSet(account, key, newLimit, newRenewPeriod);
    }

    /**
     * @dev Registers keys with validity range AND spending config in one pass.
     *
     * Requirements:
     *
     * * `newKeys.length == limits.length == renewPeriods.length`. Reverts with
     *   {ERC7579NativeSpenderMismatchedInitDataLengths} otherwise.
     * * Those from the parent's {ERC7579SessionKeys-_addKeys} (key registration).
     * * Those from {_setConfig} for the spending config requirements.
     *
     * Emits {ERC7579SessionKeysERC7913KeySet} and {ERC7579NativeSpendingConfigSet} for each key.
     */
    function _addKeysWithConfig(
        address account,
        uint256 installation_,
        bytes[] calldata keys,
        uint48[] calldata starts,
        uint48[] calldata ends,
        uint160[] calldata limits,
        uint48[] calldata renewPeriods
    ) internal virtual {
        require(
            keys.length == limits.length && keys.length == renewPeriods.length,
            ERC7579NativeSpenderMismatchedInitDataLengths(keys.length, limits.length, renewPeriods.length)
        );
        // Parent's _addKeys checks keys/starts/ends length match and emits the key-set event.
        _addKeys(account, installation_, keys, starts, ends);
        for (uint256 i = 0; i < keys.length; ++i) {
            // No need to check if the key is registered, they were just added in the parent's _addKeys.
            _setConfig(account, installation_, keys[i], limits[i], renewPeriods[i]);
        }
    }

    /**
     * @dev Returns whether `userOp.callData` is a permitted call into {transferFrom} or
     * {batchTransferFrom} on this module, and whether its `key` argument matches the one
     * decoded from `userOp.signature`.
     */
    function _isAuthorizedCallData(PackedUserOperation calldata userOp) internal view virtual returns (bool) {
        (bool isSingleAndValid, bytes calldata exec) = _validateSingleExecutionCalldata(userOp.callData);
        if (!isSingleAndValid) return false;
        (bool success, bytes calldata callDataKey) = _validateTransferKey(exec);
        if (!success) return false;
        (, bytes calldata sigKey, ) = _tryDecodeSignature(userOp.signature);
        // _tryDecodeSignature's success is checked down in `super._validateUserOp` -> `_rawERC7579Validation`

        // validity is checked down in `super._validateUserOp`
        return keccak256(sigKey) == keccak256(callDataKey); // Only signing keys can call transferFrom or batchTransferFrom on its behalf
    }

    /**
     * @dev Decodes the outer `IERC7579Execution.execute(SINGLE, executionCalldata)` call.
     *
     * Returns `(false, "")` if the call doesn't match the expected shape.
     */
    function _validateSingleExecutionCalldata(
        bytes calldata callData
    ) internal pure returns (bool isSingleAndValid, bytes calldata exec) {
        // Min length: selector(4) + mode(32) + offset(32) + length(32) = 100 bytes.
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Execution.execute.selector) {
            return (false, Calldata.emptyBytes()); // Invalid
        }

        (CallType callType, , , ) = ERC7579Utils.decodeMode(Mode.wrap(bytes32(callData[4:36])));
        if (CallType.unwrap(callType) != CallType.unwrap(ERC7579Utils.CALLTYPE_SINGLE)) {
            return (false, Calldata.emptyBytes()); // Not single
        }

        unchecked {
            // executionCalldata offset is relative to position after the selector.
            // The length field must be within bounds. Safe subtraction given `callData.length >= 100`.
            uint256 execOffset = uint256(bytes32(callData[36:68]));
            if (execOffset > callData.length - 36) return (false, Calldata.emptyBytes()); // Invalid
            uint256 execLenPos = 4 + execOffset; // Cannot overflow given the check above
            uint256 execStart = execLenPos + 32; // Cannot overflow given the check above
            uint256 execLen = uint256(bytes32(callData[execLenPos:execStart]));
            if (execLen > callData.length - execStart) return (false, Calldata.emptyBytes()); // Invalid

            return (true, callData[execStart:execStart + execLen]);
        }
    }

    /**
     * @dev Verifies the inner single execution targets this module with zero value, calls
     * {transferFrom} or {batchTransferFrom}, and returns the `key` argument extracted from the
     * inner calldata.
     *
     * Returns `(false, "")` if any check fails.
     */
    function _validateTransferKey(
        bytes calldata exec
    ) internal view returns (bool success, bytes calldata callDataKey) {
        // Execute encoded as: abi.encodePacked(target20, value32, innerData).
        if (exec.length < 52) return (false, Calldata.emptyBytes());
        (address target, uint256 value, bytes calldata innerData) = ERC7579Utils.decodeSingle(exec);
        if (target != address(this) || value != 0) return (false, Calldata.emptyBytes());

        // Inner layout: [selector(4) | account(32) | keyOffset(32) | ... | keyLength(32) | key].
        if (innerData.length < 100) return (false, Calldata.emptyBytes()); // 4 + 32 + 32 + 32 = 100
        bytes4 selector = bytes4(innerData[0:4]);
        if (selector != this.transferFrom.selector && selector != this.batchTransferFrom.selector) {
            return (false, Calldata.emptyBytes());
        }

        unchecked {
            // keyOffset is relative to start of args (innerData[4:]).
            // The length field must be within bounds. Safe subtraction given `innerData.length >= 100`.
            uint256 keyOffset = uint256(bytes32(innerData[0x24:0x44]));
            if (keyOffset > innerData.length - 0x24) return (false, Calldata.emptyBytes());
            uint256 keyLenPos = 4 + keyOffset; // Cannot overflow given the check above
            uint256 keyDataStart = keyLenPos + 0x20; // Cannot overflow given the check above
            uint256 keyLen = uint256(bytes32(innerData[keyLenPos:keyDataStart]));
            if (keyLen > innerData.length - keyDataStart) return (false, Calldata.emptyBytes());

            return (true, innerData[keyDataStart:keyDataStart + keyLen]);
        }
    }

    /**
     * @dev Decodes the initialization data for the second install of the module.
     *
     * The `initData` must be ABI-encoded as `abi.encode(bytes[] keys, uint160[] limits, uint48[] renewPeriods)`
     * where each array has the same length.
     *
     * Requirements:
     *
     * * `initData` must be at least 192 bytes (6 × 32 bytes for the 3 ABI offsets and 3 array lengths).
     * * All offsets must point within the `initData` bounds.
     *
     * Reverts with {ERC7579NativeSpenderInvalidInitData} if the encoding is invalid.
     */
    function _decodeKeyConfigsInitData(
        bytes calldata initData
    ) internal pure returns (bytes[] calldata keys, uint160[] calldata limits, uint48[] calldata renewPeriods) {
        // Minimum length:
        // keys offset (32 bytes) + limits offset (32 bytes) + renewPeriods offset (32 bytes) +
        // keys length (32 bytes) + limits length (32 bytes) + renewPeriods length (32 bytes) = 192 bytes
        require(initData.length > 0xbf, ERC7579NativeSpenderInvalidInitData());

        return (
            _decodeKeyConfigsInitDataKeys(initData),
            _decodeKeyConfigsInitDataLimits(initData),
            _decodeKeyConfigsInitDataRenewPeriods(initData)
        );
    }

    function _decodeKeyConfigsInitDataKeys(bytes calldata initData) private pure returns (bytes[] calldata keys) {
        uint256 keysOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 keysDataOffset = keysOffset + 0x20;
        require(keysDataOffset <= initData.length, ERC7579NativeSpenderInvalidInitData());
        uint256 keysLength = uint256(bytes32(initData[keysOffset:keysDataOffset]));
        require(keysDataOffset + keysLength * 0x20 <= initData.length, ERC7579NativeSpenderInvalidInitData());
        assembly ("memory-safe") {
            keys.offset := add(initData.offset, keysDataOffset)
            keys.length := keysLength
        }
        return keys;
    }

    function _decodeKeyConfigsInitDataLimits(bytes calldata initData) private pure returns (uint160[] calldata limits) {
        uint256 limitsOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 limitsDataOffset = limitsOffset + 0x20;
        require(limitsDataOffset <= initData.length, ERC7579NativeSpenderInvalidInitData());
        uint256 limitsLength = uint256(bytes32(initData[limitsOffset:limitsDataOffset]));
        require(limitsDataOffset + limitsLength * 0x20 <= initData.length, ERC7579NativeSpenderInvalidInitData());
        assembly ("memory-safe") {
            limits.offset := add(initData.offset, limitsDataOffset)
            limits.length := limitsLength
        }
        return limits;
    }

    function _decodeKeyConfigsInitDataRenewPeriods(
        bytes calldata initData
    ) private pure returns (uint48[] calldata renewPeriods) {
        uint256 renewPeriodsOffset = uint256(bytes32(initData[0x40:0x60]));
        uint256 renewPeriodsDataOffset = renewPeriodsOffset + 0x20;
        require(renewPeriodsDataOffset <= initData.length, ERC7579NativeSpenderInvalidInitData());
        uint256 renewPeriodsLength = uint256(bytes32(initData[renewPeriodsOffset:renewPeriodsDataOffset]));
        require(
            renewPeriodsDataOffset + renewPeriodsLength * 0x20 <= initData.length,
            ERC7579NativeSpenderInvalidInitData()
        );
        assembly ("memory-safe") {
            renewPeriods.offset := add(initData.offset, renewPeriodsDataOffset)
            renewPeriods.length := renewPeriodsLength
        }
        return renewPeriods;
    }
}
