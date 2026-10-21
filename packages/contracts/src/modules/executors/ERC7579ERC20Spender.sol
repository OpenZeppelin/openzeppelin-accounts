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
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC7579SessionKeys} from "../ERC7579SessionKeys.sol";
import {ERC7579Validator} from "../validators/ERC7579Validator.sol";
import {ERC7579SessionKeysValidator} from "../validators/ERC7579SessionKeysValidator.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

/**
 * @dev Extension of {ERC7579SessionKeysValidator} that provides ERC20 token spending limits
 * granted to session keys with automatic renewal periods for ERC-7579 smart accounts.
 *
 * This module allows accounts to configure spending allowances for external spenders,
 * enabling use cases like subscription services, recurring payments, or delegated spending
 * with predefined limits.
 *
 * Same dual-role design as {ERC7579NativeSpender}: a session key authorizes a UserOp whose
 * `callData` targets {transferFrom} or {batchTransferFrom} on this module, and the module
 * spends through `executeFromExecutor` on the account.
 *
 * Each `(session key, ERC-20 token)` pair carries its own `(limit, renewPeriod)` spending
 * policy. A single key can have policies for multiple tokens by listing it multiple times
 * (with different tokens) in the executor install initData.
 *
 * > [!NOTE]
 * > The module should be installed under both module types, in this order:
 * >
 * > 1. **Validator install (first)**: `initData` is `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)`.
 * >    Registers session keys with their validity ranges through {ERC7579SessionKeys-_addKeys}.
 * >    At least one key must be registered, otherwise the install reverts.
 * > 2. **Executor install (second)**: `initData` is
 * >    `abi.encode(bytes[] keys, address[] tokens, uint160[] limits, uint48[] renewPeriods)`.
 * >    Writes a spending policy for each `(keys[i], tokens[i])` row. Each row's `keys[i]` MUST
 * >    already be registered. Keys MAY repeat across rows to configure multiple tokens for the
 * >    same key. The `keys` array MUST be non-empty.
 * >
 * > Once any `(key, token)` config is written, the module is "installed" and further `onInstall`
 * > calls revert with {ERC7579ERC20SpenderAlreadyInstalled}. To change the spending policy, the
 * > account must uninstall and reinstall (which bumps the installation nonce and resets state).
 *
 * > [!IMPORTANT]
 * > This module deliberately disables ERC-1271 signing
 * > ({isValidSignatureWithSender} always returns `0xffffffff`) so a spending session key cannot be
 * > repurposed to authorize arbitrary off-chain messages on behalf of the account.
 *
 * > [!NOTE]
 * > Removing a session key via {ERC7579SessionKeys-removeKeys} clears its validity range but
 * > does NOT clear the `(key, token)` spending configs. If the same key bytes are re-registered via
 * > {ERC7579SessionKeys-addKeys} (without `addKeysWithConfig`), the previously-stored configs become
 * > active again. To re-register a key with a fresh policy, call {addKeysWithConfig} instead.
 *
 * > [!TIP]
 * > Set `starts[i] == 0` to schedule a key from the current timepoint.
 *
 * > [!TIP]
 * > Set `renewPeriod == type(uint48).max` to effectively disable the renewal period.
 */
contract ERC7579ERC20Spender is ERC7579SessionKeysValidator, ERC7579Executor {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev The account already has a spending configuration installed.
    error ERC7579ERC20SpenderAlreadyInstalled();

    /// @dev The requested `amount` exceeds the available spending limit for `(key, token)`.
    error ERC7579ERC20InsufficientAvailable(address account, bytes key, address token, uint256 amount);

    /// @dev The provided `initData` is invalid or malformed.
    error ERC7579ERC20SpenderInvalidInitData();

    /// @dev The spending config is not set for `(keyId, token)`.
    error ERC7579ERC20SpendingConfigNotSet(address account, bytes32 keyId, address token);

    /// @dev The arrays in the executor `initData` have mismatched lengths.
    error ERC7579ERC20SpenderMismatchedInitDataLengths(
        uint256 keys,
        uint256 tokens,
        uint256 limits,
        uint256 renewPeriods
    );

    /// @dev The first install registered zero session keys, or the second install's `keys` array is empty.
    error ERC7579ERC20SpenderEmptyKeys();

    /// @dev The `tos` and `amounts` arrays have mismatched lengths in batch transfer.
    error ERC7579ERC20SpenderMismatchedBatchLengths(uint256 tos, uint256 amounts);

    /// @dev The `renewPeriod` is invalid (must be greater than zero).
    error ERC7579ERC20SpenderInvalidRenewPeriod(uint256 renewPeriod);

    /// @dev The `limit` is invalid (must be greater than zero).
    error ERC7579ERC20SpenderInvalidLimit(uint256 limit);

    /// @dev The `token` address is not a contract.
    error ERC7579ERC20SpenderInvalidToken(address token);

    /// @dev The spending config has not started yet for `(keyId, token)` at `timepoint`.
    error ERC7579ERC20SpendingConfigNotStarted(
        address account,
        bytes32 keyId,
        address token,
        uint256 timepoint,
        uint256 start
    );

    /// @dev The caller is not authorized to spend on behalf of `key`.
    error ERC7579ERC20SpenderUnauthorized(address caller, bytes key);

    /// @dev The `start` time is invalid (cannot reuse a past start time).
    error ERC7579ERC20SpenderInvalidStart(uint256 start);

    /// @dev The ERC20 `transfer` call on `token` returned `false`.
    error ERC7579ERC20SpenderFailedTransfer(address token);

    /// @dev Emitted when the spending configuration is set or updated for a `(key, token)` pair.
    event ERC7579ERC20SpendingConfigSet(
        address indexed account,
        bytes indexed key,
        address indexed token,
        uint256 limit,
        uint256 renewPeriod
    );

    /**
     * @dev Spending configuration for a specific `(account, key, token)` tuple.
     *
     * The start of the spending periods is the session key's `from` timepoint, accessible via
     * {ERC7579SessionKeys-validity}.
     */
    struct SpendingConfig {
        uint48 renewPeriod; // Up to 8,925,512.96 years (2**48 / 60 / 60 / 24 / 365) from January 1, 1970, 00:00:00 UTC
        uint160 limit; // Up to 1.4615016373e30 with 18 decimals (2**160 / 1e18)
    }

    mapping(address account => mapping(uint256 installation => mapping(bytes32 keyId => mapping(address token => SpendingConfig))))
        private _config;
    mapping(address account => mapping(uint256 installation => mapping(bytes32 keyId => mapping(address token => mapping(uint256 start => mapping(uint256 period => uint256))))))
        private _spentFor;
    mapping(address account => mapping(uint256 installation => EnumerableSet.AddressSet)) private _tokens;

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

    /// @dev Returns the number of tokens with at least one spending config for `account`.
    function tokensCount(address account) public view virtual returns (uint256) {
        return _tokensCount(account, installation(account));
    }

    /**
     * @dev Returns a paginated slice of tokens with at least one spending config for `account`.
     *
     * > [!WARNING]
     * > Depending on `startIdx` and `endIdx`, this operation can copy a large amount of
     * > data to memory. Designed for view accessors queried without gas fees.
     */
    function tokens(address account, uint256 startIdx, uint256 endIdx) public view virtual returns (address[] memory) {
        return _tokens[account][installation(account)].values(startIdx, endIdx);
    }

    /// @dev Returns the renewal period for the `(key, token)` config on `account`.
    function renewPeriod(address account, bytes calldata key, address token) public view virtual returns (uint256) {
        return _renewPeriod(account, installation(account), _keyId(key), token);
    }

    /// @dev Returns the spending limit per period for the `(key, token)` config on `account`.
    function limit(address account, bytes calldata key, address token) public view virtual returns (uint256) {
        return _limit(account, installation(account), _keyId(key), token);
    }

    /// @dev Returns the amount spent by `key` for `token` during `period`, anchored at the key's `from`.
    function spent(
        address account,
        bytes calldata key,
        address token,
        uint256 period
    ) public view virtual returns (uint256) {
        uint256 installation_ = installation(account);
        bytes32 keyId = _keyId(key);
        (uint48 from, ) = _validity(account, installation_, keyId);
        return _spent(account, installation_, keyId, token, period, from);
    }

    /// @dev Same as {spent} but reads from an explicit `start` timepoint.
    function spent(
        address account,
        bytes calldata key,
        address token,
        uint256 period,
        uint256 start
    ) public view virtual returns (uint256) {
        return _spent(account, installation(account), _keyId(key), token, period, start);
    }

    /// @dev Returns `(spending, available)` for `(key, token)` at `period`.
    function spendingAt(
        address account,
        bytes calldata key,
        address token,
        uint256 period
    ) public view virtual returns (uint256 spending, uint256 available) {
        uint256 installation_ = installation(account);
        bytes32 keyId = _keyId(key);
        (uint48 from, ) = _validity(account, installation_, keyId);
        return _spendingAt(account, installation_, keyId, token, period, from);
    }

    /**
     * @dev Returns `(start, period)` for `(key, token)` at `timepoint`.
     *
     * Requirements:
     *
     * * `timepoint` must be `>=` the key's `from`. Reverts with {ERC7579ERC20SpendingConfigNotStarted} otherwise.
     * * The spending config must be set. Reverts with {ERC7579ERC20SpendingConfigNotSet} otherwise.
     */
    function periodAt(
        address account,
        bytes calldata key,
        address token,
        uint48 timepoint
    ) public view virtual returns (uint256 start, uint256 period) {
        return _periodAt(account, installation(account), _keyId(key), token, timepoint);
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     *
     * This module is installed under BOTH module types and `onInstall` is called twice. The
     * shape of `initData` differs between the two calls:
     *
     * * **First call** (validator install, `installed(msg.sender) == false`):
     *   `abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)`.
     * * **Second call** (executor install, `installed(msg.sender) == true`):
     *   `abi.encode(bytes[] keys, address[] tokens, uint160[] limits, uint48[] renewPeriods)`.
     *
     * First call requirements:
     *
     * * The `keys` array must be non-empty. Reverts with {ERC7579ERC20SpenderEmptyKeys} otherwise.
     * * Those from the parent's {ERC7579SessionKeys-onInstall} (key registration).
     *
     * Second call requirements:
     *
     * * No `(key, token)` config has been written yet under this installation. Reverts with
     *   {ERC7579ERC20SpenderAlreadyInstalled} otherwise.
     * * `initData.length` must be at least 256 bytes (4 ABI offsets + 4 array lengths). Reverts
     *   with {ERC7579ERC20SpenderInvalidInitData} otherwise. All offsets must point within bounds.
     * * All four arrays must have equal length.
     * * The `keys` array must be non-empty.
     * * Each `keys[i]` must already be registered. Reverts with {ERC7579SessionKeysNonexistentKey} otherwise.
     * * Those from {_setConfig} for the spending config requirements.
     *
     * Emits {ERC7579SessionKeysERC7913KeySet} on the first call and {ERC7579ERC20SpendingConfigSet}
     * for each row on the second call.
     *
     * > [!TIP]
     * > Each start will be set to the current timepoint if it's 0.
     */
    function onInstall(bytes calldata initData) public virtual override(ERC7579SessionKeys, IERC7579Module) {
        if (!installed(msg.sender)) {
            super.onInstall(initData);
            require(installed(msg.sender), ERC7579ERC20SpenderEmptyKeys());
        } else {
            uint256 installation_ = installation(msg.sender);
            // After the second install, there must be at least one token with a spending config.
            require(_tokensCount(msg.sender, installation_) == 0, ERC7579ERC20SpenderAlreadyInstalled());
            // Minimum length: 4 offsets + 4 lengths = 256 bytes (0x100)
            require(initData.length > 0xff, ERC7579ERC20SpenderInvalidInitData());
            bytes[] calldata keys = _decodeKeyConfigsInitDataKeys(initData);
            address[] calldata tokens_ = _decodeKeyConfigsInitDataTokens(initData);
            uint160[] calldata limits = _decodeKeyConfigsInitDataLimits(initData);
            uint48[] calldata renewPeriods = _decodeKeyConfigsInitDataRenewPeriods(initData);
            require(
                keys.length == tokens_.length && keys.length == limits.length && keys.length == renewPeriods.length,
                ERC7579ERC20SpenderMismatchedInitDataLengths(
                    keys.length,
                    tokens_.length,
                    limits.length,
                    renewPeriods.length
                )
            );
            require(keys.length > 0, ERC7579ERC20SpenderEmptyKeys());
            for (uint256 i = 0; i < keys.length; ++i) {
                require(_isKey(msg.sender, installation_, keys[i]), ERC7579SessionKeysNonexistentKey(keys[i]));
                _setConfig(msg.sender, installation_, keys[i], tokens_[i], limits[i], renewPeriods[i]);
            }
        }
    }

    /**
     * @dev Adds new session keys with one spending configuration each, in a single call. Can only
     * be called by the account itself.
     *
     * Requirements:
     *
     * * All six arrays must have equal length.
     * * Those from {ERC7579SessionKeys-_addKeys} (and the {_addKeys} override's past-start ban).
     * * Those from {_setConfig} for each row.
     *
     * > [!NOTE]
     * > This helper only supports one `(token, limit, renewPeriod)` per new key. To configure
     * > multiple tokens for a single key, list it multiple times in the executor install initData.
     */
    function addKeysWithConfig(
        bytes[] calldata newKeys,
        uint48[] calldata starts,
        uint48[] calldata ends,
        address[] calldata tokens_,
        uint160[] calldata limits,
        uint48[] calldata renewPeriods
    ) public virtual {
        require(
            newKeys.length == tokens_.length &&
                newKeys.length == limits.length &&
                newKeys.length == renewPeriods.length,
            ERC7579ERC20SpenderMismatchedInitDataLengths(
                newKeys.length,
                tokens_.length,
                limits.length,
                renewPeriods.length
            )
        );
        uint256 installation_ = installation(msg.sender);
        // Parent's _addKeys checks keys/starts/ends length match and emits the key-set event.
        _addKeys(msg.sender, installation_, newKeys, starts, ends);
        for (uint256 i = 0; i < newKeys.length; ++i) {
            bytes calldata key = newKeys[i];
            // No need to check if the key is registered, they were just added in the parent's _addKeys.
            _setConfig(msg.sender, installation_, key, tokens_[i], limits[i], renewPeriods[i]);
        }
    }

    /**
     * @dev Transfers `token` from `account` to `to` on behalf of `key`.
     *
     * Tracks the spending limit for the `(key, token)` pair on `account`, updates the spent
     * amount for the current period, and executes the transfer through the account's
     * {IERC7579Execution-executeFromExecutor}.
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
     *   {ERC7579ERC20SpenderUnauthorized} otherwise.
     * * `amount` must not exceed the available limit for the current period. Reverts with
     *   {ERC7579ERC20InsufficientAvailable} otherwise.
     * * The token's `transfer` must return `true` or have no return value. Reverts with
     *   {ERC7579ERC20SpenderFailedTransfer} otherwise.
     * * Those from {_periodAt} for the current timepoint.
     */
    function transferFrom(
        address account,
        bytes calldata key,
        address token,
        address to,
        uint256 amount
    ) public virtual {
        uint256 installation_ = installation(account);
        _checkAccountOrKeySender(account, installation_, key);
        _transferFrom(account, installation_, key, token, to, amount);
    }

    /**
     * @dev Transfers `token` from `account` to multiple recipients in a single batch.
     *
     * Same authorization paths as {transferFrom}. The available limit check is performed once
     * against the total of `amounts`.
     *
     * Requirements:
     *
     * * `tos.length == amounts.length`. Reverts with {ERC7579ERC20SpenderMismatchedBatchLengths} otherwise.
     * * The caller is authorized via one of the two paths described in {transferFrom}.
     * * The sum of `amounts` must not exceed the available limit.
     * * Each ERC20 `transfer` must succeed (return value handled identically to {transferFrom}).
     */
    function batchTransferFrom(
        address account,
        bytes calldata key,
        address token,
        address[] calldata tos,
        uint256[] calldata amounts
    ) public virtual {
        uint256 installation_ = installation(account);
        _checkAccountOrKeySender(account, installation_, key);
        _batchTransferFrom(account, installation_, key, token, tos, amounts);
    }

    /**
     * @dev Disables ERC-1271 signing by session keys. See {ERC7579NativeSpender-isValidSignatureWithSender}
     * for rationale.
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
     * * `mode` is `CALLTYPE_SINGLE`.
     * * `executionCalldata` decodes to `(target=address(this), value=0, data)`.
     * * `data` calls {transferFrom} or {batchTransferFrom}.
     * * The `key` parameter inside `data` matches the key in `userOp.signature`.
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
     * `start` timepoint. See {ERC7579NativeSpender-_addKeys} for the full rationale.
     *
     * Requirements:
     *
     * * Each `starts[i]` must be either `0` or `>= clock()`. Reverts with
     *   {ERC7579ERC20SpenderInvalidStart} otherwise.
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
            require(starts[i] == 0 || starts[i] >= currentTimepoint, ERC7579ERC20SpenderInvalidStart(starts[i]));
        }
    }

    /// @dev Internal version of {installed}.
    function _installed(address account, uint256 installation_) internal view virtual returns (bool) {
        return _keyCount(account, installation_) > 0;
    }

    /// @dev Internal version of {tokensCount}.
    function _tokensCount(address account, uint256 installation_) internal view virtual returns (uint256) {
        return _tokens[account][installation_].length();
    }

    /// @dev Internal version of {renewPeriod}.
    function _renewPeriod(
        address account,
        uint256 installation_,
        bytes32 keyId,
        address token
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][keyId][token].renewPeriod;
    }

    /// @dev Internal version of {limit}.
    function _limit(
        address account,
        uint256 installation_,
        bytes32 keyId,
        address token
    ) internal view virtual returns (uint256) {
        return _config[account][installation_][keyId][token].limit;
    }

    /// @dev Internal version of {spent} with explicit `start`.
    function _spent(
        address account,
        uint256 installation_,
        bytes32 keyId,
        address token,
        uint256 period,
        uint256 start
    ) internal view virtual returns (uint256) {
        return _spentFor[account][installation_][keyId][token][start][period];
    }

    /// @dev Internal version of {spendingAt} with explicit `start`.
    function _spendingAt(
        address account,
        uint256 installation_,
        bytes32 keyId,
        address token,
        uint256 period,
        uint256 start
    ) internal view virtual returns (uint256 spending, uint256 available) {
        spending = _spent(account, installation_, keyId, token, period, start);
        (bool success, uint256 available_) = Math.trySub(_limit(account, installation_, keyId, token), spending);
        return (spending, Math.ternary(success, available_, 0));
    }

    /**
     * @dev Internal version of {periodAt} with explicit `installation_`.
     *
     * Requirements:
     *
     * * `timepoint` must be `>=` the key's `from`. Reverts with {ERC7579ERC20SpendingConfigNotStarted} otherwise.
     * * The spending config must be set. Reverts with {ERC7579ERC20SpendingConfigNotSet} otherwise.
     */
    function _periodAt(
        address account,
        uint256 installation_,
        bytes32 keyId,
        address token,
        uint48 timepoint
    ) internal view virtual returns (uint256 start, uint256 period) {
        (uint48 from, ) = _validity(account, installation_, keyId);
        (bool ok, uint256 elapsed) = Math.trySub(timepoint, from);
        require(ok, ERC7579ERC20SpendingConfigNotStarted(account, keyId, token, timepoint, from));
        uint256 renew = _renewPeriod(account, installation_, keyId, token);
        require(renew > 0, ERC7579ERC20SpendingConfigNotSet(account, keyId, token));
        return (from, elapsed / renew);
    }

    /**
     * @dev Authorizes a {transferFrom} / {batchTransferFrom} call.
     *
     * Accepts `msg.sender` as the account itself (executor flow, validator already verified) or as
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
            ERC7579ERC20SpenderUnauthorized(msg.sender, key)
        );
    }

    /// @dev Internal version of {transferFrom} without access control.
    function _transferFrom(
        address account,
        uint256 installation_,
        bytes calldata key,
        address token,
        address to,
        uint256 amount
    ) internal virtual {
        bytes32 keyId = _keyId(key);
        (uint256 start, uint256 period) = _periodAt(account, installation_, keyId, token, clock());
        (, uint256 available) = _spendingAt(account, installation_, keyId, token, period, start);
        require(amount <= available, ERC7579ERC20InsufficientAvailable(account, key, token, amount));
        _spentFor[account][installation_][keyId][token][start][period] += amount;

        bytes[] memory returndatas = _execute(
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
        uint256 installation_,
        bytes calldata key,
        address token,
        address[] calldata tos,
        uint256[] calldata amounts
    ) internal virtual {
        require(tos.length == amounts.length, ERC7579ERC20SpenderMismatchedBatchLengths(tos.length, amounts.length));

        uint256 totalAmount;
        for (uint256 i = 0; i < amounts.length; ++i) {
            totalAmount += amounts[i];
        }

        bytes32 keyId = _keyId(key);
        (uint256 start, uint256 period) = _periodAt(account, installation_, keyId, token, clock());
        {
            // Avoid stack too deep error
            (, uint256 available) = _spendingAt(account, installation_, keyId, token, period, start);
            require(totalAmount <= available, ERC7579ERC20InsufficientAvailable(account, key, token, totalAmount));
        }
        _spentFor[account][installation_][keyId][token][start][period] += totalAmount;

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
        for (uint256 i = 0; i < returndatas.length; ++i) {
            bytes memory returndata = returndatas[i];
            bool standardReturn;
            // Accept empty returndata (non-standard ERC20 with no return value) or an explicit true.
            assembly ("memory-safe") {
                standardReturn := or(iszero(mload(returndata)), eq(mload(add(returndata, 0x20)), 1))
            }
            require(standardReturn, ERC7579ERC20SpenderFailedTransfer(token));
        }
    }

    /**
     * @dev Writes a spending config for `(keyId, token)` and adds the token to the per-installation
     * token set.
     *
     * Requirements:
     *
     * * `newRenewPeriod > 0`. Reverts with {ERC7579ERC20SpenderInvalidRenewPeriod} otherwise.
     * * `newLimit > 0`. Reverts with {ERC7579ERC20SpenderInvalidLimit} otherwise.
     * * `token` must be a contract. Reverts with {ERC7579ERC20SpenderInvalidToken} otherwise.
     *
     * Emits {ERC7579ERC20SpendingConfigSet}.
     */
    function _setConfig(
        address account,
        uint256 installation_,
        bytes calldata key,
        address token,
        uint160 newLimit,
        uint48 newRenewPeriod
    ) internal virtual {
        bytes32 keyId = _keyId(key);
        require(newRenewPeriod > 0, ERC7579ERC20SpenderInvalidRenewPeriod(newRenewPeriod));
        require(newLimit > 0, ERC7579ERC20SpenderInvalidLimit(newLimit));
        require(token.code.length > 0, ERC7579ERC20SpenderInvalidToken(token));
        _config[account][installation_][keyId][token].renewPeriod = newRenewPeriod;
        _config[account][installation_][keyId][token].limit = newLimit;
        _tokens[account][installation_].add(token);
        emit ERC7579ERC20SpendingConfigSet(account, key, token, newLimit, newRenewPeriod);
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
        return _keyId(sigKey) == _keyId(callDataKey);
    }

    /// @dev See {ERC7579NativeSpender-_validateSingleExecutionCalldata}.
    function _validateSingleExecutionCalldata(
        bytes calldata callData
    ) internal pure returns (bool isSingleAndValid, bytes calldata exec) {
        if (callData.length < 100 || bytes4(callData[0:4]) != IERC7579Execution.execute.selector) {
            return (false, Calldata.emptyBytes());
        }
        (CallType callType, , , ) = ERC7579Utils.decodeMode(Mode.wrap(bytes32(callData[4:36])));
        if (CallType.unwrap(callType) != CallType.unwrap(ERC7579Utils.CALLTYPE_SINGLE)) {
            return (false, Calldata.emptyBytes());
        }
        uint256 execLenPos = 4 + uint256(bytes32(callData[36:68]));
        if (execLenPos + 32 > callData.length) return (false, Calldata.emptyBytes());
        uint256 execLen = uint256(bytes32(callData[execLenPos:execLenPos + 32]));
        uint256 execStart = execLenPos + 32;
        if (execStart + execLen > callData.length) return (false, Calldata.emptyBytes());
        return (true, callData[execStart:execStart + execLen]);
    }

    /**
     * @dev See {ERC7579NativeSpender-_validateTransferKey}. The key argument is the second
     * parameter of both {transferFrom} and {batchTransferFrom}, so the offset slot lies at a
     * fixed position regardless of which selector is used.
     */
    function _validateTransferKey(
        bytes calldata exec
    ) internal view returns (bool success, bytes calldata callDataKey) {
        if (exec.length < 52) return (false, Calldata.emptyBytes());
        (address target, uint256 value, bytes calldata innerData) = ERC7579Utils.decodeSingle(exec);
        if (target != address(this) || value != 0) return (false, Calldata.emptyBytes());

        if (innerData.length < 100) return (false, Calldata.emptyBytes());
        bytes4 selector = bytes4(innerData[0:4]);
        if (selector != this.transferFrom.selector && selector != this.batchTransferFrom.selector) {
            return (false, Calldata.emptyBytes());
        }

        uint256 keyLenPos = 4 + uint256(bytes32(innerData[0x24:0x44]));
        if (keyLenPos + 32 > innerData.length) return (false, Calldata.emptyBytes());
        uint256 keyLen = uint256(bytes32(innerData[keyLenPos:keyLenPos + 0x20]));
        uint256 keyDataStart = keyLenPos + 0x20;
        if (keyDataStart + keyLen > innerData.length) return (false, Calldata.emptyBytes());

        return (true, innerData[keyDataStart:keyDataStart + keyLen]);
    }

    function _decodeKeyConfigsInitDataKeys(bytes calldata initData) private pure returns (bytes[] calldata keys) {
        uint256 keysOffset = uint256(bytes32(initData[0x00:0x20]));
        uint256 keysDataOffset = keysOffset + 0x20;
        require(keysDataOffset <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        uint256 keysLength = uint256(bytes32(initData[keysOffset:keysDataOffset]));
        require(keysDataOffset + keysLength * 0x20 <= initData.length, ERC7579ERC20SpenderInvalidInitData());
        assembly ("memory-safe") {
            keys.offset := add(initData.offset, keysDataOffset)
            keys.length := keysLength
        }
        return keys;
    }

    function _decodeKeyConfigsInitDataTokens(
        bytes calldata initData
    ) private pure returns (address[] calldata tokens_) {
        uint256 tokensOffset = uint256(bytes32(initData[0x20:0x40]));
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

    function _decodeKeyConfigsInitDataLimits(bytes calldata initData) private pure returns (uint160[] calldata limits) {
        uint256 limitsOffset = uint256(bytes32(initData[0x40:0x60]));
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

    function _decodeKeyConfigsInitDataRenewPeriods(
        bytes calldata initData
    ) private pure returns (uint48[] calldata renewPeriods) {
        uint256 renewPeriodsOffset = uint256(bytes32(initData[0x60:0x80]));
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
