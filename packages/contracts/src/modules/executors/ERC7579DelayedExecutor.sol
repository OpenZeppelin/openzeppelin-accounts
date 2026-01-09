// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ERC7579Executor} from "./ERC7579Executor.sol";

/**
 * @dev Extension of {ERC7579Executor} that provides time-delayed execution patterns
 * for smart accounts with scheduling and expiration capabilities.
 *
 * This contract provides the basic scheduling functionality through the {_schedule},
 * {_scheduleAt}, and {_cancel} functions. Developers must implement their own public
 * `schedule`, `cancel`, and `execute` functions in derived contracts to define the
 * specific validation and access control logic for each operation.
 *
 * ==== Operation Lifecycle
 *
 * 1. Scheduling: Operations are scheduled via {_schedule} with a specified delay period.
 * The delay period is set during {onInstall} and can be customized via {setDelay}. Each
 * operation enters a `Scheduled` state and must wait for its delay period to elapse.
 *
 * 2. Security Window: During the delay period, operations remain in `Scheduled` state but
 * cannot be executed. Through this period, suspicious operations can be monitored and
 * canceled via {_cancel} if appropriate.
 *
 * 3. Execution & Expiration: Once the delay period elapses, operations transition to `Ready` state.
 * Operations can be executed via {_execute} and have an expiration period after becoming
 * executable. If an operation is not executed within the expiration period, it becomes `Expired`
 * and can't be executed. Expired operations must be rescheduled with a different salt.
 *
 * ==== Delay Management
 *
 * Accounts can set their own delay periods during installation or via {setDelay}.
 * The delay period is enforced even between installs and uninstalls to prevent
 * immediate downgrades. When setting a new delay period, the new delay takes effect
 * after a transition period defined by the current delay or {minSetback}, whichever
 * is longer.
 *
 * TIP: Use {_scheduleAt} to schedule operations at specific points in time. This is
 * useful to pre-schedule operations for non-deployed accounts (e.g. subscriptions).
 *
 * NOTE: Execution is not restricted by default once the operation is ready.
 * See {_execute} for more details.
 *
 * NOTE: Target addresses of an operation may return an arbitrary large amount of data, which
 * may cause the operation to fail due to insufficient gas. Consider that a target could return
 * more data than initially expected (e.g. after being upgraded, or when their return data
 * depends on state), potentially blocking the operation's execution until they expire.
 */
abstract contract ERC7579DelayedExecutor is ERC7579Executor {
    using Time for *;

    struct Schedule {
        // 1 slot = 48 + 32 + 32 + 8 + 8 = 114 bits = 16 bytes
        uint48 scheduledAt; // The time when the operation was scheduled
        uint32 executableAfter; // Time after the operation becomes executable
        uint32 expiresAfter; // Time after the operation expires
        bool executed;
        bool canceled;
    }

    struct ExecutionConfig {
        // 1 slot = 112 + 32 + 8 = 152 bits = 19 bytes
        Time.Delay delay;
        uint32 expiration; // Time after operation is OperationState.Ready to expire
        bool installed;
    }

    enum OperationState {
        Unknown,
        Scheduled,
        Ready,
        Expired,
        Executed,
        Canceled
    }

    /// @dev Emitted when a new operation is scheduled.
    event ERC7579ExecutorOperationScheduled(
        address indexed account,
        bytes32 indexed operationId,
        bytes32 salt,
        bytes32 mode,
        bytes executionCalldata,
        uint48 schedule
    );

    // @dev Throws if the module is already installed on the account.
    error ERC7579DelayedExecutorAlreadyInstalled();

    /// @dev Emitted when a new operation is canceled.
    event ERC7579ExecutorOperationCanceled(address indexed account, bytes32 indexed operationId);

    /// @dev Emitted when the execution delay is updated.
    event ERC7579ExecutorDelayUpdated(address indexed account, uint32 newDelay, uint48 effectTime);

    /// @dev Emitted when the expiration delay is updated.
    event ERC7579ExecutorExpirationUpdated(address indexed account, uint32 newExpiration);

    /**
     * @dev The current state of an operation is not the expected. The `allowedStates` is a bitmap with the
     * bits enabled for each OperationState enum position counting from right to left. See {_encodeStateBitmap}.
     */
    error ERC7579ExecutorUnexpectedOperationState(
        bytes32 operationId,
        OperationState currentState,
        bytes32 allowedStates
    );

    /// @dev The module is not installed on the account.
    error ERC7579ExecutorModuleNotInstalled();

    mapping(address account => ExecutionConfig) private _configs;
    mapping(bytes32 operationId => Schedule) private _schedules;

    /// @dev Current state of an operation.
    function state(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata
    ) public view returns (OperationState) {
        return state(hashOperation(account, salt, mode, executionCalldata));
    }

    /// @dev Same as {state}, but for a specific operation id.
    function state(bytes32 operationId) public view returns (OperationState) {
        if (_schedules[operationId].scheduledAt == 0) return OperationState.Unknown;
        if (_schedules[operationId].canceled) return OperationState.Canceled;
        if (_schedules[operationId].executed) return OperationState.Executed;
        (, uint48 executableAt, uint48 expiresAt) = getSchedule(operationId);
        if (block.timestamp < executableAt) return OperationState.Scheduled;
        if (block.timestamp >= expiresAt) return OperationState.Expired;
        return OperationState.Ready;
    }

    /**
     * @dev Minimum delay after which {setDelay} takes effect.
     * Set as default delay if not provided during {onInstall}.
     */
    function minSetback() public view virtual returns (uint32) {
        return 5 days; // Up to ~136 years
    }

    /// @dev Delay for a specific account.
    function getDelay(
        address account
    ) public view virtual returns (uint32 delay, uint32 pendingDelay, uint48 effectTime) {
        return _configs[account].delay.getFull();
    }

    /// @dev Expiration delay for account operations.
    function getExpiration(address account) public view virtual returns (uint32) {
        return _configs[account].expiration;
    }

    /// @dev Schedule for an operation. Returns default values if not set (i.e. `uint48(0)`, `uint48(0)`, `uint48(0)`).
    function getSchedule(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata
    ) public view virtual returns (uint48 scheduledAt, uint48 executableAt, uint48 expiresAt) {
        return getSchedule(hashOperation(account, salt, mode, executionCalldata));
    }

    /// @dev Same as {getSchedule} but with the operation id.
    function getSchedule(
        bytes32 operationId
    ) public view virtual returns (uint48 scheduledAt, uint48 executableAt, uint48 expiresAt) {
        scheduledAt = _schedules[operationId].scheduledAt;
        executableAt = scheduledAt + _schedules[operationId].executableAfter;
        return (scheduledAt, executableAt, executableAt + _schedules[operationId].expiresAfter);
    }

    /// @dev Returns the operation id.
    function hashOperation(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes memory executionCalldata
    ) public view virtual returns (bytes32) {
        return keccak256(abi.encode(account, salt, mode, executionCalldata));
    }

    /// @dev Default expiration for account operations. Set if not provided during {onInstall}.
    function defaultExpiration() public view virtual returns (uint32) {
        return 60 days;
    }

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * The account calling this function becomes registered with the module.
     *
     * The `initData` must be `abi.encodePacked(uint32(initialDelay), uint32(initialExpiration))`.
     * The delay will be set to the maximum of this value and the minimum delay if provided.
     * Otherwise, the delay will be set to {minSetback} and {defaultExpiration} respectively.
     *
     * Requirements:
     *
     * * The module must not be already installed on the account. Reverts with {ERC7579DelayedExecutorAlreadyInstalled} if not.
     * * `initData` must be empty or decode correctly to `(uint32, uint32)`.
     */
    function onInstall(bytes calldata initData) public virtual {
        require(!_configs[msg.sender].installed, ERC7579DelayedExecutorAlreadyInstalled());
        _configs[msg.sender].installed = true;
        (uint32 initialDelay, uint32 initialExpiration) = _decodeDelayedExecutorInitData(initData);
        (uint32 currentDelay, , ) = getDelay(msg.sender); // An old delay might be still present after uninstallation
        _setDelay(msg.sender, initialDelay, uint32(Math.ternary(currentDelay > 0, minSetback(), 0)));
        _setExpiration(msg.sender, initialExpiration);
    }

    /**
     * @dev Allows an account to update its execution delay (see {getDelay}).
     *
     * The new delay will take effect after a transition period defined by the current delay
     * or {minSetback}, whichever is longer. This prevents immediate security downgrades.
     * Can only be called by the account itself.
     */
    function setDelay(uint32 newDelay) public virtual {
        _setDelay(msg.sender, newDelay, minSetback());
    }

    /// @dev Allows an account to update its execution expiration (see {getExpiration}).
    function setExpiration(uint32 newExpiration) public virtual {
        _setExpiration(msg.sender, newExpiration);
    }

    /**
     * @dev Cleans up the {getDelay} and {getExpiration} values by scheduling them to `0`
     * and respecting the previous delay and expiration values.
     *
     * IMPORTANT: This function does not clean up scheduled operations. This means operations
     * could potentially be re-executed if the module is reinstalled later. This is a deliberate
     * design choice for efficiency, but module implementations may want to override this behavior
     * to clear scheduled operations during uninstallation for their specific use cases.
     *
     * NOTE: Uninstalling the module schedules the delay to reset to `0` after {minSetback}, and
     * immediately removes the expiration. If the module is reinstalled before the delay reset
     * completes, the new delay will be subject to {minSetback} protection to prevent bypassing
     * the minimum security window for delay reductions.
     */
    function onUninstall(bytes calldata) public virtual {
        _configs[msg.sender].installed = false;
        _setDelay(msg.sender, 0, minSetback()); // Avoids immediate downgrades
        _setExpiration(msg.sender, 0);
    }

    /**
     * @dev Internal implementation for setting an account's delay. See {getDelay}.
     *
     * Emits an {ERC7579ExecutorDelayUpdated} event.
     */
    function _setDelay(address account, uint32 newDelay, uint32 minimumSetback) internal virtual {
        uint48 effect;
        (_configs[account].delay, effect) = _configs[account].delay.withUpdate(newDelay, minimumSetback);
        emit ERC7579ExecutorDelayUpdated(account, newDelay, effect);
    }

    /**
     * @dev Internal implementation for setting an account's expiration. See {getExpiration}.
     *
     * Emits an {ERC7579ExecutorExpirationUpdated} event.
     */
    function _setExpiration(address account, uint32 newExpiration) internal virtual {
        // Safe downcast since both arguments are uint32
        _configs[account].expiration = newExpiration;
        emit ERC7579ExecutorExpirationUpdated(account, newExpiration);
    }

    /**
     * @dev Schedules an operation to be executed after the account's delay period (see {getDelay}).
     * Operations are uniquely identified by the combination of `account`, `salt`, `mode`, and `data`.
     * This should be called by derived contracts after performing their custom validation logic.
     *
     * Requirements:
     *
     * * The module must be installed on the account. Reverts with {ERC7579ExecutorModuleNotInstalled} if not.
     *
     * NOTE: This function does not have any access control validation.
     */
    function _schedule(address account, bytes32 salt, bytes32 mode, bytes calldata data) internal virtual {
        require(_configs[account].installed, ERC7579ExecutorModuleNotInstalled());
        (uint32 executableAfter, , ) = getDelay(account);
        _scheduleAt(account, salt, mode, data, Time.timestamp(), executableAfter);
    }

    /**
     * @dev Internal function to schedule an operation at a specific timepoint with a custom delay.
     * The operation starts its security window at `timepoint` and becomes executable after `delay`.
     *
     * Requirements:
     *
     * * The operation must be `Unknown`.
     *
     * Emits an {ERC7579ExecutorOperationScheduled} event.
     *
     * NOTE: This function does not have any access control validation.
     */
    function _scheduleAt(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes calldata executionCalldata,
        uint48 timepoint,
        uint32 delay
    ) internal virtual returns (bytes32) {
        bytes32 id = hashOperation(account, salt, mode, executionCalldata);
        _validateStateBitmap(id, _encodeStateBitmap(OperationState.Unknown));

        _schedules[id].scheduledAt = timepoint;
        _schedules[id].executableAfter = delay;
        _schedules[id].expiresAfter = getExpiration(account);

        emit ERC7579ExecutorOperationScheduled(account, id, salt, mode, executionCalldata, timepoint + delay);
        return id;
    }

    /**
     * @dev See {ERC7579Executor-_execute}.
     *
     * Requirements:
     *
     * * The operation must be `Ready`.
     */
    function _execute(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes memory executionCalldata
    ) internal virtual override returns (bytes[] memory) {
        bytes32 id = hashOperation(account, salt, mode, executionCalldata);
        _validateStateBitmap(id, _encodeStateBitmap(OperationState.Ready));

        _schedules[id].executed = true;

        return super._execute(account, salt, mode, executionCalldata);
    }

    /**
     * @dev Internal function to cancel a scheduled operation.
     * This should be called by derived contracts after performing their custom validation logic.
     *
     * Requirements:
     *
     * * The operation must be `Scheduled` or `Ready`.
     *
     * Canceled operations can't be rescheduled. Emits an {ERC7579ExecutorOperationCanceled} event.
     *
     * NOTE: This function does not have any access control validation.
     */
    function _cancel(address account, bytes32 salt, bytes32 mode, bytes calldata executionCalldata) internal virtual {
        bytes32 id = hashOperation(account, salt, mode, executionCalldata);
        bytes32 allowedStates = _encodeStateBitmap(OperationState.Scheduled) | _encodeStateBitmap(OperationState.Ready);
        _validateStateBitmap(id, allowedStates);

        _schedules[id].canceled = true;

        emit ERC7579ExecutorOperationCanceled(account, id);
    }

    /// @dev Decodes the init data into a delay and expiration.
    function _decodeDelayedExecutorInitData(
        bytes calldata initData
    ) internal virtual returns (uint32 delay, uint32 expiration) {
        return
            initData.length > 7
                ? (uint32(bytes4(initData[:4])), uint32(bytes4(initData[4:8])))
                : (minSetback(), defaultExpiration());
    }

    /**
     * @dev Check that the current state of an operation matches the requirements described by the `allowedStates` bitmap.
     * This bitmap should be built using {_encodeStateBitmap}.
     *
     * If requirements are not met, reverts with a {ERC7579ExecutorUnexpectedOperationState} error.
     *
     * NOTE: Passing a `bytes32(0)` for `allowedStates` will always revert.
     */
    function _validateStateBitmap(bytes32 operationId, bytes32 allowedStates) internal view returns (OperationState) {
        OperationState currentState = state(operationId);
        require(
            _encodeStateBitmap(currentState) & allowedStates != bytes32(0),
            ERC7579ExecutorUnexpectedOperationState(operationId, currentState, allowedStates)
        );
        return currentState;
    }

    /**
     * @dev Encodes a `OperationState` into a `bytes32` representation where each bit enabled corresponds to
     * the underlying position in the `OperationState` enum. For example:
     *
     * ```
     * 0x00...100000
     *   ^^^^^^------ ...
     *        ^------ Canceled
     *         ^----- Executed
     *          ^---- Expired
     *           ^--- Ready
     *            ^-- Scheduled
     *             ^- Unknown
     * ```
     */
    function _encodeStateBitmap(OperationState operationState) internal pure returns (bytes32) {
        return bytes32(1 << uint8(operationState));
    }
}
