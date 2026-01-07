// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    IERC7579Execution
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/**
 * @dev Abstract executor module for ERC-7579 accounts.
 *
 * This contract provides the base execution functionality for ERC-7579 accounts.
 * Developers must implement the {onInstall} and {onUninstall} functions, as well as
 * wrap {_execute} in a custom external function in derived contracts to define the
 * specific validation and access control logic.
 *
 * Example implementation:
 *
 * ```solidity
 * contract MyExecutor is ERC7579Executor {
 *     function execute(
 *         address account,
 *         bytes32 salt,
 *         bytes32 mode,
 *         bytes calldata data
 *     ) public virtual returns (bytes[] memory) {
 *         // Implement your validation logic here
 *         // e.g., signature verification, access control, time delays, etc.
 *
 *         // Then call the internal _execute function
 *         return _execute(account, salt, mode, data);
 *     }
 * }
 * ```
 *
 * TIP: For a more advanced implementation with time-delayed execution patterns and
 * security features, see {ERC7579DelayedExecutor}.
 */
abstract contract ERC7579Executor is IERC7579Module {
    /// @dev Emitted when an operation is executed.
    event ERC7579ExecutorOperationExecuted(
        address indexed account,
        bytes32 salt,
        bytes32 mode,
        bytes executionCalldata
    );

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) public pure virtual returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @dev Internal function to execute an operation through the account's executor interface.
     *
     * Emits {ERC7579ExecutorOperationExecuted} event.
     *
     * NOTE: Target addresses included in the `executionCalldata` may return a large amount of data,
     * which may cause the operation to fail due to insufficient gas given `executeFromExecutor` copies
     * all return datas to memory.
     *
     * Requirements:
     *
     * * The `account` must implement the {IERC7579Execution-executeFromExecutor} function.
     *
     * NOTE: This function does not have any access control validation.
     */
    function _execute(
        address account,
        bytes32 salt,
        bytes32 mode,
        bytes memory executionCalldata
    ) internal virtual returns (bytes[] memory) {
        emit ERC7579ExecutorOperationExecuted(account, salt, mode, executionCalldata);
        return IERC7579Execution(account).executeFromExecutor(mode, executionCalldata);
    }
}
