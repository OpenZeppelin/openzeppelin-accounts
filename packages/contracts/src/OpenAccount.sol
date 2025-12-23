// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

/**
 * @dev A modular smart account implementation.
 */
abstract contract OpenAccount is Initializable, Account, EIP712, AccountERC7579, ERC721Holder, ERC1155Holder {
    /// @dev Thrown when the length of the module type ids, modules, and init datas do not match during initialization.
    error OpenAccountModuleTypeIdsLengthMismatch();

    /// @dev Thrown when the account is initialized without a validator or executor module.
    error OpenAccountNoValidatorOrExecutor();

    /**
     * @dev Initializes the account with a validator or executor module.
     *
     * It receives an array of `moduleTypeIds`, `modules`, and `initDatas` that are used
     * to install modules during initialization. It also receives a `mode` and `executionCalldata`
     * that are used to execute the account, these can be used to configure the account.
     *
     * Set the `configCalldata` to `bytes("")` to skip the configuration call.
     */
    function initialize(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        Mode configMode,
        bytes calldata configCalldata
    ) public virtual initializer {
        require(
            moduleTypeIds.length == modules.length && modules.length == initDatas.length,
            OpenAccountModuleTypeIdsLengthMismatch()
        );
        bool hasValidatorOrExecutor;
        for (uint256 i = 0; i < moduleTypeIds.length; i++) {
            _installModule(moduleTypeIds[i], modules[i], initDatas[i]);
            hasValidatorOrExecutor =
                hasValidatorOrExecutor ||
                moduleTypeIds[i] == MODULE_TYPE_VALIDATOR ||
                moduleTypeIds[i] == MODULE_TYPE_EXECUTOR;
        }
        require(hasValidatorOrExecutor, OpenAccountNoValidatorOrExecutor());
        if (configCalldata.length > 0) {
            _execute(configMode, configCalldata);
        }
    }

    /// @inheritdoc AccountERC7579
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal virtual override(Account, AccountERC7579) returns (uint256) {
        return super._validateUserOp(userOp, userOpHash, signature);
    }
}
