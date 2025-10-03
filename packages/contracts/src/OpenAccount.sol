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

/**
 * @dev A modular smart account implementation.
 */
abstract contract OpenAccount is
    Initializable,
    Account,
    EIP712,
    AccountERC7579,
    ERC721Holder,
    ERC1155Holder
{
    /**
     * @dev Initializes the account with a validator or executor module.
     *
     * The `moduleTypeId` must be either MODULE_TYPE_VALIDATOR (1) or MODULE_TYPE_EXECUTOR (2).
     * The `module` address and `initData` are passed to the `_installModule` function.
     */
    function initialize(
        uint256 moduleTypeId,
        address module,
        bytes memory initData
    ) public virtual initializer {
        require(
            moduleTypeId == MODULE_TYPE_VALIDATOR ||
                moduleTypeId == MODULE_TYPE_EXECUTOR
        );
        _installModule(moduleTypeId, module, initData);
    }

    /// @inheritdoc AccountERC7579
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override(Account, AccountERC7579) returns (uint256) {
        return super._validateUserOp(userOp, userOpHash);
    }
}
