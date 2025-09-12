// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC7739} from "@openzeppelin/contracts/utils/cryptography/signers/draft-ERC7739.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

contract OpenAccount is
    Initializable,
    Account,
    EIP712,
    ERC7739,
    AccountERC7579,
    ERC721Holder,
    ERC1155Holder
{
    constructor() EIP712("OpenAccount", "1") {}

    function initialize(
        uint256 moduleTypeId,
        address module,
        bytes memory initData
    ) public initializer {
        require(
            moduleTypeId == MODULE_TYPE_VALIDATOR ||
                moduleTypeId == MODULE_TYPE_EXECUTOR
        );
        _installModule(moduleTypeId, module, initData);
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override(AccountERC7579, ERC7739) returns (bytes4) {
        // ERC-7739 can return the ERC-1271 magic value, 0xffffffff (invalid) or 0x77390001 (detection).
        // If the returned value is 0xffffffff, fallback to ERC-7579 validation.
        bytes4 erc7739magic = ERC7739.isValidSignature(hash, signature);
        return
            erc7739magic == bytes4(0xffffffff)
                ? AccountERC7579.isValidSignature(hash, signature)
                : erc7739magic;
    }

    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override(Account, AccountERC7579) returns (uint256) {
        return super._validateUserOp(userOp, userOpHash);
    }
}
