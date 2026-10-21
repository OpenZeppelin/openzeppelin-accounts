// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AccountERC7579Upgradeable} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ERC8043Utils} from "../utils/ERC8043Utils.sol";

/**
 * @dev Extension of {AccountERC7579Upgradeable} that implements atomic module installation and usage
 * through _init mode_ following [ERC-8043](https://eip.tools/eip/8043).
 *
 * This extension allows installing and using one or more modules within the same user operation.
 * Init mode is triggered when `userOp.initCode` starts with the 4-byte magic value `0x80438043`.
 * The remaining bytes of `initCode` carry the ABI-encoded module installation payload and an
 * EIP-712 installation signature from the account owner.
 *
 * Because the {ERC-4337} EntryPoint v0.9 silently ignores `initCode` for already-deployed accounts,
 * and because `initCode` is included in the `userOpHash`, the module installation parameters are
 * both inert at the EntryPoint level and cryptographically committed to by the user operation signature.
 *
 * This pattern is particularly useful for session keys and other modules that need to be
 * installed and immediately used, reducing user operation count from N+1 to 1.
 *
 * > [!NOTE]
 * > Requires EntryPoint v0.9 or later.
 */
abstract contract AccountERC8043Upgradeable is Initializable, Account, EIP712, AccountERC7579Upgradeable {
    /**
     * @dev Validates a user operation, checking for the init mode magic value in `initCode`.
     *
     * If `userOp.initCode` starts with `INIT_MODE_MAGIC_VALUE`, enters init mode:
     *
     * 1. Decodes module installation data from `userOp.initCode[4:]`
     * 2. Validates the EIP-712 `installationSignature` over the module installation parameters
     * 3. Installs the modules if validation succeeds
     * 4. Continues with normal user operation validation using the forwarded `signature`
     * Otherwise, falls back to `super._validateUserOp`.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal virtual override(Account, AccountERC7579Upgradeable) returns (uint256) {
        if (userOp.initCode.length >= 4 && bytes4(userOp.initCode[:4]) == ERC8043Utils.INIT_MODE_MAGIC_VALUE) {
            (
                bool valid,
                uint256[] calldata moduleTypeIds,
                address[] calldata modules,
                bytes[] calldata initDatas,
                bytes calldata installationSignature
            ) = ERC8043Utils.tryDecodeInitMode(userOp.initCode[4:]);
            if (!valid) return ERC4337Utils.SIG_VALIDATION_FAILED;
            if (installationSignature.length > 0) {
                uint256 nonce = userOp.nonce;
                bytes32 structHash = ERC8043Utils.initModulesStructHash(moduleTypeIds, modules, initDatas, nonce);
                if (
                    isValidSignature(_hashTypedDataV4(structHash), installationSignature) !=
                    IERC1271.isValidSignature.selector
                ) {
                    return ERC4337Utils.SIG_VALIDATION_FAILED;
                }
                for (uint256 i = 0; i < modules.length; i++) {
                    _installModule(moduleTypeIds[i], modules[i], initDatas[i]);
                }
            }
        }
        return super._validateUserOp(userOp, userOpHash, signature);
    }
}
