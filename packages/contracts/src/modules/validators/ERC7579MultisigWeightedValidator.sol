// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC7579Multisig} from "../ERC7579Multisig.sol";
import {ERC7579MultisigValidator} from "./ERC7579MultisigValidator.sol";
import {ERC7579MultisigWeighted} from "../ERC7579MultisigWeighted.sol";

/**
 * @dev Extension of {ERC7579MultisigValidator} that uses {ERC7579MultisigWeighted} for multisignature validation
 * with weighted signatures.
 */
abstract contract ERC7579MultisigWeightedValidator is ERC7579MultisigValidator, ERC7579MultisigWeighted {
    function onInstall(
        bytes calldata initData
    ) public virtual override(ERC7579Multisig, ERC7579MultisigWeighted, IERC7579Module) {
        super.onInstall(initData);
    }

    function onUninstall(
        bytes calldata data
    ) public virtual override(ERC7579Multisig, ERC7579MultisigWeighted, IERC7579Module) {
        super.onUninstall(data);
    }

    function _addSigners(
        address account,
        bytes[] memory newSigners
    ) internal virtual override(ERC7579Multisig, ERC7579MultisigWeighted) {
        super._addSigners(account, newSigners);
    }

    function _removeSigners(
        address account,
        bytes[] memory oldSigners
    ) internal virtual override(ERC7579Multisig, ERC7579MultisigWeighted) {
        super._removeSigners(account, oldSigners);
    }

    function _validateReachableThreshold(
        address account
    ) internal view virtual override(ERC7579Multisig, ERC7579MultisigWeighted) {
        super._validateReachableThreshold(account);
    }

    function _validateThreshold(
        address account,
        bytes[] calldata validatingSigners
    ) internal view virtual override(ERC7579Multisig, ERC7579MultisigWeighted) returns (bool) {
        return super._validateThreshold(account, validatingSigners);
    }
}
