// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579MultisigConfidentialValidator} from "./ERC7579MultisigConfidentialValidator.sol";
import {ERC7579MultisigWeightedConfidential} from "../ERC7579MultisigWeightedConfidential.sol";
import {ERC7579MultisigConfidential} from "../ERC7579MultisigConfidential.sol";
import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {euint256, euint32, euint16} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @dev Extension of {ERC7579MultisigConfidentialValidator} that uses {ERC7579MultisigWeightedConfidential}
 * for confidential multisignature validation with weighted signatures.
 */
contract ERC7579MultisigWeightedConfidentialValidator is
    ERC7579MultisigConfidentialValidator,
    ERC7579MultisigWeightedConfidential
{
    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function onInstall(
        bytes calldata initData
    ) public virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential, IERC7579Module) {
        super.onInstall(initData);
    }

    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function onUninstall(
        bytes calldata data
    ) public virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential, IERC7579Module) {
        super.onUninstall(data);
    }

    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function _addSigners(
        address account,
        euint256[] memory newSigners
    ) internal virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential) {
        super._addSigners(account, newSigners);
    }

    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function _removeSigners(
        address account,
        euint256[] calldata oldSigners
    ) internal virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential) {
        super._removeSigners(account, oldSigners);
    }

    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function _maxThreshold(
        address account
    ) internal virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential) returns (euint32) {
        return super._maxThreshold(account);
    }

    /// @inheritdoc ERC7579MultisigWeightedConfidential
    function _signerWeight(
        address account,
        euint256 signer
    ) internal virtual override(ERC7579MultisigConfidential, ERC7579MultisigWeightedConfidential) returns (euint16) {
        return super._signerWeight(account, signer);
    }
}
