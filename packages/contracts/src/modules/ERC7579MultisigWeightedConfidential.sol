// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579MultisigConfidential} from "./ERC7579MultisigConfidential.sol";
import {
    FHE,
    euint16,
    euint32,
    euint256,
    externalEuint16,
    externalEuint32,
    externalEuint256
} from "@fhevm/solidity/lib/FHE.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @dev Extension of {ERC7579MultisigConfidential} that supports weighted signatures.
 *
 * This module extends the confidential multisignature module to allow assigning different weights
 * to each signer, enabling more flexible governance schemes. For example, some guardians
 * could have higher weight than others, allowing for weighted voting or prioritized authorization.
 *
 * Unlike the standard {ERC7579MultisigWeighted} module, this confidential version uses Fully
 * Homomorphic Encryption (FHE) to keep signer identities (as uint256), weights, and the threshold
 * value encrypted on-chain. This provides privacy benefits by hiding the identity of authorized
 * signers (whether addresses or ERC-7913 keys), their individual weights, and the number of
 * signatures required to approve operations.
 *
 * A smart account with this module installed can schedule social recovery operations
 * after obtaining approval from guardians with sufficient total weight (e.g., requiring
 * a total weight of 10, with 3 guardians weighted as 5, 3, and 2), while keeping both the
 * signer identities, weights, and threshold confidential.
 *
 * IMPORTANT: When setting a threshold value, ensure it matches the scale used for signer weights.
 * For example, if signers have weights like 1, 2, or 3, then a threshold of 4 would require
 * signatures with a total weight of at least 4 (e.g., one with weight 1 and one with weight 3).
 *
 * NOTE: The threshold can be set to 0 given it can't be validated in runtime. The account
 * operators must rely on external validation to ensure the threshold is not 0, which allows
 * arbitrary execution.
 */
abstract contract ERC7579MultisigWeightedConfidential is ERC7579MultisigConfidential {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // There is space for up to 65337 signers using the max weight (i.e. (2**32-1)/(2**16-1))
    // Given _addSigners caps signers to 65335, the max uint32 must never be reached
    // as long as weights are encrypted uint16
    mapping(address account => euint32) private _totalExtraWeight;
    mapping(address account => mapping(euint256 signer => euint16)) private _extraWeights;

    /// @dev Emitted when an encrypted signer's weight is changed.
    event ERC7579MultisigWeightChanged(address indexed account, euint256 signer, euint16 weight);

    /// @dev The `signers` and `weights` arrays have mismatched lengths.
    error ERC7579MultisigMismatchedSignerWeights();

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * Besides the standard signer and threshold configuration, this can also include
     * encrypted signer weights.
     *
     * See {_decodeMultisigWeightedInitData} for the `initData` encoding details.
     *
     * NOTE: An account can only call `onInstall` once. If called directly by the account,
     * the signers, weights, and threshold will be set to the provided data. Future
     * installations will revert with {ERC7579MultisigAlreadyInstalled}.
     *
     * Requirements:
     *
     * * The `account` must have no signers installed. Reverts with {ERC7579MultisigAlreadyInstalled} if not.
     * * The `signers` array must be non-empty. Reverts with {ERC7579MultisigEmptySigners} if not.
     * * Those of {_decodeMultisigWeightedInitData} for the decoding requirements.
     * * Those of {addSigners} and {setSignerWeights} for signer and weight configuration requirements.
     */
    function onInstall(bytes calldata initData) public virtual override {
        require(getSignerCount(msg.sender) == 0, ERC7579MultisigAlreadyInstalled());
        (
            bytes calldata inputProof,
            externalEuint256[] calldata externalSigners,
            externalEuint32 externalThreshold,
            externalEuint16[] calldata externalWeights
        ) = _decodeMultisigWeightedInitData(initData);
        require(externalSigners.length > 0, ERC7579MultisigEmptySigners());
        addSigners(externalSigners, inputProof);
        setSignerWeights(getSigners(msg.sender, 0, type(uint16).max), externalWeights, inputProof);
        setThreshold(externalThreshold, inputProof);
    }

    /**
     * @dev Cleans up module's configuration when uninstalled from an account.
     * Clears all signers, weights, and total weights.
     *
     * See {ERC7579MultisigConfidential-onUninstall}.
     */
    function onUninstall(bytes calldata data) public virtual override {
        euint256[] memory allSigners = getSigners(msg.sender, 0, type(uint32).max);
        for (uint256 i = 0; i < allSigners.length; ++i) {
            _extraWeights[msg.sender][allSigners[i]] = euint16.wrap(0);
        }
        _totalExtraWeight[msg.sender] = euint32.wrap(0);
        super.onUninstall(data);
    }

    /// @dev Returns the encrypted extra weight of an encrypted signer for the specified account.
    function extraWeight(address account, euint256 signer) public view virtual returns (euint16) {
        return _extraWeights[account][signer];
    }

    /// @dev Returns the encrypted total extra weight of all signers for the specified account.
    function totalExtraWeight(address account) public view virtual returns (euint32) {
        return _totalExtraWeight[account];
    }

    /// @dev Returns the encrypted weight of an encrypted signer for the specified account.
    function signerWeight(address account, euint256 signer) public virtual returns (euint16) {
        return _signerWeight(account, signer);
    }

    /// @dev Returns the encrypted total weight of all signers for the specified account.
    function totalWeight(address account) public virtual returns (euint32) {
        return _totalWeight(account);
    }

    /**
     * @dev Sets encrypted weights for signers for the calling account.
     * Can only be called by the account itself.
     *
     * Requirements:
     *
     * * Those of {_setSignerWeights} for additional requirements.
     */
    function setSignerWeights(
        euint256[] memory signers,
        externalEuint16[] calldata externalWeights,
        bytes calldata inputProof
    ) public virtual {
        euint16[] memory weights = new euint16[](externalWeights.length);
        for (uint256 i = 0; i < externalWeights.length; ++i) {
            weights[i] = FHE.fromExternal(externalWeights[i], inputProof);
            FHE.allowThis(weights[i]);
            FHE.allow(weights[i], msg.sender);
        }
        _setSignerWeights(msg.sender, signers, weights);
    }

    /**
     * @dev Decodes weighted multisig initialization data from calldata without memory allocation.
     *
     * The initData should be encoded as:
     * `abi.encode(bytes inputProof, externalEuint256[] signers, externalEuint32 threshold, externalEuint16[] weights)`
     *
     * Requirements:
     *
     * * The `initData` must be at least 224 bytes long to contain the minimum structure.
     * * All offsets must be properly aligned and within bounds.
     * * All array length fields must be accessible within the provided data.
     * * The proof data must be fully contained within the provided data.
     */
    function _decodeMultisigWeightedInitData(
        bytes calldata initData
    )
        internal
        pure
        virtual
        returns (
            bytes calldata inputProof,
            externalEuint256[] calldata signers,
            externalEuint32 threshold_,
            externalEuint16[] calldata weights
        )
    {
        // Minimum length:
        // inputProofOffset(32) + signersOffset(32) + threshold(32) + weightsOffset(32) +
        // inputProofLength(32) + signersArrayLength(32) + weightsArrayLength(32) = 224 bytes
        require(initData.length > 0xdf, ERC7579MultisigInvalidInitData());
        (inputProof, signers, threshold_) = _decodeMultisigInitData(initData);

        uint256 weightsOffset = uint256(bytes32(initData[0x60:0x80]));
        uint256 weightsDataOffset = weightsOffset + 0x20;

        require(weightsOffset > 0xbf && weightsDataOffset <= initData.length, ERC7579MultisigInvalidInitData());
        uint256 weightsLength = uint256(bytes32(initData[weightsOffset:weightsDataOffset]));
        require(weightsDataOffset + weightsLength * 0x20 <= initData.length, ERC7579MultisigInvalidInitData());

        assembly ("memory-safe") {
            weights.offset := add(initData.offset, weightsDataOffset)
            weights.length := weightsLength
        }

        return (inputProof, signers, threshold_, weights);
    }

    /**
     * @dev Override to add weight tracking and restrict signer count. See {ERC7579MultisigConfidential-_addSigners}.
     * Each new signer has a default weight of 1.
     *
     * Requirements:
     *
     * * The number of signers must not exceed `type(uint16).max`. Reverts with {ERC7579MultisigTooManySigners} if exceeded.
     */
    function _addSigners(address account, euint256[] memory newSigners) internal virtual override {
        super._addSigners(account, newSigners);
        // Restrict to uint16 to allow each signer to have as much as `type(uint16).max` weight
        // without overflowing the total weight.
        require(getSignerCount(account) <= type(uint16).max, ERC7579MultisigTooManySigners());
    }

    /**
     * @dev Sets encrypted weights for multiple signers at once. Internal version without access control.
     *
     * Requirements:
     *
     * * `signers` and `weights` arrays must have the same length. Reverts with {ERC7579MultisigMismatchedSignerWeights} on mismatch.
     * * Each signer must exist in the set of authorized signers. Reverts with {ERC7579MultisigNonexistentSigner} if not.
     *
     * NOTE: The threshold will be automatically capped at the total weight to ensure it's always reachable.
     * NOTE: Weights of 0 are automatically converted to weight 1 (base weight). See {signerWeight}.
     *
     * Emits {ERC7579MultisigWeightChanged} for each signer.
     */
    function _setSignerWeights(address account, euint256[] memory signers, euint16[] memory weights) internal virtual {
        require(signers.length == weights.length, ERC7579MultisigMismatchedSignerWeights());

        euint32 extraWeightAdded = FHE.asEuint32(0);
        euint32 extraWeightRemoved = FHE.asEuint32(0);
        for (uint256 i = 0; i < signers.length; ++i) {
            euint256 signer = signers[i];
            require(isSigner(account, signer), ERC7579MultisigNonexistentSigner(signer));

            euint16 weight = weights[i];
            euint16 newExtraWeight_ = FHE.sub(weight, FHE.asEuint16(1));
            // Implicitly caps newExtraWeight to `type(uint16).max - 1`
            euint16 newExtraWeight = FHE.select(FHE.le(newExtraWeight_, weight), newExtraWeight_, FHE.asEuint16(0));

            euint16 oldExtraWeight = extraWeight(account, signer);
            // extraWeightRemoved can't overflow because there are at most `type(uint16).max` signers
            extraWeightRemoved = FHE.add(
                extraWeightRemoved,
                // On the first call to _setSignerWeights, oldExtraWeight is not initialized, so we use 0.
                FHE.isInitialized(oldExtraWeight) ? oldExtraWeight : FHE.asEuint16(0)
            );
            // extraWeightAdded can't overflow for the same reason as extraWeightRemoved.
            extraWeightAdded = FHE.add(extraWeightAdded, newExtraWeight);
            _setExtraWeight(account, signer, newExtraWeight);
            emit ERC7579MultisigWeightChanged(account, signer, weight);
        }

        euint32 oldTotalExtraWeight = totalExtraWeight(account);
        // The `extraWeightRemoved` is bounded by `totalExtraWeight(account)` by construction,
        // so the subtraction can't overflow. Addition can't overflow for the same reason as extraWeightAdded.
        euint32 newTotalExtraWeight = FHE.add(
            FHE.sub(
                // On the first call to _setSignerWeights, oldTotalExtraWeight is not initialized, so we use 0.
                FHE.isInitialized(oldTotalExtraWeight) ? oldTotalExtraWeight : FHE.asEuint32(0),
                extraWeightRemoved
            ),
            extraWeightAdded
        );
        _setTotalExtraWeight(account, newTotalExtraWeight);
        _setThreshold(account, threshold(account)); // Caps the threshold at the total weight
    }

    /**
     * @dev Override to handle weight tracking during removal. See {ERC7579MultisigConfidential-_removeSigners}.
     *
     * Cleans up weights for removed signers and updates the total extra weight accordingly.
     */
    function _removeSigners(address account, euint256[] calldata oldSigners) internal virtual override {
        euint32 extraWeightRemoved = FHE.asEuint32(0);
        for (uint256 i = 0; i < oldSigners.length; ++i) {
            euint256 signer = oldSigners[i];
            // extraWeightRemoved can't overflow because there are at most `type(uint16).max` signers
            extraWeightRemoved = FHE.add(extraWeightRemoved, extraWeight(account, signer));
            _setExtraWeight(account, signer, FHE.asEuint16(0));
        }
        // The `extraWeightRemoved` is bounded by `totalExtraWeight(account)` by construction,
        // so the subtraction can't overflow.
        euint32 newTotalExtraWeight = FHE.sub(totalExtraWeight(account), extraWeightRemoved);
        _setTotalExtraWeight(account, newTotalExtraWeight);
        super._removeSigners(account, oldSigners);
    }

    /// @dev Sets the total extra weight for the specified account.
    function _setTotalExtraWeight(address account, euint32 newTotalExtraWeight) internal virtual {
        _totalExtraWeight[account] = newTotalExtraWeight;
        FHE.allowThis(newTotalExtraWeight);
        FHE.allow(newTotalExtraWeight, account);
    }

    /// @dev Sets the extra weight for a signer for the specified account.
    function _setExtraWeight(address account, euint256 signer, euint16 newExtraWeight) internal virtual {
        _extraWeights[account][signer] = newExtraWeight;
        FHE.allowThis(newExtraWeight);
        FHE.allow(newExtraWeight, account);
    }

    /**
     * @dev Override to return the maximum threshold based on total weight instead of signer count.
     * See {ERC7579MultisigConfidential-_maxThreshold}.
     */
    function _maxThreshold(address account) internal virtual override returns (euint32) {
        return _totalWeight(account);
    }

    /**
     * @dev Override to return the encrypted weight of a signer instead of a fixed weight of 1.
     * See {ERC7579MultisigConfidential-_signerWeight}.
     *
     * Returns 0 if the signer is not authorized, otherwise returns 1 plus the signer's extra weight.
     */
    function _signerWeight(address account, euint256 signer) internal virtual override returns (euint16) {
        euint16 weight = FHE.select(
            FHE.asEbool(isSigner(account, signer)),
            FHE.add(FHE.asEuint16(1), extraWeight(account, signer)),
            FHE.asEuint16(0)
        );
        FHE.allowThis(weight);
        FHE.allow(weight, account);
        return weight;
    }

    /// @dev Returns the encrypted total weight of all signers for the specified account.
    function _totalWeight(address account) internal virtual returns (euint32) {
        // total can't overflow because there are at most `type(uint16).max` signers
        // with at most `type(uint16).max - 1` extra weight each, so the total extra weight is at most
        // `type(uint16).max * (type(uint16).max - 1) = type(uint16).max**2 - type(uint16).max`.
        euint32 total = FHE.add(uint32(getSignerCount(account)), totalExtraWeight(account));
        FHE.allowThis(total);
        FHE.allow(total, account);
        return total;
    }
}
