// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {FHE, euint16, euint32, externalEuint32, externalEaddress, eaddress, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/**
 * @dev Implementation of an {IERC7579Module} that provides confidential multisignature
 * validation.
 *
 * This module provides a base implementation for multisignature validation that can be
 * attached to any function through the {_validateMultisig} internal function. Unlike
 * the standard {ERC7579Multisig} module, this confidential version uses Fully Homomorphic
 * Encryption (FHE) to keep signer addresses and the threshold value encrypted on-chain.
 * This provides privacy benefits by hiding the identity of authorized signers and the
 * number of signatures required to approve operations.
 *
 * A smart account with this module installed can require multiple signers to approve
 * operations before they are executed, such as requiring 3-of-5 guardians to approve
 * a social recovery operation, while keeping both the signer identities and threshold
 * confidential.
 *
 * IMPORTANT: Due to the probabilistic nature of FHE encryption, encrypting the same plaintext
 * address multiple times produces different ciphertexts. This means the same underlying signer
 * can be added multiple times with different encrypted handles, and duplicate detection by
 * comparing encrypted handles is not possible. Consider duplicate signers may cause the
 * threshold to become unreachable since {_validateSignatures} checks for duplicates.
 */
abstract contract ERC7579MultisigConfidential is IERC7579Module {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using SignatureChecker for bytes32;

    /// @dev The `initData` is invalid or improperly formatted.
    error ERC7579MultisigInvalidInitData();

    /// @dev The validation arrays have mismatched lengths.
    error ERC7579MultisigMismatchedValidationLength(
        uint256 signingSignersLength,
        uint256 signerHandlesLength,
        uint256 signaturesLength
    );

    /// @dev The number of signers exceeds `type(uint32).max`.
    error ERC7579MultisigTooManySigners();

    /// @dev The `signers` array is empty.
    error ERC7579MultisigEmptySigners();

    /// @dev The encrypted `signer` does not exist in the authorized set.
    error ERC7579MultisigNonexistentSigner(eaddress signer);

    /// @dev The `account` has already installed the module.
    error ERC7579MultisigAlreadyInstalled();

    /// @dev Emitted when an encrypted signer is added to the authorized set.
    event ERC7579MultisigSignerAdded(address indexed account, eaddress signer);

    /// @dev Emitted when an encrypted signer is removed from the authorized set.
    event ERC7579MultisigSignerRemoved(address indexed account, eaddress signer);

    /// @dev Emitted when the encrypted threshold is updated.
    event ERC7579MultisigThresholdSet(address indexed account, euint32 threshold);

    mapping(address account => EnumerableSet.Bytes32Set) private _signersSetByAccount;
    mapping(address account => euint32) private _thresholdByAccount;

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * See {IERC7579Module-onInstall}. The `initData` encodes externally encrypted
     * `signers` and `threshold`. See {_decodeMultisigInitData} for the encoding details.
     *
     * NOTE: An account can only call `onInstall` once. If called directly by the account,
     * the signers will be set to the provided data. Future installations will revert with
     * {ERC7579MultisigAlreadyInstalled}.
     *
     * Requirements:
     *
     * * The `account` must have no signers installed. Reverts with {ERC7579MultisigAlreadyInstalled} if not.
     * * The `signers` array must be non-empty. Reverts with {ERC7579MultisigEmptySigners} if not.
     * * Those of {_decodeMultisigInitData} for the decoding requirements.
     * * Those of {addSigners} for encrypted signers configuration requirements.
     */
    function onInstall(bytes calldata initData) public virtual {
        require(getSignerCount(msg.sender) == 0, ERC7579MultisigAlreadyInstalled());
        (
            bytes calldata inputProof,
            externalEaddress[] calldata externalSigners,
            externalEuint32 externalThreshold
        ) = _decodeMultisigInitData(initData);
        require(externalSigners.length > 0, ERC7579MultisigEmptySigners());
        addSigners(externalSigners, inputProof);
        setThreshold(externalThreshold, inputProof);
    }

    /**
     * @dev Cleans up module's configuration when uninstalled from an account.
     * Clears all signers and resets the threshold.
     *
     * See {IERC7579Module-onUninstall}.
     *
     * WARNING: This function has unbounded gas costs and may become uncallable if the set grows too large.
     * See {EnumerableSet-clear}.
     */
    function onUninstall(bytes calldata /* data */) public virtual {
        _signersSetByAccount[msg.sender].clear();
        _thresholdByAccount[msg.sender] = euint32.wrap(0);
    }

    /**
     * @dev Returns a slice of the set of authorized encrypted signers for the specified account.
     *
     * The returned signers are encrypted addresses (eaddress). Using `start = 0` and
     * `end = type(uint32).max` will return the entire set of signers.
     *
     * WARNING: Depending on the `start` and `end`, this operation can copy a large amount of data to memory, which
     * can be expensive. This is designed for view accessors queried without gas fees. Using it in state-changing
     * functions may become uncallable if the slice grows too large.
     */
    function getSigners(address account, uint32 start, uint32 end) public view virtual returns (eaddress[] memory) {
        bytes32[] memory signerHandles = _signersSetByAccount[account].values(start, end);
        eaddress[] memory signers;
        assembly ("memory-safe") {
            signers := signerHandles
        }
        return signers;
    }

    /// @dev Returns the number of authorized encrypted signers for the specified account.
    function getSignerCount(address account) public view virtual returns (uint256) {
        return _signersSetByAccount[account].length();
    }

    /// @dev Returns whether the encrypted `signer` is an authorized signer for the specified account.
    function isSigner(address account, eaddress signer) public view virtual returns (bool) {
        return _signersSetByAccount[account].contains(FHE.toBytes32(signer));
    }

    /**
     * @dev Returns the encrypted minimum number of signers required to approve a multisignature
     * operation for the specified account.
     */
    function threshold(address account) public view virtual returns (euint32) {
        return _thresholdByAccount[account];
    }

    /**
     * @dev Adds new encrypted signers to the authorized set for the calling account.
     * Can only be called by the account itself. See {_addSigners}.
     *
     * Requirements:
     *
     * * Those of {_addSigners} for additional requirements.
     */
    function addSigners(externalEaddress[] calldata newSigners, bytes calldata inputProof) public virtual {
        eaddress[] memory signers = new eaddress[](newSigners.length);
        for (uint256 i = 0; i < newSigners.length; ++i) {
            signers[i] = FHE.fromExternal(newSigners[i], inputProof);
            FHE.allowThis(signers[i]);
            FHE.allow(signers[i], msg.sender);
        }
        _addSigners(msg.sender, signers);
    }

    /**
     * @dev Removes encrypted signers from the authorized set for the calling account.
     * Can only be called by the account itself. See {_removeSigners}.
     */
    function removeSigners(eaddress[] calldata oldSigners) public virtual {
        _removeSigners(msg.sender, oldSigners);
    }

    /**
     * @dev Sets the encrypted threshold for the calling account.
     * Can only be called by the account itself. See {_setThreshold}.
     */
    function setThreshold(externalEuint32 newThreshold, bytes memory inputProof) public virtual {
        _setThreshold(msg.sender, FHE.fromExternal(newThreshold, inputProof));
    }

    /**
     * @dev Adds the encrypted `newSigners` to those allowed to sign on behalf of the `account`.
     *
     * Requirements:
     *
     * * The number of signers must not exceed `type(uint32).max`. Reverts with {ERC7579MultisigTooManySigners} if exceeded.
     *
     * NOTE: FHE encryption is probabilistic. Encrypting the same plaintext address multiple times
     * produces different ciphertexts and thus different handles. This allows the same underlying
     * signer to be added multiple times, so duplicate detection by comparing encrypted handles
     * is not possible.
     *
     * Emits {ERC7579MultisigSignerAdded} for each new signer.
     */
    function _addSigners(address account, eaddress[] memory newSigners) internal virtual {
        for (uint256 i = 0; i < newSigners.length; ++i) {
            eaddress encryptedSigner = newSigners[i];
            // FHE encryption is probabilistic. Encrypting the same plaintext address multiple times
            // produces different ciphertexts and thus different handles. This allows the same
            // underlying signer to be added multiple times so it doesn't make sense to check for duplicates
            // by checking the return value of add.
            _signersSetByAccount[account].add(FHE.toBytes32(encryptedSigner));
            emit ERC7579MultisigSignerAdded(account, encryptedSigner);
        }
        require(getSignerCount(account) <= type(uint32).max, ERC7579MultisigTooManySigners());
    }

    /**
     * @dev Removes the encrypted `oldSigners` from the authorized signers for the account.
     *
     * Requirements:
     *
     * * Each of `oldSigners` must be authorized. Reverts with {ERC7579MultisigNonexistentSigner} if not.
     * * After removal, at least one signer must remain. Reverts with {ERC7579MultisigEmptySigners} if not.
     *
     * NOTE: The threshold will be automatically capped at the number of remaining signers to ensure it's
     * always reachable.
     *
     * Emits {ERC7579MultisigSignerRemoved} for each removed signer.
     */
    function _removeSigners(address account, eaddress[] calldata oldSigners) internal virtual {
        for (uint256 i = 0; i < oldSigners.length; ++i) {
            eaddress encryptedSigner = oldSigners[i];
            require(
                _signersSetByAccount[account].remove(FHE.toBytes32(encryptedSigner)),
                ERC7579MultisigNonexistentSigner(encryptedSigner)
            );
            emit ERC7579MultisigSignerRemoved(account, encryptedSigner);
        }
        require(getSignerCount(account) > 0, ERC7579MultisigEmptySigners());
        _setThreshold(account, threshold(account)); // Caps the threshold at the number of signers
    }

    /**
     * @dev Sets the encrypted signatures `threshold` required to approve a multisignature operation.
     *
     * NOTE: The threshold is automatically capped at the current number of signers to ensure it's
     * always reachable.
     *
     * Emits {ERC7579MultisigThresholdSet} with the final threshold value.
     */
    function _setThreshold(address account, euint32 newThreshold) internal virtual {
        euint32 thresholdToSet = FHE.min(newThreshold, _maxThreshold(account));
        _thresholdByAccount[account] = thresholdToSet;
        FHE.allowThis(thresholdToSet);
        FHE.allow(thresholdToSet, account);
        emit ERC7579MultisigThresholdSet(account, thresholdToSet);
    }

    /// @dev Returns the maximum threshold for the specified account.
    function _maxThreshold(address account) internal virtual returns (euint32) {
        return FHE.asEuint32(uint32(getSignerCount(account)));
    }

    /**
     * @dev Validates the multisignature operation by checking the threshold and the signatures.
     *
     * The validation is performed using encrypted values to maintain confidentiality. The function
     * verifies that the number of valid signatures meets or exceeds the encrypted threshold.
     *
     * Where `signingSigners` are the plaintext addresses of signers, `signerHandles` are their
     * corresponding encrypted handles, and `signatures` are their signatures of the operation `hash`.
     *
     * TIP: Given that both the threshold and signers are encrypted, it's possible to pass-in
     * valid signatures that don't count towards the threshold.
     */
    function _validateMultisig(
        address account,
        bytes32 hash,
        address[] calldata signingSigners,
        eaddress[] calldata signerHandles,
        bytes[] calldata signatures
    ) internal virtual returns (ebool) {
        ebool valid = _validateThreshold(
            account,
            _validateSignatures(account, hash, signingSigners, signerHandles, signatures)
        );
        FHE.allowThis(valid);
        FHE.allow(valid, account);
        return valid;
    }

    /**
     * @dev Validates the signatures using the signers and their corresponding signatures.
     * Returns the number of valid signatures as an encrypted value.
     *
     * To count towards the threshold, for each signer:
     *
     * 1. The handle must exist in the authorized set
     * 2. The handle must match the corresponding plaintext address
     * 3. The signature must be valid for the given hash
     * 4. The must not be a duplicate of a previous signer in the array
     *
     * The signers should be ordered by their address value to ensure efficient duplication check.
     * Unordered signers are supported, but the uniqueness check will be more expensive.
     *
     * Requirements:
     *
     * * The `signingSigners`, `signerHandles`, and `signatures` arrays must have the same length.
     *   Reverts with {ERC7579MultisigMismatchedValidationLength} if not.
     */
    function _validateSignatures(
        address account,
        bytes32 hash,
        address[] calldata signingSigners,
        eaddress[] calldata signerHandles,
        bytes[] calldata signatures
    ) internal virtual returns (euint32) {
        require(
            signingSigners.length == signerHandles.length && signingSigners.length == signatures.length,
            ERC7579MultisigMismatchedValidationLength(signingSigners.length, signerHandles.length, signatures.length)
        );

        euint32 reachedThreshold = FHE.asEuint32(0);
        address lastSigner = address(0);

        for (uint256 i = 0; i < signingSigners.length; ++i) {
            address signer = signingSigners[i];
            eaddress signerHandle = signerHandles[i];

            bool isDuplicate = false;

            // If the current signer is greater than all previous signers, then this is a new signer.
            if (lastSigner < signer) {
                lastSigner = signer;
            } else {
                // If this signer is not greater than all the previous ones, verify that it is not a duplicate
                // This loop is never executed if the signers are ordered by address.
                for (uint256 j = 0; j < i && !isDuplicate; ++j) {
                    isDuplicate = signer == signingSigners[j];
                }
            }

            bool isValidSignature = SignatureChecker.isValidSignatureNow(signer, hash, signatures[i]);
            // Can't overflow because the amount of signers is bounded to type(uint32).max
            reachedThreshold = FHE.add(
                reachedThreshold,
                FHE.select(
                    FHE.and(
                        FHE.asEbool(!isDuplicate),
                        FHE.and(FHE.eq(signerHandle, FHE.asEaddress(signer)), FHE.asEbool(isValidSignature))
                    ),
                    _signerWeight(account, signerHandle), // 0 if not a signer
                    FHE.asEuint16(0)
                )
            );
        }

        return reachedThreshold;
    }

    /// @dev Returns the encrypted weight of an encrypted signer towards the threshold of the account.
    function _signerWeight(address account, eaddress signer) internal virtual returns (euint16) {
        return FHE.select(FHE.asEbool(isSigner(account, signer)), FHE.asEuint16(1), FHE.asEuint16(0));
    }

    /**
     * @dev Validates that the encrypted `reachedThreshold` meets or exceeds the encrypted threshold
     * set for the account.
     */
    function _validateThreshold(address account, euint32 reachedThreshold) internal virtual returns (ebool) {
        return FHE.ge(reachedThreshold, threshold(account));
    }

    /**
     * @dev Decodes multisig initialization data from calldata without memory allocation.
     *
     * The initData should be encoded as:
     * `abi.encode(bytes inputProof, externalEaddress[] signers, externalEuint32 threshold)`
     *
     * Requirements:
     *
     * * The `initData` must be at least 160 bytes long to contain the minimum structure.
     * * All offsets must be properly aligned and within bounds.
     * * All array length fields must be accessible within the provided data.
     * * The proof data must be fully contained within the provided data.
     */
    function _decodeMultisigInitData(
        bytes calldata initData
    )
        internal
        pure
        virtual
        returns (bytes calldata inputProof, externalEaddress[] calldata signers, externalEuint32 threshold_)
    {
        // Minimum length:
        // inputProofOffset(32) + signersOffset(32) + threshold(32) +
        // inputProofLength(32) + signersArrayLength(32) = 160 bytes
        require(initData.length > 0x9f, ERC7579MultisigInvalidInitData());

        // Get the externally encrypted threshold handle
        threshold_ = externalEuint32.wrap(bytes32(initData[0x40:0x60]));

        // Get offset to the input proof
        uint256 inputProofOffset = uint256(bytes32(initData[:0x20]));
        uint256 proofDataOffset = inputProofOffset + 0x20;

        // Validate inputProof offset is within bounds and has space for proof data length
        require(inputProofOffset > 0x5f && proofDataOffset <= initData.length, ERC7579MultisigInvalidInitData());
        uint256 proofLength = uint256(bytes32(initData[inputProofOffset:proofDataOffset]));
        require(proofDataOffset + proofLength <= initData.length, ERC7579MultisigInvalidInitData());

        // Extract the input proof
        assembly ("memory-safe") {
            inputProof.offset := add(initData.offset, proofDataOffset)
            inputProof.length := proofLength
        }

        // Get offset to the signers array
        uint256 signersOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 signersDataOffset = signersOffset + 0x20;

        // Validate signers offset is within bounds and has space for array length
        require(signersOffset > 0x7f && signersDataOffset <= initData.length, ERC7579MultisigInvalidInitData());
        uint256 signersLength = uint256(bytes32(initData[signersOffset:signersDataOffset]));
        require(signersDataOffset + signersLength * 0x20 <= initData.length, ERC7579MultisigInvalidInitData());

        // Set up the calldata slice for the signers array
        assembly ("memory-safe") {
            signers.offset := add(initData.offset, signersDataOffset)
            signers.length := signersLength
        }

        return (inputProof, signers, threshold_);
    }
}
