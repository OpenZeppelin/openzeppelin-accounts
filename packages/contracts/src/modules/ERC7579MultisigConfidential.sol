// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {FHE, ebool, euint16, euint32, euint256, externalEuint32, externalEuint256} from "@fhevm/solidity/lib/FHE.sol";
import {IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/**
 * @dev Implementation of an {IERC7579Module} that provides confidential multisignature
 * validation.
 *
 * This module provides a base implementation for multisignature validation that can be
 * attached to any function through the {_validateMultisig} internal function. Unlike
 * the standard {ERC7579Multisig} module, this confidential version uses Fully Homomorphic
 * Encryption (FHE) to keep signer identities and the threshold value encrypted on-chain.
 * This provides privacy benefits by hiding the identity of authorized signers and the
 * number of signatures required to approve operations.
 *
 * A smart account with this module installed can require multiple signers to approve
 * operations, such as requiring 3-of-5 guardians to approve a social recovery operation,
 * while keeping both the signer identities and threshold confidential.
 *
 * Operations are identified by their hash, which represents arbitrary data for the application
 * to validate. Therefore, replay protection and other considersations about the operation must be
 * handled by the application.
 *
 * To request disclosure of the multisignature validation result for a given operation, the
 * application must call `requestDiscloseOperation` to make the result publicly decryptable,
 * then call `discloseOperation` to verify the decryption proof and get the result.
 *
 * IMPORTANT: Due to the non-deterministic nature of FHE encryption, encrypting the same plaintext
 * uint256 value multiple times produces different ciphertexts. This means the same underlying signer
 * can be added multiple times with different encrypted handles, and duplicate detection by
 * comparing encrypted handles is not possible. Consider duplicate signers may cause the
 * threshold to become unreachable since {_validateSignatures} checks for duplicates.
 *
 * NOTE: This module supports both address-based signers (EOAs and ERC-1271 contracts) and
 * ERC-7913 signers (arbitrary keys with verifiers). Addresses are cast to uint256 and
 * encrypted, while ERC-7913 keys are hashed with `keccak256(verifier || key)` before
 * encryption. This hybrid approach allows addresses to be recognizable after decryption,
 * while ERC-7913 keys require an off-chain mapping from hash to preimage.
 *
 * NOTE: The threshold can be set to 0 given it can't be validated in runtime. The account
 * operators must rely on external validation to ensure the threshold is not 0, which allows
 * arbitrary execution.
 *
 * NOTE: A per-account configuration nonce (from {Nonces}) is incremented on every configuration
 * change ({addSigners}, {removeSigners}, {setThreshold}, {onInstall}). Disclosure state is scoped
 * to the nonce active at the time of {requestDiscloseOperation}, so any configuration change
 * automatically invalidates outstanding disclosure entries and closes the stale-approval window.
 *
 * WARNING: This module provides confidentiality of signer identities and threshold values, but
 * does not provide confidentiality of threshold relationships among participants. Once a valid
 * disclosure is made via {requestDiscloseOperation}, any party that has observed valid signatures
 * for the operation hash (e.g. from mempool or calldata) can probe arbitrary signer subsets to
 * infer the threshold or weight distribution. To limit the exposure window, accounts can perform
 * a signer reset after sensitive operations: re-encrypting the signer set with fresh FHE handles
 * (and optionally updating the threshold) invalidates any oracle knowledge accumulated over the
 * previous handle set, since FHE encryption is non-deterministic and old handles are unlinkable
 * to new ones.
 */
abstract contract ERC7579MultisigConfidential is IERC7579Module, Nonces {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using SignatureChecker for bytes;

    /// @dev The `initData` is invalid or improperly formatted.
    error ERC7579MultisigInvalidInitData();

    /// @dev The validation arrays have mismatched lengths.
    error ERC7579MultisigMismatchedValidationLength(
        uint256 signingSignersLength,
        uint256 signerIdHandlesLength,
        uint256 signaturesLength
    );

    /// @dev The number of signers exceeds `type(uint32).max`.
    error ERC7579MultisigTooManySigners();

    /// @dev The `signers` array is empty.
    error ERC7579MultisigEmptySigners();

    /// @dev The encrypted `signerId` does not exist in the authorized set.
    error ERC7579MultisigNonexistentSigner(euint256 signerId);

    /// @dev The `account` has already installed the module.
    error ERC7579MultisigAlreadyInstalled();

    /// @dev The encrypted `signerId` is a duplicate handle.
    error ERC7579MultisigDuplicateHandle(euint256 signerId);

    /// @dev The operation (hash) is not requested for disclosure.
    error ERC7579MultisigUnknownDisclosure(bytes32 hash);

    /// @dev Emitted when an encrypted signerId is added to the authorized set.
    event ERC7579MultisigSignerAdded(address indexed account, euint256 signerId);

    /// @dev Emitted when an encrypted signerId is removed from the authorized set.
    event ERC7579MultisigSignerRemoved(address indexed account, euint256 signerId);

    /// @dev Emitted when the encrypted threshold is updated.
    event ERC7579MultisigThresholdSet(address indexed account, euint32 threshold);

    /// @dev Emitted when a disclosure request is made for an operation.
    event ERC7579MultisigOperationDiscloseRequested(
        address indexed relayer,
        address indexed account,
        bytes32 indexed hash,
        ebool valid
    );

    /// @dev Emitted when an operation is disclosed with its decryption proof verified.
    event ERC7579MultisigOperationDisclosed(address indexed account, bytes32 indexed hash, ebool valid);

    mapping(address account => EnumerableSet.Bytes32Set) private _signersSetByAccount;
    mapping(address account => euint32) private _thresholdByAccount;
    mapping(address relayer => mapping(address account => mapping(uint256 nonce => mapping(bytes32 hash => ebool))))
        private _requestedDisclosure;
    mapping(address account => mapping(uint256 nonce => mapping(bytes32 hash => bool))) private _disclosed;

    /**
     * @dev Sets up the module's initial configuration when installed by an account.
     * See {IERC7579Module-onInstall}. The `initData` encodes externally encrypted
     * `signerIds` and `threshold`. See {_decodeMultisigInitData} for the encoding details.
     *
     * NOTE: An account can only call `onInstall` once. If called directly by the account,
     * the signerIds will be set to the provided data. Future installations will revert with
     * {ERC7579MultisigAlreadyInstalled}.
     *
     * Requirements:
     *
     * * The `account` must have no signers installed. Reverts with {ERC7579MultisigAlreadyInstalled} if not.
     * * The `signerIds` array must be non-empty. Reverts with {ERC7579MultisigEmptySigners} if not.
     * * Those of {_decodeMultisigInitData} for the decoding requirements.
     * * Those of {addSigners} for encrypted signers configuration requirements.
     */
    function onInstall(bytes calldata initData) public virtual {
        require(getSignerCount(msg.sender) == 0, ERC7579MultisigAlreadyInstalled());
        (
            bytes calldata inputProof,
            externalEuint256[] calldata externalSignersIds,
            externalEuint32 externalThreshold
        ) = _decodeMultisigInitData(initData);
        require(externalSignersIds.length > 0, ERC7579MultisigEmptySigners());
        euint256[] memory signersIds = new euint256[](externalSignersIds.length);
        for (uint256 i = 0; i < externalSignersIds.length; ++i) {
            signersIds[i] = FHE.fromExternal(externalSignersIds[i], inputProof);
            FHE.allowThis(signersIds[i]);
            FHE.allow(signersIds[i], msg.sender);
        }
        _addSigners(msg.sender, signersIds);
        _setThreshold(msg.sender, FHE.fromExternal(externalThreshold, inputProof));
        _useNonce(msg.sender);
    }

    /**
     * @dev Cleans up module's configuration when uninstalled from an account.
     * Clears all signerIds and resets the threshold.
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
     * The returned signers are encrypted uint256 values (euint256). Using `start = 0` and
     * `end = type(uint32).max` will return the entire set of signerIds.
     *
     * WARNING: Depending on the `start` and `end`, this operation can copy a large amount of data to memory, which
     * can be expensive. This is designed for view accessors queried without gas fees. Using it in state-changing
     * functions may become uncallable if the slice grows too large.
     */
    function getSigners(address account, uint32 start, uint32 end) public view virtual returns (euint256[] memory) {
        bytes32[] memory signerHandles = _signersSetByAccount[account].values(start, end);
        euint256[] memory signerIds;
        assembly ("memory-safe") {
            signerIds := signerHandles
        }
        return signerIds;
    }

    /// @dev Returns the number of authorized encrypted signers for the specified account.
    function getSignerCount(address account) public view virtual returns (uint256) {
        return _signersSetByAccount[account].length();
    }

    /// @dev Returns whether the encrypted `signerId` is an authorized signer for the specified account.
    function isSigner(address account, euint256 signerId) public view virtual returns (bool) {
        return _signersSetByAccount[account].contains(FHE.toBytes32(signerId));
    }

    /**
     * @dev Returns the encrypted minimum number of signers required to approve a multisignature
     * operation for the specified account.
     */
    function threshold(address account) public view virtual returns (euint32) {
        return _thresholdByAccount[account];
    }

    /**
     * @dev Returns whether the multisignature validation result for an operation (hash) is requested for
     * disclosure under the account's current configuration nonce.
     *
     * NOTE: Returns an uninitialized handle if the configuration has changed since the disclosure was requested.
     */
    function requestedDisclosure(address relayer, address account, bytes32 hash) public view virtual returns (ebool) {
        return _requestedDisclosure[relayer][account][nonces(account)][hash];
    }

    /**
     * @dev Returns whether the multisignature validation result for an operation (hash) is disclosed
     * under the account's current configuration nonce.
     *
     * NOTE: Returns false if the configuration has changed since the operation was disclosed.
     */
    function disclosed(address account, bytes32 hash) public view virtual returns (bool) {
        return _disclosed[account][nonces(account)][hash];
    }

    /**
     * @dev Adds new encrypted signerIds to the authorized set for the calling account.
     * Can only be called by the account itself. See {_addSigners}.
     *
     * Increments the account's configuration nonce, invalidating any outstanding disclosure entries
     * made under the previous nonce.
     *
     * The signerIds are provided as externally encrypted uint256 values. Each signerId represents
     * either an address (cast to uint256) or an ERC-7913 key (hashed with `keccak256(verifier || key)`
     * and cast to uint256). The caller must encrypt the signerId off-chain before calling this function.
     *
     * Requirements:
     *
     * * Those of {_addSigners} for additional requirements.
     */
    function addSigners(externalEuint256[] calldata newSignersIds, bytes calldata inputProof) public virtual {
        euint256[] memory signersIds = new euint256[](newSignersIds.length);
        for (uint256 i = 0; i < newSignersIds.length; ++i) {
            signersIds[i] = FHE.fromExternal(newSignersIds[i], inputProof);
            FHE.allowThis(signersIds[i]);
            FHE.allow(signersIds[i], msg.sender);
        }
        _addSigners(msg.sender, signersIds);
        _useNonce(msg.sender);
    }

    /**
     * @dev Removes encrypted signerIds from the authorized set for the calling account.
     * Can only be called by the account itself. See {_removeSigners}.
     *
     * Increments the account's configuration nonce, invalidating any outstanding disclosure entries
     * made under the previous nonce.
     */
    function removeSigners(euint256[] calldata oldSignersIds) public virtual {
        _removeSigners(msg.sender, oldSignersIds);
        _useNonce(msg.sender);
    }

    /**
     * @dev Sets the encrypted threshold for the calling account.
     * Can only be called by the account itself. See {_setThreshold}.
     *
     * Increments the account's configuration nonce, invalidating any outstanding disclosure entries
     * made under the previous nonce.
     */
    function setThreshold(externalEuint32 newThreshold, bytes memory inputProof) public virtual {
        _setThreshold(msg.sender, FHE.fromExternal(newThreshold, inputProof));
        _useNonce(msg.sender);
    }

    /**
     * @dev Requests disclosure of the multisignature validation result for an operation (hash).
     *
     * This function validates the multisignature using encrypted values and makes the
     * result publicly decryptable. Applications that require using the validation result
     * must call this function off-chain first to enable the decryption proof to be included
     * in a subsequent call to `discloseOperation` to verify the proof.
     *
     * NOTE: This function does not perform any access control. Anyone can request disclosure
     * of the multisignature validation result for any operation.
     *
     * IMPORTANT: Each call produces a secret-dependent encrypted boolean that is made publicly
     * decryptable. A caller who possesses valid signatures for the operation `hash` can
     * probe arbitrary signer subsets across multiple calls to infer the threshold or weight
     * distribution, since the decrypted result reveals whether the chosen subset meets the
     * threshold.
     *
     * Emits a {ERC7579MultisigOperationDiscloseRequested} event.
     */
    function requestDiscloseOperation(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        euint256[] calldata signerIdHandles,
        bytes[] calldata signatures
    ) public {
        _requestDiscloseOperation(
            msg.sender,
            account,
            hash,
            _validateMultisig(account, hash, signingSigners, signerIdHandles, signatures)
        );
    }

    /**
     * @dev Verifies the decryption proof for a disclosed operation (hash).
     *
     * Requirements:
     *
     * * The decryption proof must be cryptographically valid. Reverts if invalid.
     *
     * Emits a {ERC7579MultisigOperationDisclosed} event.
     */
    function discloseOperation(address relayer, address account, bytes32 hash, bytes calldata decryptionProof) public {
        _discloseOperation(relayer, account, hash, decryptionProof);
    }

    /// @dev Same as {discloseOperation} but with the relayer set to `msg.sender`.
    function discloseOperation(address account, bytes32 hash, bytes calldata decryptionProof) public {
        _discloseOperation(msg.sender, account, hash, decryptionProof);
    }

    /**
     * @dev Adds the encrypted `newSignerIds` to those allowed to sign on behalf of the `account`.
     *
     * Requirements:
     *
     * * The number of signers must not exceed `type(uint32).max`. Reverts with {ERC7579MultisigTooManySigners} if exceeded.
     *
     * IMPORTANT: This function does not increment the account's configuration nonce.
     * Callers that change the configuration must call {Nonces-_useNonce} to invalidate
     * outstanding disclosure entries.
     *
     * NOTE: FHE encryption is non-deterministic. Encrypting the same plaintext uint256 value multiple times
     * produces different ciphertexts and thus different handles. This allows the same underlying
     * signer to be added multiple times, so duplicate detection by comparing encrypted handles
     * is not possible.
     *
     * Emits {ERC7579MultisigSignerAdded} for each new signer.
     */
    function _addSigners(address account, euint256[] memory newSignerIds) internal virtual {
        for (uint256 i = 0; i < newSignerIds.length; ++i) {
            euint256 encryptedSignerId = newSignerIds[i];
            // We only check that the handle is not duplicate, though, it doesn't guarantee that the signer is not a duplicate.
            require(
                _signersSetByAccount[account].add(FHE.toBytes32(encryptedSignerId)),
                ERC7579MultisigDuplicateHandle(encryptedSignerId)
            );
            emit ERC7579MultisigSignerAdded(account, encryptedSignerId);
        }
        require(getSignerCount(account) <= type(uint32).max, ERC7579MultisigTooManySigners());
    }

    /**
     * @dev Removes the encrypted `oldSignerIds` from the authorized signerIds for the account.
     *
     * Requirements:
     *
     * * Each of `oldSignerIds` must be authorized. Reverts with {ERC7579MultisigNonexistentSigner} if not.
     * * After removal, at least one signer must remain. Reverts with {ERC7579MultisigEmptySigners} if not.
     *
     * IMPORTANT: This function does not increment the account's configuration nonce.
     * Callers that change the configuration must call {Nonces-_useNonce} to invalidate
     * outstanding disclosure entries.
     *
     * NOTE: The threshold will be automatically capped at the number of remaining signers to ensure it's
     * always reachable.
     *
     * Emits {ERC7579MultisigSignerRemoved} for each removed signer.
     */
    function _removeSigners(address account, euint256[] calldata oldSignerIds) internal virtual {
        for (uint256 i = 0; i < oldSignerIds.length; ++i) {
            euint256 encryptedSignerId = oldSignerIds[i];
            require(
                _signersSetByAccount[account].remove(FHE.toBytes32(encryptedSignerId)),
                ERC7579MultisigNonexistentSigner(encryptedSignerId)
            );
            emit ERC7579MultisigSignerRemoved(account, encryptedSignerId);
        }
        require(getSignerCount(account) > 0, ERC7579MultisigEmptySigners());
        _setThreshold(account, threshold(account)); // Caps the threshold at the number of signers
    }

    /**
     * @dev Sets the encrypted signatures `threshold` required to approve a multisignature operation.
     *
     * IMPORTANT: This function does not increment the account's configuration nonce.
     * Callers that change the configuration must call {Nonces-_useNonce} to invalidate
     * outstanding disclosure entries.
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

    /// @dev Requests disclosure of the multisignature validation result for an operation (hash).
    function _requestDiscloseOperation(address relayer, address account, bytes32 hash, ebool valid) internal virtual {
        FHE.makePubliclyDecryptable(valid);
        _requestedDisclosure[relayer][account][nonces(account)][hash] = valid;
        emit ERC7579MultisigOperationDiscloseRequested(relayer, account, hash, valid);
    }

    /// @dev Verifies the decryption proof for a disclosed operation (hash).
    function _discloseOperation(address relayer, address account, bytes32 hash, bytes calldata decryptionProof) public {
        uint256 currentNonce = nonces(account);
        ebool valid = _requestedDisclosure[relayer][account][currentNonce][hash];
        require(FHE.isInitialized(valid), ERC7579MultisigUnknownDisclosure(hash));

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = FHE.toBytes32(valid);
        bytes memory cleartextMemory = abi.encode(true); // Must be true by design
        FHE.checkSignatures(handles, cleartextMemory, decryptionProof);

        _requestedDisclosure[relayer][account][currentNonce][hash] = ebool.wrap(0);
        _disclosed[account][currentNonce][hash] = true;
        emit ERC7579MultisigOperationDisclosed(account, hash, valid);
    }

    /**
     * @dev Validates the multisignature operation by checking the threshold and the signatures.
     *
     * The validation is performed using encrypted values to maintain confidentiality. The function
     * verifies that the number of valid signatures meets or exceeds the encrypted threshold.
     *
     * Where `signingSigners` are the plaintext signers (addresses or ERC-7913 keys as bytes),
     * `signerIdHandles` are their corresponding encrypted id handles, and `signatures` are their
     * signatures of the operation `hash`.
     *
     * TIP: Given that both the threshold and signers are encrypted, it's possible to pass-in
     * signatures that don't count towards the threshold.
     */
    function _validateMultisig(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        euint256[] calldata signerIdHandles,
        bytes[] calldata signatures
    ) internal virtual returns (ebool) {
        ebool valid = _validateThreshold(
            account,
            _validateSignatures(account, hash, signingSigners, signerIdHandles, signatures)
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
     * 2. The handle must match the corresponding plaintext signer
     *    (address cast to uint256 or keccak256 hash for ERC-7913 keys)
     * 3. The signature must be valid for the given hash
     * 4. The signer must not be a duplicate of a previous signer in the array
     *
     * The signers should be ordered by their uint256 representation to ensure efficient duplication check.
     * Unordered signers are supported, but the uniqueness check will be more expensive. See {_toId}.
     *
     * Requirements:
     *
     * * The `signingSigners`, `signerIdHandles`, and `signatures` arrays must have the same length.
     *   Reverts with {ERC7579MultisigMismatchedValidationLength} if not.
     */
    function _validateSignatures(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        euint256[] calldata signerIdHandles,
        bytes[] calldata signatures
    ) internal virtual returns (euint32) {
        require(
            signingSigners.length == signerIdHandles.length && signingSigners.length == signatures.length,
            ERC7579MultisigMismatchedValidationLength(signingSigners.length, signerIdHandles.length, signatures.length)
        );

        euint32 reachedThreshold = FHE.asEuint32(0);
        uint256 lastId = uint256(0);

        for (uint256 i = 0; i < signingSigners.length; ++i) {
            uint256 signerId = _toId(signingSigners[i]);
            // Avoid stack too deep
            {
                bool isDuplicate = false;

                // If the current signer id is greater than all previous signer ids, then this is a new signer.
                if (lastId < signerId) lastId = signerId;
                else {
                    // If this signer is not greater than all the previous ones, verify that it is not a duplicate
                    // This loop is never executed if the signers are ordered by their uint256 representation.
                    for (uint256 j = 0; j < i && !isDuplicate; ++j) {
                        isDuplicate = signerId == _toId(signingSigners[j]);
                    }
                }

                if (isDuplicate) continue;
            }
            bool isValidSignature = signingSigners[i].isValidSignatureNow(hash, signatures[i]);
            euint16 signerWeight = _signerWeight(account, signerIdHandles[i]);
            euint16 weight = FHE.select(
                FHE.and(FHE.eq(signerIdHandles[i], signerId), isValidSignature),
                signerWeight,
                FHE.asEuint16(0)
            );
            reachedThreshold = FHE.add(reachedThreshold, weight); // Can't overflow because the amount of signers is bounded to type(uint32).max
        }

        return reachedThreshold;
    }

    /// @dev Returns the encrypted weight of an encrypted signerId towards the threshold of the account (0 or 1).
    function _signerWeight(address account, euint256 signerId) internal virtual returns (euint16) {
        return FHE.select(FHE.asEbool(isSigner(account, signerId)), FHE.asEuint16(1), FHE.asEuint16(0));
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
     * `abi.encode(bytes inputProof, externalEuint256[] signerIds, externalEuint32 threshold)`
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
        returns (bytes calldata inputProof, externalEuint256[] calldata signerIds, externalEuint32 _threshold)
    {
        // Minimum length:
        // inputProofOffset(32) + signerIdsOffset(32) + threshold(32) +
        // inputProofLength(32) + signerIdsArrayLength(32) = 160 bytes
        require(initData.length > 0x9f, ERC7579MultisigInvalidInitData());

        // Get the externally encrypted threshold handle
        _threshold = externalEuint32.wrap(bytes32(initData[0x40:0x60]));

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

        // Get offset to the signerIds array
        uint256 signerIdsOffset = uint256(bytes32(initData[0x20:0x40]));
        uint256 signerIdsDataOffset = signerIdsOffset + 0x20;

        // Validate signers offset is within bounds and has space for array length
        require(signerIdsOffset > 0x7f && signerIdsDataOffset <= initData.length, ERC7579MultisigInvalidInitData());
        uint256 signerIdsLength = uint256(bytes32(initData[signerIdsOffset:signerIdsDataOffset]));
        require(signerIdsDataOffset + signerIdsLength * 0x20 <= initData.length, ERC7579MultisigInvalidInitData());

        // Set up the calldata slice for the signers array
        assembly ("memory-safe") {
            signerIds.offset := add(initData.offset, signerIdsDataOffset)
            signerIds.length := signerIdsLength
        }

        return (inputProof, signerIds, _threshold);
    }

    /// @dev Converts a signer (address or ERC-7913 key) to uint256 for encryption.
    function _toId(bytes calldata signer) private pure returns (uint256) {
        return
            signer.length > 20
                ? uint256(keccak256(signer)) // forge-lint: disable-next-line(unsafe-typecast)
                : uint256(uint160(bytes20(signer)));
    }
}
