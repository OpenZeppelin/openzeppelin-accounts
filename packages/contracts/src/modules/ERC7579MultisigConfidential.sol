// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {FHE, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ERC7579Validator} from "./validators/ERC7579Validator.sol";

abstract contract ERC7579MultisigConfidential is ERC7579Validator {
    using EnumerableSet for EnumerableSet.BytesSet;
    using SignatureChecker for bytes32;
    using SignatureChecker for bytes;

    event ERC7913SignerAdded(address indexed account, bytes signer);

    event ERC7913SignerRemoved(address indexed account, bytes signer);

    error ERC7579MultisigInvalidInitData();

    error ERC7579MultisigInvalidValidation();

    event ERC7913ThresholdSet(address indexed account, euint64 threshold);

    error ERC7579MultisigAlreadyExists(bytes signer);

    error ERC7579MultisigNonexistentSigner(bytes signer);

    error ERC7579MultisigInvalidSigner(bytes signer);

    error ERC7579MultisigZeroThreshold();

    mapping(address account => EnumerableSet.BytesSet) private _signersSetByAccount;
    mapping(address account => euint64) private _thresholdByAccount;

    function onInstall(bytes calldata initData) public virtual {
        if (initData.length > 32 && getSignerCount(msg.sender) == 0) {
            (bytes[] calldata signers_, euint64 threshold_) = _decodeMultisigInitData(initData);
            _addSigners(msg.sender, signers_);
            _setThreshold(msg.sender, threshold_);
        }
    }

    function onUninstall(bytes calldata /* data */) public virtual {
        _signersSetByAccount[msg.sender].clear();
        _thresholdByAccount[msg.sender] = FHE.asEuint64(0);
    }

    function getSigners(address account, uint64 start, uint64 end) public view virtual returns (bytes[] memory) {
        return _signersSetByAccount[account].values(start, end);
    }

    function getSignerCount(address account) public view virtual returns (uint256) {
        return _signersSetByAccount[account].length();
    }

    function isSigner(address account, bytes memory signer) public view virtual returns (bool) {
        return _signersSetByAccount[account].contains(signer);
    }

    function threshold(address account) public view virtual returns (euint64) {
        return _thresholdByAccount[account];
    }

    function addSigners(bytes[] memory newSigners) public virtual {
        _addSigners(msg.sender, newSigners);
    }

    function removeSigners(bytes[] memory oldSigners) public virtual {
        _removeSigners(msg.sender, oldSigners);
    }

    function setThreshold(euint64 newThreshold) public virtual {
        _setThreshold(msg.sender, newThreshold);
    }

    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bytes[] calldata signingSigners, bytes[] calldata signatures) = _decodeValidationSignature(signature);
        return
            _validateThreshold(account, signingSigners) &&
            _validateSignatures(account, hash, signingSigners, signatures);
    }

    function _decodeMultisigInitData(
        bytes calldata initData
    ) internal pure virtual returns (bytes[] calldata signers, euint64 threshold_) {
        // Minimum length: offset(32) + threshold(32) + array_length(32) = 96 bytes
        require(initData.length > 0x5f, ERC7579MultisigInvalidInitData());

        // Get offset to the signers array (first 32 bytes)
        uint256 signersOffset = uint256(bytes32(initData[:0x20]));

        // Get the threshold handle (32 bytes) and wrap it into an euint64
        threshold_ = euint64.wrap(bytes32(initData[0x20:0x40]));

        // The signers data starts after the length field
        uint256 signersDataOffset = signersOffset + 0x20;

        // Validate offset is within bounds and has space for array length
        require(signersOffset > 0x3f && signersDataOffset <= initData.length, ERC7579MultisigInvalidInitData());
        uint256 signersLength = uint256(bytes32(initData[signersOffset:signersDataOffset]));

        // Set up the calldata slice for the signers array
        assembly ("memory-safe") {
            signers.offset := add(initData.offset, signersDataOffset)
            signers.length := signersLength
        }

        return (signers, threshold_);
    }

    function _decodeValidationSignature(
        bytes calldata signature
    ) internal pure virtual returns (bytes[] calldata signingSigners, bytes[] calldata signatures) {
        // Minimum length: offset1(32) + offset2(32) + array1_length(32) + array2_length(32) = 128 bytes
        require(signature.length > 0x7f, ERC7579MultisigInvalidValidation());

        // Get offset to the first array (signingSigners)
        uint256 signersOffset = uint256(bytes32(signature[:0x20]));

        // Get offset to the second array (signatures)
        uint256 signaturesOffset = uint256(bytes32(signature[0x20:0x40]));

        // Validate offsets are within bounds and properly aligned
        require(
            signersOffset > 0x3f &&
                signersOffset + 0x1f < signature.length &&
                signaturesOffset > 0x3f &&
                signaturesOffset + 0x1f < signature.length,
            ERC7579MultisigInvalidValidation()
        );

        // Get the signers array length
        uint256 signersLength = uint256(bytes32(signature[signersOffset:signersOffset + 0x20]));

        // Get the signatures array length
        uint256 signaturesLength = uint256(bytes32(signature[signaturesOffset:signaturesOffset + 0x20]));

        // The array data starts after the length field
        uint256 signersDataOffset = signersOffset + 0x20;
        uint256 signaturesDataOffset = signaturesOffset + 0x20;

        // Validate data offsets are within bounds
        require(
            signersDataOffset <= signature.length && signaturesDataOffset <= signature.length,
            ERC7579MultisigInvalidValidation()
        );

        // Set up the calldata slices for both arrays
        assembly ("memory-safe") {
            signingSigners.offset := add(signature.offset, signersDataOffset)
            signingSigners.length := signersLength
            signatures.offset := add(signature.offset, signaturesDataOffset)
            signatures.length := signaturesLength
        }

        return (signingSigners, signatures);
    }

    function _addSigners(address account, bytes[] memory newSigners) internal virtual {
        for (uint256 i = 0; i < newSigners.length; ++i) {
            bytes memory signer = newSigners[i];
            require(signer.length >= 20, ERC7579MultisigInvalidSigner(signer));
            require(_signersSetByAccount[account].add(signer), ERC7579MultisigAlreadyExists(signer));
            emit ERC7913SignerAdded(account, signer);
        }
    }

    function _removeSigners(address account, bytes[] memory oldSigners) internal virtual {
        for (uint256 i = 0; i < oldSigners.length; ++i) {
            bytes memory signer = oldSigners[i];
            require(_signersSetByAccount[account].remove(signer), ERC7579MultisigNonexistentSigner(signer));
            emit ERC7913SignerRemoved(account, signer);
        }
        require(getSignerCount(account) > 0, ERC7579MultisigZeroThreshold());
        _setThreshold(account, FHE.min(FHE.asEuint64(uint64(getSignerCount(account))), threshold(account)));
    }

    function _setThreshold(address account, euint64 newThreshold) internal virtual {
        uint256 totalSigners = getSignerCount(account);
        euint64 currentThreshold = threshold(account);
        ebool isReachable = FHE.ge(FHE.asEuint64(uint64(totalSigners)), currentThreshold);
        euint64 thresholdToSet = FHE.select(isReachable, newThreshold, currentThreshold);
        _thresholdByAccount[account] = thresholdToSet;
        emit ERC7913ThresholdSet(account, thresholdToSet);
    }

    function _validateSignatures(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        bytes[] calldata signatures
    ) internal view virtual returns (bool valid) {
        for (uint256 i = 0; i < signingSigners.length; ++i) {
            if (!isSigner(account, signingSigners[i])) {
                return false;
            }
        }
        return hash.areValidSignaturesNow(signingSigners, signatures);
    }

    function _validateThreshold(
        address account,
        bytes[] calldata validatingSigners
    ) internal view virtual returns (ebool) {
        return FHE.ge(FHE.asEuint64(uint64(validatingSigners.length)), threshold(account));
    }
}
