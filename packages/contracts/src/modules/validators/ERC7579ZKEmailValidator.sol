// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {IDKIMRegistry} from "@zk-email/contracts/DKIMRegistry.sol";
import {IGroth16Verifier} from "@zk-email/email-tx-builder/src/interfaces/IGroth16Verifier.sol";
import {ZKEmailUtils} from "@openzeppelin/community-contracts/utils/cryptography/ZKEmailUtils.sol";
import {EmailProof} from "@zk-email/email-tx-builder/src/interfaces/IVerifier.sol";

contract ERC7579ECDSAValidator is ERC7579Validator {
    using ZKEmailUtils for EmailProof;

    error ERC7579ZKEmailValidatorInvalidInitData();
    error ERC7579ZKEmailValidatorNotAuthorized(address sender, address account);
    error ERC7579ZKEmailValidatorAlreadyInstalled(address account);

    event ERC7579ZKEmailValidatorDKIMRegistrySet(address indexed account, address indexed registry);
    event ERC7579ZKEmailValidatorVerifierSet(address indexed account, address indexed verifier);
    event ERC7579ZKEmailValidatorAccountSaltSet(address indexed account, bytes32 accountSalt);

    mapping(address account => IDKIMRegistry) private _registries;
    mapping(address account => IGroth16Verifier) private _verifiers;
    mapping(address account => bytes32) private _accountSalts;

    modifier onlyAccount(address account) {
        require(msg.sender == account, ERC7579ZKEmailValidatorNotAuthorized(msg.sender, account));
        _;
    }

    function accountSalt(address account) public view virtual returns (bytes32) {
        return _accountSalts[account];
    }

    function verifier(address account) public view virtual returns (IGroth16Verifier) {
        return _verifiers[account];
    }

    function dkimRegistry(address account) public view virtual returns (IDKIMRegistry) {
        return _registries[account];
    }

    function onInstall(bytes calldata data) public virtual override {
        require(accountSalt(msg.sender) == bytes32(0), ERC7579ZKEmailValidatorAlreadyInstalled(msg.sender));
        (IDKIMRegistry registry_, IGroth16Verifier verifier_, bytes32 accountSalt_) = _decodeInitData(data);
        _setDKIMRegistry(msg.sender, registry_);
        _setVerifier(msg.sender, verifier_);
        _setAccountSalt(msg.sender, accountSalt_);
    }

    function onUninstall(bytes calldata) public virtual override {
        delete _registries[msg.sender];
        delete _verifiers[msg.sender];
        delete _accountSalts[msg.sender];
    }

    function setDKIMRegistry(address account, IDKIMRegistry registry) public virtual onlyAccount(account) {
        _setDKIMRegistry(account, registry);
    }

    function setVerifier(address account, IGroth16Verifier verifier_) public virtual onlyAccount(account) {
        _setVerifier(account, verifier_);
    }

    function setAccountSalt(address account, bytes32 accountSalt_) public virtual onlyAccount(account) {
        _setAccountSalt(account, accountSalt_);
    }

    function _setDKIMRegistry(address account, IDKIMRegistry registry_) internal virtual {
        _registries[account] = registry_;
        emit ERC7579ZKEmailValidatorDKIMRegistrySet(account, address(registry_));
    }

    function _setVerifier(address account, IGroth16Verifier verifier_) internal virtual {
        _verifiers[account] = verifier_;
        emit ERC7579ZKEmailValidatorVerifierSet(account, address(verifier_));
    }

    function _setAccountSalt(address account, bytes32 accountSalt_) internal virtual {
        _accountSalts[account] = accountSalt_;
        emit ERC7579ZKEmailValidatorAccountSaltSet(account, accountSalt_);
    }

    function _decodeInitData(
        bytes calldata data
    ) internal pure virtual returns (IDKIMRegistry registry_, IGroth16Verifier verifier_, bytes32 accountSalt_) {
        // Minimun length: registry(32 bytes) + verifier(32 bytes) + accountSalt(32 bytes) = 96 bytes
        require(data.length >= 96, ERC7579ZKEmailValidatorInvalidInitData());
        return (
            IDKIMRegistry(address(bytes20(data[:20]))),
            IGroth16Verifier(address(bytes20(data[20:40]))),
            bytes32(data[40:])
        );
    }

    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bool decodeSuccess, EmailProof calldata emailProof) = ZKEmailUtils.tryDecodeEmailProof(signature);
        return (decodeSuccess &&
            emailProof.accountSalt == accountSalt(account) &&
            emailProof.isValidZKEmail(dkimRegistry(account), verifier(account), hash) ==
            ZKEmailUtils.EmailProofError.NoError);
    }
}
