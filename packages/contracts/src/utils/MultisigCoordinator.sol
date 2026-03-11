// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IERC7579ModuleConfig, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {Impl} from "@fhevm/solidity/lib/Impl.sol";
import {
    FHE,
    ebool,
    externalEbool,
    euint8,
    externalEuint8,
    euint16,
    externalEuint16,
    euint32,
    externalEuint32,
    euint64,
    externalEuint64,
    euint128,
    externalEuint128,
    euint256,
    externalEuint256,
    eaddress,
    externalEaddress
} from "@fhevm/solidity/lib/FHE.sol";
import {ERC7579Multisig} from "../modules/ERC7579Multisig.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @dev Utility contract that bridges multisig accounts with Fully Homomorphic Encryption (FHE).
 *
 * When a multisig account interacts with a confidential token (e.g. ERC-7984), one signer
 * typically constructs the encrypted input off-chain and packages it with an input proof. The
 * remaining signers cannot independently inspect or reconstruct the encrypted value, they must
 * trust the submitting signer's off-chain preparation.
 *
 * Additionally, Zama's FHE Access Control List (ACL) only supports EOA addresses as decryption
 * recipients; it does not natively support smart-contract multisigs. This means signers that are
 * not EOAs cannot receive decryption rights that their signers can act on.
 *
 * === Solution
 *
 * This contract provides two capabilities:
 *
 * 1. **Encrypted value creation**: Any caller can submit an externally-encrypted FHE value along
 *    with its input proof. The contract verifies the proof and stores ACL permissions so that both
 *    this coordinator and the target account can subsequently use or re-share the handle.
 *    The resulting handle is returned for use in downstream calls (e.g. `confidentialTransferFrom`).
 *
 * 2. **Handle allowance delegation**: Any authorized signer (or the account itself) can grant
 *    ACL permission over an existing encrypted handle to an arbitrary EOA or contract address.
 *    This lets signers individually expose a confidential value to their own EOA for decryption,
 *    without the account contract having to approve anything. Two variants are provided:
 *    {allowHandle} for a permanent grant and {allowHandleTransient} for a transient grant that
 *    only persists for the duration of the current transaction.
 *
 * === Setup
 *
 * This is a standalone contract where multiple accounts can register against a single
 * deployment, each identified by their address. Before using {allowHandle} or
 * {allowHandleTransient}, an account must register its associated {ERC7579Multisig} module by
 * calling {setMultisig} from the account itself (e.g. via a UserOperation's `execute` call).
 *
 * === Signature scheme
 *
 * When an explicit signer and signature are supplied, the signed digest is an EIP-712 typed
 * data hash anchored to the `account`'s own domain separator. The domain is retrieved at
 * call-time via {IERC5267-eip712Domain}, so no additional configuration of this coordinator
 * is needed.
 *
 * NOTE: The `as**` functions do not require prior registration; they grant ACL permissions to
 * any address provided as `account`, regardless of whether a multisig has been configured.
 */
contract MultisigCoordinator {
    using MessageHashUtils for *;

    /// @dev EIP-712 typehash for `AllowHandle` operations (permanent ACL grant).
    bytes32 private constant ALLOW_HANDLE_TYPEHASH =
        keccak256("AllowHandle(address account,bytes32 handle,address to)");

    /// @dev EIP-712 typehash for `AllowHandleTransient` operations (transient ACL grant).
    bytes32 private constant ALLOW_HANDLE_TRANSIENT_TYPEHASH =
        keccak256("AllowHandleTransient(address account,bytes32 handle,address to)");

    /// @dev Emitted when an account updates its associated multisig address.
    event MultisigCoordinatorMultisigSet(address indexed account, address indexed multisig);

    /// @dev The provided signer is not authorized for the account.
    error MultisigCoordinatorInvalidSigner(address account, bytes signer);

    /// @dev The provided signature is not valid for the given signer.
    error MultisigCoordinatorInvalidSignature(address account, bytes signer, bytes signature);

    /// @dev The provided multisig address is the zero address.
    error MultisigCoordinatorInvalidMultisig();

    /// @dev The provided multisig module is not installed in the account.
    error MultisigCoordinatorInvalidMultisigModule();

    mapping(address account => address multisig) private _multisigs;

    /**
     * @dev Returns the address of the {ERC7579Multisig} module associated with `account`.
     * Returns `address(0)` if no multisig has been registered.
     */
    function multisig(address account) public view virtual returns (address) {
        return _multisigs[account];
    }

    /**
     * @dev Registers or updates the {ERC7579Multisig} module address for the calling account.
     *
     * This should be called by the account itself, typically via a UserOperation's `execute` call,
     * so that {allowHandle} can verify signer authority.
     *
     * Requirements:
     *
     * * `multisig_` must not be the zero address.
     */
    function setMultisig(address multisig_) public virtual {
        require(multisig_ != address(0), MultisigCoordinatorInvalidMultisig());
        _multisigs[msg.sender] = multisig_;
        emit MultisigCoordinatorMultisigSet(msg.sender, multisig_);
    }

    /**
     * @dev Verifies an externally-encrypted `ebool` input proof and registers ACL permissions.
     *
     * The proof is validated by {FHE-fromExternal}, after which both this coordinator (`address(this)`)
     * and the target `account` are permanently allowed to use the resulting handle.
     *
     * The returned handle can be passed directly to functions that accept an `ebool`, such as
     * confidential token operations.
     *
     * NOTE: Anyone can call this function for any `account` address. ACL permissions are additive
     * and the caller has no ability to revoke them, so there is no griefing risk.
     */
    function asEbool(address account, externalEbool value, bytes memory inputProof) external returns (ebool) {
        ebool evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint8` externally-encrypted values.
    function asEuint8(address account, externalEuint8 value, bytes memory inputProof) external returns (euint8) {
        euint8 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint16` externally-encrypted values.
    function asEuint16(address account, externalEuint16 value, bytes memory inputProof) external returns (euint16) {
        euint16 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint32` externally-encrypted values.
    function asEuint32(address account, externalEuint32 value, bytes memory inputProof) external returns (euint32) {
        euint32 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint64` externally-encrypted values.
    function asEuint64(address account, externalEuint64 value, bytes memory inputProof) external returns (euint64) {
        euint64 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint128` externally-encrypted values.
    function asEuint128(address account, externalEuint128 value, bytes memory inputProof) external returns (euint128) {
        euint128 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `euint256` externally-encrypted values.
    function asEuint256(address account, externalEuint256 value, bytes memory inputProof) external returns (euint256) {
        euint256 evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /// @dev Same as {asEbool} but for `eaddress` externally-encrypted values.
    function asEaddress(address account, externalEaddress value, bytes memory inputProof) external returns (eaddress) {
        eaddress evalue = FHE.fromExternal(value, inputProof);
        FHE.allowThis(evalue);
        FHE.allow(evalue, account);
        return evalue;
    }

    /**
     * @dev Grants ACL permission over an encrypted `handle` to address `to`.
     *
     * `msg.sender` must be `account` itself or a registered signer EOA. Use the overload
     * when authorizing via an explicit signer and signature (e.g. an ERC-7913 key or an
     *off-chain EIP-712 signature).
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setMultisig}.
     * * `account` must implement {IERC5267}.
     */
    function allowHandle(address account, bytes32 handle, address to) public virtual {
        allowHandle(account, Calldata.emptyBytes(), Calldata.emptyBytes(), handle, to);
    }

    /**
     * @dev Grants a permanent ACL permission over an encrypted `handle` to address `to`, verified
     * against the account's registered {ERC7579Multisig}.
     *
     * See {_validateAccess} for the full authorization rules and {_getTypedHash} for the
     * {ALLOW_HANDLE_TYPEHASH} typed data hash.
     *
     * Once authorization is confirmed, the `handle` is permanently allowed to `to` via the FHE
     * ACL. This enables `to` (typically an EOA) to request off-chain decryption of the value.
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setMultisig} and installed as a validator.
     * * `account` must implement {IERC5267}.
     */
    function allowHandle(
        address account,
        bytes calldata signer,
        bytes calldata signature,
        bytes32 handle,
        address to
    ) public virtual {
        _validateAccess(account, signer, signature, _getTypedHash(ALLOW_HANDLE_TYPEHASH, account, handle, to));
        Impl.allow(handle, to);
    }

    /**
     * @dev Grants a transient ACL permission over an encrypted `handle` to address `to`.
     *
     * `msg.sender` must be `account` itself or a registered signer EOA. Use the overload
     * when authorizing via an explicit signer and signature (e.g. an ERC-7913 key or an
     * off-chain EIP-712 signature).
     *
     * Unlike {allowHandle}, the permission granted here only persists for the duration of the
     * current transaction; it is not recorded permanently in the FHE ACL.
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setMultisig} and installed as a validator.
     * * `account` must implement {IERC5267}.
     */
    function allowHandleTransient(address account, bytes32 handle, address to) public virtual {
        _validateAccess(
            account,
            Calldata.emptyBytes(),
            Calldata.emptyBytes(),
            _getTypedHash(ALLOW_HANDLE_TRANSIENT_TYPEHASH, account, handle, to)
        );
        Impl.allowTransient(handle, to);
    }

    /**
     * @dev Grants a transient ACL permission over an encrypted `handle` to address `to`, verified
     * against the account's registered {ERC7579Multisig}.
     *
     * See {_validateAccess} for the full authorization rules and {_getTypedHash} for the
     * {ALLOW_HANDLE_TRANSIENT_TYPEHASH} typed data hash.
     *
     * Unlike {allowHandle}, the permission granted here only persists for the duration of the
     * current transaction; it is not recorded permanently in the FHE ACL.
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setMultisig} and installed as a validator.
     * * `account` must implement {IERC5267}.
     */
    function allowHandleTransient(
        address account,
        bytes calldata signer,
        bytes calldata signature,
        bytes32 handle,
        address to
    ) public virtual {
        _validateAccess(
            account,
            signer,
            signature,
            _getTypedHash(ALLOW_HANDLE_TRANSIENT_TYPEHASH, account, handle, to)
        );
        Impl.allowTransient(handle, to);
    }

    /**
     * @dev Validates that `signer` is authorized to act for `account` over the given `hash`.
     *
     * First confirms that the registered multisig module is actually installed as a validator on
     * the account (via {IERC7579ModuleConfig-isModuleInstalled}), then applies the following
     * authorization rules:
     *
     * - If `signer` is empty: `msg.sender` must be `account` itself or a registered signer EOA.
     * - If `signer` is exactly 20 bytes: treated as an EOA; must be a registered signer and
     *   `signature` must be a valid EIP-712 signature over `hash`.
     * - If `signer` is more than 20 bytes: treated as an ERC-7913 signer (`verifier || key`);
     *   must be a registered signer and `signature` is forwarded to the verifier via
     *   {IERC7913SignatureVerifier-verify}.
     */
    function _validateAccess(
        address account,
        bytes calldata signer,
        bytes calldata signature,
        bytes32 hash
    ) internal view virtual {
        address multisigModule = multisig(account);
        require(
            IERC7579ModuleConfig(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, multisigModule, ""),
            MultisigCoordinatorInvalidMultisigModule()
        );
        ERC7579Multisig multisig_ = ERC7579Multisig(multisig(account));
        if (signer.length == 0) {
            require(
                msg.sender == account || multisig_.isSigner(account, abi.encodePacked(msg.sender)),
                MultisigCoordinatorInvalidSigner(account, signer)
            );
        } else if (signer.length == 20) {
            require(multisig_.isSigner(account, signer), MultisigCoordinatorInvalidSigner(account, signer));
            require(
                SignatureChecker.isValidSignatureNow(address(bytes20(signer)), hash, signature),
                MultisigCoordinatorInvalidSignature(account, signer, signature)
            );
        } else if (signer.length > 20) {
            require(multisig_.isSigner(account, signer), MultisigCoordinatorInvalidSigner(account, signer));
            (bool success, bytes memory result) = address(bytes20(signer)).staticcall(
                abi.encodeCall(IERC7913SignatureVerifier.verify, (signer[20:], hash, signature))
            );
            require(
                success &&
                    result.length >= 32 &&
                    abi.decode(result, (bytes32)) == bytes32(IERC7913SignatureVerifier.verify.selector),
                MultisigCoordinatorInvalidSignature(account, signer, signature)
            );
        } else {
            revert MultisigCoordinatorInvalidSigner(account, signer);
        }
    }

    /**
     * @dev Generates the EIP-712 typed data hash for an operation using the `typehash` and the
     * `account`'s domain separator.
     *
     * The typed data structure includes:
     *
     * * `account`: The account address
     * * `handle`: The encrypted handle
     * * `to`: The address to grant ACL permission to
     *
     * Requirements:
     *
     * * The `account` must implement {IERC5267}.
     */
    function _getTypedHash(
        bytes32 typehash,
        address account,
        bytes32 handle,
        address to
    ) private view returns (bytes32) {
        bytes1 fields;
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;
        bytes32 domainSalt;
        (fields, name, version, chainId, verifyingContract, domainSalt, ) = IERC5267(account).eip712Domain();
        return
            fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt).toTypedDataHash(
                keccak256(abi.encode(typehash, account, handle, to))
            );
    }
}
