// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {IERC7579ModuleConfig, MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {Impl} from "@fhevm/solidity/lib/Impl.sol";
import {ERC7579Multisig} from "../modules/ERC7579Multisig.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {FheType} from "@fhevm/solidity/lib/FheType.sol";

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
 * 2. **Handle allowance granting**: Any authorized signer (or the account itself) can grant
 *    ACL permission over an existing encrypted handle to an arbitrary EOA or contract address.
 *    This lets signers individually expose a confidential value to their own EOA for decryption,
 *    without the account contract having to approve anything.
 *
 * === Setup
 *
 * This is an abstract contract. Concrete deployments must also inherit an fhEVM coprocessor
 * configuration. For Zama's fhEVM this is done by inheriting `ZamaEthereumConfig` from the
 * https://github.com/zama-ai/fhevm/tree/main/library-solidity[FHEVM Solidity package] alongside
 * this contract:
 *
 * ```solidity
 * contract MyMultisigCoordinator is MultisigCoordinator, ZamaEthereumConfig {}
 * ```
 *
 * A single deployment can serve multiple accounts: each account is identified by its address.
 * Before using {allowHandle}, an account must register its associated
 * {ERC7579Multisig} module by calling {setERC7579Multisig} from the account itself (e.g. via a
 * UserOperation's `execute` call).
 *
 * === Signature scheme
 *
 * When an explicit signer and signature are supplied, the signed digest is an EIP-712 typed
 * data hash anchored to the `account`'s own domain separator. The domain is retrieved at
 * call-time via {IERC5267-eip712Domain}, so no additional configuration of this coordinator
 * is needed.
 *
 * NOTE: {fromExternal} does not require prior registration; it grants ACL permissions to
 * any address provided as `account`, regardless of whether a multisig has been configured.
 */
abstract contract MultisigCoordinator {
    using MessageHashUtils for *;

    /// @dev EIP-712 typehash for {allowHandle} operations.
    bytes32 private constant ALLOW_HANDLE_TYPEHASH =
        keccak256("AllowHandle(address account,bytes32 handle,address to)");

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

    /// @dev The provided account is not allowed to use the handle.
    error MultisigCoordinatorAccountNotAllowedToUseHandle(bytes32 handle, address account);

    mapping(address account => address multisig) private _multisigs;

    /**
     * @dev Returns the address of the {ERC7579Multisig} module associated with `account`.
     * Returns `address(0)` if no multisig has been registered.
     */
    function erc7579Multisig(address account) public view virtual returns (address) {
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
    function setERC7579Multisig(address multisig_) public virtual {
        require(multisig_ != address(0), MultisigCoordinatorInvalidMultisig());
        _multisigs[msg.sender] = multisig_;
        emit MultisigCoordinatorMultisigSet(msg.sender, multisig_);
    }

    /**
     * @dev Verifies an externally-encrypted handle input proof and registers ACL permissions.
     *
     * The proof is validated by {FHE-fromExternal}, after which both this coordinator (`address(this)`)
     * and the target `account` are permanently allowed to use the resulting handle.
     *
     * The returned handle can be cast to the appropriate type using with `ebool.wrap(externalHandle)`
     * for `ebool`, `eaddress.wrap(externalHandle)` for `eaddress`, `euint8.wrap(externalHandle)` for
     * `euint8` and so on.
     *
     * NOTE: Anyone can call this function for any `account` address. ACL permissions are additive
     * and the caller has no ability to revoke them, so there is no griefing risk.
     */
    function fromExternal(
        address account,
        bytes32 externalHandle,
        bytes memory inputProof,
        FheType fheType
    ) public virtual returns (bytes32) {
        return _fromExternal(account, externalHandle, inputProof, fheType);
    }

    /// @dev Internal version of {fromExternal}
    function _fromExternal(
        address account,
        bytes32 externalHandle,
        bytes memory inputProof,
        FheType fheType
    ) internal virtual returns (bytes32 handle) {
        if (inputProof.length != 0) {
            handle = Impl.verify(externalHandle, inputProof, fheType);
        } else {
            require(
                externalHandle != 0 && Impl.isAllowed(externalHandle, msg.sender),
                MultisigCoordinatorAccountNotAllowedToUseHandle(externalHandle, msg.sender)
            );
            handle = externalHandle;
        }
        Impl.allow(handle, address(this));
        Impl.allow(handle, account);
        return handle;
    }

    /**
     * @dev Grants ACL permission over an encrypted `handle` to address `to`.
     *
     * `msg.sender` must be `account` itself or a registered signer EOA.
     * See {allowHandle-address-bytes-bytes-bytes32-address-} for the full authorization
     * rules and requirements.
     */
    function allowHandle(address account, bytes32 handle, address to) public virtual {
        allowHandle(account, Calldata.emptyBytes(), Calldata.emptyBytes(), handle, to);
    }

    /**
     * @dev Grants a permanent ACL permission over an encrypted `handle` to address `to`, verified
     * against the account's registered {ERC7579Multisig}.
     *
     * See {_validateAccess} for the full authorization rules.
     *
     * Once authorization is confirmed, the `handle` is permanently allowed to `to` via the FHE
     * ACL. This enables `to` (typically an EOA) to request off-chain decryption of the value.
     *
     * WARNING: This grant is permanent and irrevocable. If `to` is later removed from the
     * multisig, they will still be able to decrypt any handle they were previously allowed. To
     * remove a former signer's access, re-encrypt the sensitive values using fresh FHE inputs
     * and grant access only to current signers.
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setERC7579Multisig} and installed as a validator.
     * * `account` must implement {IERC5267}.
     * * The EIP-712 domain returned by `account` must not set the extensions flag (bit `0x20` of `fields`),
     */
    function allowHandle(
        address account,
        bytes calldata signer,
        bytes calldata signature,
        bytes32 handle,
        address to
    ) public virtual {
        bytes1 fields;
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;
        bytes32 domainSalt;
        (fields, name, version, chainId, verifyingContract, domainSalt, ) = IERC5267(account).eip712Domain();
        bytes32 hash = fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt).toTypedDataHash(
            keccak256(abi.encode(ALLOW_HANDLE_TYPEHASH, account, handle, to))
        );
        _validateAccess(account, signer, signature, hash);
        require(Impl.isAllowed(handle, account), MultisigCoordinatorAccountNotAllowedToUseHandle(handle, account));
        Impl.allow(handle, to);
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
     *
     * NOTE: Existing FHE ACL permissions (`FHE.isAllowed`) are intentionally not checked here.
     * Authorization is strictly tied to the account's multisig membership. Callers that already
     * hold ACL access to a handle and wish to extend it to another address can do so directly via
     * the FHE ACL (e.g. `FHE.allow`) without involving this coordinator.
     *
     * Requirements:
     *
     * * `account` must have a multisig registered via {setERC7579Multisig} and installed as a validator.
     */
    function _validateAccess(
        address account,
        bytes calldata signer,
        bytes calldata signature,
        bytes32 hash
    ) internal view virtual {
        address multisigModule = erc7579Multisig(account);
        require(
            multisigModule != address(0) &&
                IERC7579ModuleConfig(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, multisigModule, ""),
            MultisigCoordinatorInvalidMultisigModule()
        );
        ERC7579Multisig multisig_ = ERC7579Multisig(multisigModule);
        if (signer.length == 0) {
            require(
                msg.sender == account || multisig_.isSigner(account, abi.encodePacked(msg.sender)),
                MultisigCoordinatorInvalidSigner(account, signer)
            );
        } else if (signer.length == 20) {
            require(multisig_.isSigner(account, signer), MultisigCoordinatorInvalidSigner(account, signer));
            require(
                // forge-lint: disable-next-line(unsafe-typecast)
                SignatureChecker.isValidSignatureNow(address(bytes20(signer)), hash, signature),
                MultisigCoordinatorInvalidSignature(account, signer, signature)
            );
        } else if (signer.length > 20) {
            require(multisig_.isSigner(account, signer), MultisigCoordinatorInvalidSigner(account, signer));
            // forge-lint: disable-next-line(unsafe-typecast)
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
}
