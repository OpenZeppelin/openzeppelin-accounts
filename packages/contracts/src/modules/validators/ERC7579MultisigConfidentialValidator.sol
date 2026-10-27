// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579MultisigConfidential} from "../ERC7579MultisigConfidential.sol";
import {FHE, ebool} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @dev Implementation of {ERC7579Validator} that uses {ERC7579MultisigConfidential}
 * for confidential multisignature validation of user operations (see ERC-4337).
 *
 * This extension bypasses the explicit {ERC7579MultisigConfidential-discloseOperation} call
 * and performs disclosure implicitly inside `_rawERC7579Validation`: when the user op
 * signature includes a valid FHE decryption proof for the multisig result (relayer address
 * plus proof after the first 20 bytes), the validator accepts the user op without requiring
 * a prior call to `discloseOperation`. This reduces the flow to two steps:
 *
 * 1. Call {ERC7579MultisigConfidential-requestDiscloseOperation} to validate the multisig
 *    and make the encrypted result publicly decryptable.
 * 2. Submit the user operation to the entrypoint with the decryption proof in the signature;
 *    the entrypoint calls `validateUserOp`, which invokes `_rawERC7579Validation` to verify
 *    the proof (or that the operation was explicitly disclosed via {disclosed}).
 *
 * > [!NOTE]
 * > The operation is not marked as disclosed in storage when validation succeeds via the
 * > inline proof. That is intentional: the fact that the user op executed implies the
 * > multisig was valid and effectively disclosed, and offchain indexers can infer it by
 * > watching entrypoint events instead of relying on the {disclosed} boolean.
 *
 * > [!NOTE]
 * > By definition, the user operation is public in the bundler mempool the moment it's
 * > submitted. Users must not assume that the user operation is confidential, and should consider
 * > front running risks associated with the user operation payload.
 */
contract ERC7579MultisigConfidentialValidator is ERC7579MultisigConfidential, ERC7579Validator {
    /**
     * @dev Validates the operation by either verifying an inline FHE decryption proof
     * in the signature (relayer address in the first 20 bytes, proof thereafter) or by
     * checking {disclosed}. Does not call {ERC7579MultisigConfidential-discloseOperation}
     * or set the disclosed flag when the proof is valid; disclosure is implicit in execution.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        // Minimum length: address(20) + offset(32) + length(32) = 84 bytes
        if (signature.length < 84) return disclosed(account, hash); // Fallback to public disclosure if the signature is too short
        if (disclosed(account, hash)) return true; // Checked first since a malformed proof reverts instead of returning false

        ebool valid = requestedDisclosure(address(bytes20(signature[:20])), account, hash);
        bytes32[] memory handles = new bytes32[](1);
        handles[0] = FHE.toBytes32(valid);

        return FHE.isInitialized(valid) && FHE.isPublicDecryptionResultValid(handles, abi.encode(true), signature[20:]);
    }
}
