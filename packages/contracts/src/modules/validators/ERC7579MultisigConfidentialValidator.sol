// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579MultisigConfidential} from "../ERC7579MultisigConfidential.sol";

/**
 * @dev Implementation of {ERC7579Validator} that uses {ERC7579MultisigConfidential}
 * for confidential multisignature validation of user operations (see ERC-4337).
 *
 * Requesting disclosure and disclosing the multisig result are implemented in the base
 * {ERC7579MultisigConfidential} module. This validator only ties that flow to user op
 * validation: it accepts a user op when the operation hash has already been disclosed.
 *
 * Validating a user operation requires three steps due to FHE's asynchronous decryption model:
 *
 * 1. Call {ERC7579MultisigConfidential-requestDiscloseOperation} to validate the multisig
 *    and make the encrypted result publicly decryptable.
 * 2. Call {ERC7579MultisigConfidential-discloseOperation} to verify the decryption proof
 *    and mark the operation as disclosed.
 * 3. Submit the user operation to the entrypoint; the entrypoint calls `validateUserOp`,
 *    which invokes this validator's `_rawERC7579Validation` to ensure the operation hash
 *    is disclosed (see {disclosed}).
 *
 * NOTE: By definition, the user operation is public in the bundler mempool the moment it's
 * submitted. Users must not assume that the user operation is confidential, and should consider
 * front running risks associated with the user operation payload.
 */
contract ERC7579MultisigConfidentialValidator is ERC7579MultisigConfidential, ERC7579Validator {
    /**
     * @dev Returns whether the operation (hash) has been disclosed via
     * {ERC7579MultisigConfidential-discloseOperation}.
     *
     * The user operation can only be validated after steps 1 and 2 of the three-step
     * flow have been completed for the user op hash.
     */
    function _rawERC7579Validation(
        address /* account */,
        bytes32 hash,
        bytes calldata /* signature */
    ) internal view virtual override returns (bool) {
        return disclosed(hash);
    }
}
