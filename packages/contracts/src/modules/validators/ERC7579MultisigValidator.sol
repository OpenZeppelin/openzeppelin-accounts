// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {ERC7579Multisig} from "../ERC7579Multisig.sol";
import {Multisig} from "../../utils/Multisig.sol";

/**
 * @dev Implementation of {ERC7579Validator} that uses {ERC7579Multisig} for multisignature validation.
 */
abstract contract ERC7579MultisigValidator is ERC7579Multisig, ERC7579Validator {
    /**
     * @dev Returns whether the number of valid signatures meets or exceeds the
     * threshold set for the target account.
     *
     * See {_decodeValidationSignature} for the encoding details.
     *
     * Where `signingSigners` are the authorized signers and signatures are their corresponding
     * signatures of the operation `hash`.
     */
    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        (bytes[] calldata signingSigners, bytes[] calldata signatures) = Multisig.decodeMultisignatureCalldata(
            signature
        );
        return _validateMultisig(account, hash, signingSigners, signatures);
    }
}
