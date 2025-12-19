// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC7579Validator} from "./ERC7579Validator.sol";
import {CrossChainSignatureChecker} from "../../utils/CrossChainSignatureChecker.sol";

abstract contract ERC7579CrossChainValidator is ERC7579Validator {
    using CrossChainSignatureChecker for *;

    bytes32 private constant CROSS_CHAIN_OPERATIONS_TYPEHASH =
        keccak256(
            "EIP712ChainDomain(uint256 chainId,address verifyingContract)"
        );

    function _rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        return account.isValidCrossChainSignatureNow(hash, signature, structHash);
    }

    function structHash(bytes32[] memory structsArray) internal view virtual returns (bytes32) {
        return keccak256(abi.encode(CROSS_CHAIN_OPERATIONS_TYPEHASH, keccak256(abi.encodePacked(structsArray))));
    }
}
