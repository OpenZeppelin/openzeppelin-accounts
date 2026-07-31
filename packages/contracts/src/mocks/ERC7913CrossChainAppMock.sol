// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {CrossChainSignatureChecker} from "../utils/CrossChainSignatureChecker.sol";

/**
 * @dev Composition mock for the Accounts SDK signer abstraction.
 *
 * Accepts a signature whose outer envelope is ERC-7913 (`abi.encode(bytes signer, bytes rawSig)`)
 * and whose inner `rawSig` is an ERC-7964 cross-chain envelope. This exercises the SDK path
 * `toERC7913Signer(toCrossChainSigner(inner, ...), { address })` end-to-end: the outer
 * envelope is peeled by this contract, and the inner cross-chain payload is verified via
 * {CrossChainSignatureChecker}.
 *
 * The verifier-less shortcut is used — `signer` is required to be a 20-byte address, which
 * is passed directly to {CrossChainSignatureChecker-isValidCrossChainSignatureNow}. Other
 * ERC-7913 shapes (verifier + key) would require calling the verifier contract; that's out
 * of scope for this mock.
 */
contract ERC7913CrossChainAppMock is EIP712 {
    using CrossChainSignatureChecker for address;

    event ValueSet(address indexed account, uint256 value);

    mapping(address account => uint256) private _values;

    bytes private constant _EIP712_CHAIN_DOMAIN_TYPE = "EIP712ChainDomain(uint256 chainId,address verifyingContract)";
    bytes private constant _CHAIN_OPERATION_TYPE = "ChainOperation(EIP712ChainDomain domain,uint256 value)";
    bytes private constant _CROSS_CHAIN_SET_VALUE_TYPE = "SetValue(ChainOperation[] operations)";

    bytes32 public constant EIP712_CHAIN_DOMAIN_TYPEHASH = keccak256(_EIP712_CHAIN_DOMAIN_TYPE);
    bytes32 public constant CHAIN_OPERATION_TYPEHASH =
        keccak256(abi.encodePacked(_CHAIN_OPERATION_TYPE, _EIP712_CHAIN_DOMAIN_TYPE));
    bytes32 public constant CROSS_CHAIN_SET_VALUE_TYPEHASH =
        keccak256(abi.encodePacked(_CROSS_CHAIN_SET_VALUE_TYPE, _CHAIN_OPERATION_TYPE, _EIP712_CHAIN_DOMAIN_TYPE));

    error ERC7913SignerNotVerifierLess();

    constructor(string memory name, string memory version) EIP712(name, version) {}

    function value(address account) public view returns (uint256) {
        return _values[account];
    }

    function setValue(uint256 value_, bytes memory composedSignature) public {
        (bytes memory signer, bytes memory crossChainEnvelope) = abi.decode(composedSignature, (bytes, bytes));
        require(signer.length == 20, ERC7913SignerNotVerifierLess());
        address account = address(bytes20(signer));

        require(
            account.isValidCrossChainSignatureNow(_structHash(value_), crossChainEnvelope, _crossChainStructHash),
            "Invalid signature"
        );

        _values[account] = value_;
        emit ValueSet(account, value_);
    }

    function _crossChainStructHash(bytes32 operationsHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(CROSS_CHAIN_SET_VALUE_TYPEHASH, operationsHash));
    }

    function _structHash(uint256 value_) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CHAIN_OPERATION_TYPEHASH,
                    keccak256(abi.encode(EIP712_CHAIN_DOMAIN_TYPEHASH, block.chainid, address(this))),
                    value_
                )
            );
    }
}
