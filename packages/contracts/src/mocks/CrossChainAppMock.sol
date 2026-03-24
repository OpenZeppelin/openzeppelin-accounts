// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {CrossChainSignatureChecker} from "../utils/CrossChainSignatureChecker.sol";

contract CrossChainAppMock is EIP712 {
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

    constructor(string memory name, string memory version) EIP712(name, version) {}

    function value(address account) public view returns (uint256) {
        return _values[account];
    }

    function setValue(address account, uint256 value_, bytes memory signature) public {
        require(
            account.isValidCrossChainSignatureNow(_structHash(value_), signature, _crossChainStructHash),
            "Invalid signature"
        );
        _setValue(account, value_);
    }

    function setValueCalldata(address account, uint256 value_, bytes calldata signature) public {
        require(
            account.isValidCrossChainSignatureNowCalldata(_structHash(value_), signature, _crossChainStructHash),
            "Invalid signature"
        );
        _setValue(account, value_);
    }

    function _setValue(address account, uint256 value_) public {
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
