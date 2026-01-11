// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {CrossChainSignatureChecker} from "../../../src/utils/CrossChainSignatureChecker.sol";
import {CrossChainAppMock} from "../../../src/mocks/CrossChainAppMock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

contract CrossChainSignatureCheckerTest is Test {
    using MessageHashUtils for *;

    function testSetValueWithCrossChainSignatureCalldata(
        uint256 signerPrivateKey,
        uint256 value,
        uint256 appsCount
    ) public {
        bytes1 fields = 0x03;
        appsCount = bound(appsCount, 2, 10);
        CrossChainAppMock[] memory apps = new CrossChainAppMock[](appsCount);
        for (uint256 i = 0; i < appsCount; i++) {
            apps[i] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        }
        (address signer, bytes memory crossChainSignature, bytes32[] memory operations) = _prepareERC7964Signature(
            fields,
            // secp256k1 order
            bound(signerPrivateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1),
            value,
            apps
        );
        for (uint16 i = 0; i < apps.length; i++) {
            // Shouldn't work with an incorrect struct index
            vm.expectRevert("Invalid signature");
            apps[i].setValueCalldata(
                signer,
                value,
                abi.encode(_encodeERC7964Header(fields, i == 0 ? 1 : 0, apps[i]), operations, crossChainSignature)
            );

            // Should work with the correct struct index
            vm.expectEmit(true, true, true, true);
            emit CrossChainAppMock.ValueSet(signer, value);
            apps[i].setValueCalldata(
                signer,
                value,
                abi.encode(_encodeERC7964Header(fields, i, apps[i]), operations, crossChainSignature)
            );
            assertEq(apps[i].value(signer), value);
        }
    }

    function testSetValueWithCrossChainSignature(uint256 signerPrivateKey, uint256 value, uint256 appsCount) public {
        bytes1 fields = 0x03;
        appsCount = bound(appsCount, 2, 10);
        CrossChainAppMock[] memory apps = new CrossChainAppMock[](appsCount);
        for (uint256 i = 0; i < appsCount; i++) {
            apps[i] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        }
        (address signer, bytes memory crossChainSignature, bytes32[] memory operations) = _prepareERC7964Signature(
            fields,
            // secp256k1 order
            bound(signerPrivateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1),
            value,
            apps
        );

        for (uint16 i = 0; i < apps.length; i++) {
            // Shouldn't work with an incorrect struct index
            vm.expectRevert("Invalid signature");
            apps[i].setValue(
                signer,
                value,
                abi.encode(_encodeERC7964Header(fields, i == 0 ? 1 : 0, apps[i]), operations, crossChainSignature)
            );

            // Should work with the correct struct index
            vm.expectEmit(true, true, true, true);
            emit CrossChainAppMock.ValueSet(signer, value);
            apps[i].setValue(
                signer,
                value,
                abi.encode(_encodeERC7964Header(fields, i, apps[i]), operations, crossChainSignature)
            );
            assertEq(apps[i].value(signer), value);
        }
    }

    function _prepareERC7964Signature(
        bytes1 fields,
        uint256 signerPrivateKey,
        uint256 value,
        CrossChainAppMock[] memory apps
    ) private view returns (address signer, bytes memory crossChainSignature, bytes32[] memory operations) {
        operations = new bytes32[](apps.length);
        for (uint256 i = 0; i < apps.length; i++) {
            operations[i] = keccak256(
                abi.encode(
                    apps[i].CHAIN_OPERATION_TYPEHASH(),
                    keccak256(abi.encode(apps[i].EIP712_CHAIN_DOMAIN_TYPEHASH(), block.chainid, address(apps[i]))),
                    value
                )
            );
        }

        string memory name;
        string memory version;
        (, name, version, , , , ) = IERC5267(address(apps[0])).eip712Domain(); // All apps share the same name and version

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            signerPrivateKey,
            fields.toDomainSeparator(name, version, 0, address(0), bytes32(0)).toTypedDataHash(
                keccak256(abi.encode(apps[0].CROSS_CHAIN_SET_VALUE_TYPEHASH(), keccak256(abi.encodePacked(operations))))
            )
        );

        return (vm.addr(signerPrivateKey), abi.encodePacked(r, s, v), operations);
    }

    function _encodeERC7964Header(
        bytes1 fields,
        uint16 structIndex,
        CrossChainAppMock application
    ) private pure returns (bytes32) {
        return
            CrossChainSignatureChecker.ERC7964_MAGIC |
            (bytes32(fields) >> 72) |
            (bytes32(bytes2(structIndex)) >> 80) |
            (bytes32(bytes20(address(application))) >> 96);
    }
}
