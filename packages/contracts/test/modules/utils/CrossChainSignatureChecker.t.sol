// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {CrossChainSignatureChecker} from "../../../src/utils/CrossChainSignatureChecker.sol";
import {CrossChainAppMock} from "../../../src/mocks/CrossChainAppMock.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/// @dev ERC-5267 application that reports arbitrary `fields`.
contract ERC5267FieldsMock is IERC5267 {
    bytes1 private immutable _fields;

    constructor(bytes1 fields_) {
        _fields = fields_;
    }

    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (_fields, "CrossChainAppMock", "1.0.0", block.chainid, address(this), bytes32(0), new uint256[](0));
    }
}

contract CrossChainSignatureCheckerTest is Test {
    using MessageHashUtils for *;

    /// @dev External function to construct the calldata for the tryParseCrossChainSignature function.
    function tryParseCrossChainSignature(
        bytes memory erc7964Signature
    )
        external
        pure
        returns (
            bool success,
            uint16 structIndex,
            address application,
            bytes32[] memory structsArray,
            bytes memory crossChainSignature
        )
    {
        return CrossChainSignatureChecker.tryParseCrossChainSignature(erc7964Signature);
    }

    /// @dev External function to construct the calldata for the tryParseCrossChainSignatureCalldata function.
    function tryParseCrossChainSignatureCalldata(
        bytes calldata erc7964Signature
    )
        external
        pure
        returns (
            bool success,
            uint16 structIndex,
            address application,
            bytes32[] memory structsArray,
            bytes memory crossChainSignature
        )
    {
        return CrossChainSignatureChecker.tryParseCrossChainSignatureCalldata(erc7964Signature);
    }

    function testParseCrossChainSignature(
        uint16 structIndex,
        address application,
        bytes32[] memory structsArray,
        bytes memory crossChainSignature
    ) public view {
        (
            bool success,
            uint16 decodedStructIndex,
            address decodedApplication,
            bytes32[] memory decodedStructsArray,
            bytes memory decodedCrossChainSignature
        ) = this.tryParseCrossChainSignature(
                abi.encode(
                    bytes32(abi.encodePacked(CrossChainSignatureChecker.ERC7964_MAGIC, structIndex, application)),
                    structsArray,
                    crossChainSignature
                )
            );
        assertTrue(success);
        assertEq(structIndex, decodedStructIndex);
        assertEq(application, decodedApplication);
        assertEq(structsArray, decodedStructsArray);
        assertEq(crossChainSignature, decodedCrossChainSignature);
    }

    /// @dev Parsing never reverts, the memory and calldata variants agree, and a failed parse returns empty values.
    function testParseCrossChainSignatureArbitraryData(bytes memory data) public view {
        (
            bool success,
            uint16 structIndex,
            address application,
            bytes32[] memory structsArray,
            bytes memory crossChainSignature
        ) = this.tryParseCrossChainSignature(data);
        (
            bool successCalldata,
            uint16 structIndexCalldata,
            address applicationCalldata,
            bytes32[] memory structsArrayCalldata,
            bytes memory crossChainSignatureCalldata
        ) = this.tryParseCrossChainSignatureCalldata(data);
        assertEq(success, successCalldata);
        assertEq(structIndex, structIndexCalldata);
        assertEq(application, applicationCalldata);
        assertEq(structsArray, structsArrayCalldata);
        assertEq(crossChainSignature, crossChainSignatureCalldata);

        if (!success) {
            assertEq(structIndex, 0);
            assertEq(application, address(0));
            assertEq(structsArray.length, 0);
            assertEq(crossChainSignature.length, 0);
        }
    }

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
                abi.encode(_encodeERC7964Header(i == 0 ? 1 : 0, apps[i]), operations, crossChainSignature)
            );

            // Should work with the correct struct index
            vm.expectEmit(true, true, true, true);
            emit CrossChainAppMock.ValueSet(signer, value);
            apps[i].setValueCalldata(
                signer,
                value,
                abi.encode(_encodeERC7964Header(i, apps[i]), operations, crossChainSignature)
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
                abi.encode(_encodeERC7964Header(i == 0 ? 1 : 0, apps[i]), operations, crossChainSignature)
            );

            // Should work with the correct struct index
            vm.expectEmit(true, true, true, true);
            emit CrossChainAppMock.ValueSet(signer, value);
            apps[i].setValue(
                signer,
                value,
                abi.encode(_encodeERC7964Header(i, apps[i]), operations, crossChainSignature)
            );
            assertEq(apps[i].value(signer), value);
        }
    }

    /// @dev Parsing never reverts with arbitrary offsets and lengths, and succeeds iff they are within bounds.
    function testParseCrossChainSignatureMalformedOffsets(
        uint256 structsArrayOffset,
        uint256 structsArrayLength,
        uint256 crossChainSignatureOffset,
        uint256 crossChainSignatureLength,
        uint8 tailWords,
        uint8 variant
    ) public view {
        // Pick small values (in bounds or near bounds) for half of the runs, and any value otherwise
        if (variant % 2 == 0) {
            structsArrayOffset = bound(structsArrayOffset, 0, 0x200);
            structsArrayLength = bound(structsArrayLength, 0, 0x10);
            crossChainSignatureOffset = bound(crossChainSignatureOffset, 0, 0x400);
            crossChainSignatureLength = bound(crossChainSignatureLength, 0, 0x200);
        }

        bytes memory signature = abi.encodePacked(
            _encodeHeader(0, address(this)),
            structsArrayOffset,
            crossChainSignatureOffset,
            new bytes(uint256(tailWords) * 0x20)
        );
        // Write lengths at their offsets (when they fall within the signature), then read them back since unaligned
        // offsets may overlap
        bool structsArrayInBounds = structsArrayOffset >= 0x60 && structsArrayOffset <= signature.length - 0x20;
        bool crossChainSignatureInBounds = crossChainSignatureOffset >= 0x60 &&
            crossChainSignatureOffset <= signature.length - 0x20;
        if (structsArrayInBounds) _store(signature, structsArrayOffset, structsArrayLength);
        if (crossChainSignatureInBounds) _store(signature, crossChainSignatureOffset, crossChainSignatureLength);
        structsArrayLength = structsArrayInBounds ? _load(signature, structsArrayOffset) : 0;
        crossChainSignatureLength = crossChainSignatureInBounds ? _load(signature, crossChainSignatureOffset) : 0;

        bool expected = signature.length >= 0xa0 &&
            structsArrayInBounds &&
            structsArrayLength <= (signature.length - structsArrayOffset - 0x20) / 0x20 &&
            crossChainSignatureOffset >= structsArrayOffset + 0x20 + structsArrayLength * 0x20 &&
            crossChainSignatureInBounds &&
            crossChainSignatureLength <= signature.length - crossChainSignatureOffset - 0x20;

        (bool success, , address application, bytes32[] memory structsArray, bytes memory crossChainSignature) = this
            .tryParseCrossChainSignature(signature);
        assertEq(success, expected);
        assertEq(application, expected ? address(this) : address(0));
        assertEq(structsArray.length, expected ? structsArrayLength : 0);
        assertEq(crossChainSignature.length, expected ? crossChainSignatureLength : 0);

        (success, , application, structsArray, crossChainSignature) = this.tryParseCrossChainSignatureCalldata(
            signature
        );
        assertEq(success, expected);
        assertEq(application, expected ? address(this) : address(0));
        assertEq(structsArray.length, expected ? structsArrayLength : 0);
        assertEq(crossChainSignature.length, expected ? crossChainSignatureLength : 0);

        // A successful parse matches `abi.decode`
        if (expected) {
            (, bytes32[] memory decodedStructsArray, bytes memory decodedCrossChainSignature) = abi.decode(
                signature,
                (bytes32, bytes32[], bytes)
            );
            assertEq(structsArray, decodedStructsArray);
            assertEq(crossChainSignature, decodedCrossChainSignature);
        }
    }

    function testSetValueWithOutOfBoundsStructIndex(
        uint256 signerPrivateKey,
        uint256 value,
        uint16 structIndex
    ) public {
        CrossChainAppMock[] memory apps = new CrossChainAppMock[](2);
        apps[0] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        apps[1] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        (address signer, bytes memory crossChainSignature, bytes32[] memory operations) = _prepareERC7964Signature(
            0x03,
            // secp256k1 order
            bound(signerPrivateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1),
            value,
            apps
        );
        structIndex = uint16(bound(structIndex, apps.length, type(uint16).max));
        bytes memory signature = abi.encode(_encodeHeader(structIndex, apps[0]), operations, crossChainSignature);

        vm.expectRevert("Invalid signature");
        apps[0].setValue(signer, value, signature);
        vm.expectRevert("Invalid signature");
        apps[0].setValueCalldata(signer, value, signature);
    }

    /// @dev A signature over any main domain other than `applicationFields & ~CHAIN_FIELDS` (0x03) is rejected.
    function testSetValueWithMismatchedMainDomain(uint256 signerPrivateKey, uint256 value, bytes1 fields) public {
        fields = bytes1(uint8(bound(uint8(fields), 0x00, 0x1f)));
        vm.assume(fields != 0x03);
        CrossChainAppMock[] memory apps = new CrossChainAppMock[](2);
        apps[0] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        apps[1] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        (address signer, bytes memory crossChainSignature, bytes32[] memory operations) = _prepareERC7964Signature(
            fields,
            // secp256k1 order
            bound(signerPrivateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1),
            value,
            apps
        );
        bytes memory signature = abi.encode(_encodeHeader(0, apps[0]), operations, crossChainSignature);

        vm.expectRevert("Invalid signature");
        apps[0].setValue(signer, value, signature);
        vm.expectRevert("Invalid signature");
        apps[0].setValueCalldata(signer, value, signature);
    }

    /// @dev An application whose main domain fields set bits beyond ERC-5267 makes verification return false.
    function testSetValueWithUnsupportedApplicationFields(
        uint256 signerPrivateKey,
        uint256 value,
        bytes1 applicationFields
    ) public {
        applicationFields = bytes1(uint8(bound(uint8(applicationFields), 0x20, 0xff)));
        ERC5267FieldsMock application = new ERC5267FieldsMock(applicationFields);
        CrossChainAppMock[] memory apps = new CrossChainAppMock[](2);
        apps[0] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        apps[1] = new CrossChainAppMock("CrossChainAppMock", "1.0.0");
        (address signer, bytes memory crossChainSignature, bytes32[] memory operations) = _prepareERC7964Signature(
            0x03,
            // secp256k1 order
            bound(signerPrivateKey, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 - 1),
            value,
            apps
        );
        bytes memory signature = abi.encode(_encodeHeader(0, address(application)), operations, crossChainSignature);

        vm.expectRevert("Invalid signature");
        apps[0].setValue(signer, value, signature);
        vm.expectRevert("Invalid signature");
        apps[0].setValueCalldata(signer, value, signature);
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
        bytes32 domainSeparator = fields.toDomainSeparator(name, version, block.chainid, address(apps[0]), bytes32(0));

        bytes32 structHash = keccak256(
            abi.encode(apps[0].CROSS_CHAIN_SET_VALUE_TYPEHASH(), keccak256(abi.encodePacked(operations)))
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, domainSeparator.toTypedDataHash(structHash));

        return (vm.addr(signerPrivateKey), abi.encodePacked(r, s, v), operations);
    }

    function _encodeHeader(uint16 structIndex, address application) private pure returns (bytes32) {
        return bytes32(abi.encodePacked(CrossChainSignatureChecker.ERC7964_MAGIC, structIndex, application));
    }

    function _encodeHeader(uint16 structIndex, CrossChainAppMock application) private pure returns (bytes32) {
        return _encodeHeader(structIndex, address(application));
    }

    function _store(bytes memory buffer, uint256 offset, uint256 value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), offset), value)
        }
    }

    function _load(bytes memory buffer, uint256 offset) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := mload(add(add(buffer, 0x20), offset))
        }
    }

    function _encodeERC7964Header(uint16 structIndex, CrossChainAppMock application) private pure returns (bytes32) {
        return
            CrossChainSignatureChecker.ERC7964_MAGIC |
            (bytes32(bytes2(structIndex)) >> 80) |
            (bytes32(bytes20(address(application))) >> 96);
    }
}
