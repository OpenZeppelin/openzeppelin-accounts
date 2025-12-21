// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Multisig} from "../../src/utils/Multisig.sol";

contract MultisigTest is Test {
    /// @dev External function to construct the calldata for the tryDecodeMultisignatureCalldata function.
    function tryDecodeMultisignatureCalldata(
        bytes calldata multisignature
    ) external pure returns (bool success, bytes[] calldata signingSigners, bytes[] calldata signatures) {
        return Multisig.tryDecodeMultisignatureCalldata(multisignature);
    }

    /// @dev External function to decode the multisignature data in memory with try-catch.
    function decodeMultisignature(
        bytes calldata multisignature
    ) external pure returns (bytes[] memory signingSigners, bytes[] memory signatures) {
        return abi.decode(multisignature, (bytes[], bytes[]));
    }

    function testTryDecodeMultisignatureCalldata(bytes[] memory signingSigners, bytes[] memory signatures) public view {
        (bool success, bytes[] memory decodedSigningSigners, bytes[] memory decodedSignatures) = this
            .tryDecodeMultisignatureCalldata(abi.encode(signingSigners, signatures));
        assertTrue(success);
        assertEq(decodedSigningSigners, signingSigners);
        assertEq(decodedSignatures, signatures);
    }

    function testTryDecodeMultisignatureCalldataArbitraryData(bytes memory data) public view {
        (bool success, bytes[] memory tryDecodedSigningSigners, bytes[] memory tryDecodedSignatures) = this
            .tryDecodeMultisignatureCalldata(data);
        try this.decodeMultisignature(data) returns (
            bytes[] memory decodedSigningSigners,
            bytes[] memory decodedSignatures
        ) {
            assertTrue(success);
            assertEq(tryDecodedSigningSigners, decodedSigningSigners);
            assertEq(tryDecodedSignatures, decodedSignatures);
        } catch {
            assertFalse(success);
            assertEq(tryDecodedSigningSigners.length, 0);
            assertEq(tryDecodedSignatures.length, 0);
        }
    }
}
