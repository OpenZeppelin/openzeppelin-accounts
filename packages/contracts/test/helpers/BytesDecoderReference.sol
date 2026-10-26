// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @dev Reference decoder for an ABI-encoded `bytes` argument inside a buffer, used to check the
 * production decoders in tests. It applies the original bounds rules with overflow-checked math,
 * treating any overflow as an invalid encoding.
 *
 * The offset word is read at `offsetPos` and is relative to `base`. The length word is read at
 * `base + offset` and the data follows it.
 */
library BytesDecoderReference {
    function tryDecode(
        bytes memory buffer,
        uint256 offsetPos,
        uint256 base
    ) internal pure returns (bool success, bytes memory data) {
        if (offsetPos + 0x20 > buffer.length) return (false, "");
        (bool ok1, uint256 lengthPos) = Math.tryAdd(base, readWord(buffer, offsetPos));
        (bool ok2, uint256 dataStart) = Math.tryAdd(lengthPos, 0x20);
        if (!ok1 || !ok2 || dataStart > buffer.length) return (false, "");
        (bool ok3, uint256 dataEnd) = Math.tryAdd(dataStart, readWord(buffer, lengthPos));
        if (!ok3 || dataEnd > buffer.length) return (false, "");
        return (true, Bytes.slice(buffer, dataStart, dataEnd));
    }

    function readWord(bytes memory buffer, uint256 pos) internal pure returns (uint256 word) {
        assembly ("memory-safe") {
            word := mload(add(add(buffer, 0x20), pos))
        }
    }
}
