// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";

library ERC1967Clones {
    /**
     * @dev Clones a deterministic ERC1967 proxy with `implementation` and `salt`.
     * Forwards `value` native value (ETH) during clonement and returns the instance address.
     *
     * IMPORTANT: The ERC1967 clone is not initialized since it doesn't rely on a constructor.
     * It is assumed that factories using this library will initialize the clone after clonement.
     *
     * NOTE: This function does not emit an {IERC1967-Upgraded} event to minimize the clone size.
     * Instead, the `implementation` contract must emit the event itself during initialization
     * to notify about the storage slot change to remain compliant with ERC-1967.
     */
    function cloneDeterministicERC1967(
        address implementation,
        bytes32 salt,
        uint256 value
    ) internal returns (address instance) {
        assembly ("memory-safe") {
            // offset | bytecode    | opcode        | stack
            // -------|-------------|---------------|---------------------------------
            // :: creation code (34 bytes)
            // 0x0000 | 60<runSize> | PUSH1 runSize | <runSize>
            // 0x0003 | 5f          | PUSH0         | 0 <runSize>
            // 0x0004 | 81          | DUP2          | <runSize> 0 <runSize>
            // 0x0005 | 60<offset>  | PUSH1 offset  | <offset> <runSize> 0 <runSize>
            // 0x0007 | 5f          | PUSH0         | 0 <offset> <runSize> 0 <runSize>
            // 0x0008 | 39          | CODECOPY      | 0 <runSize>
            // 0x0009 | 73<impl>    | PUSH20 impl   | impl 0 <runSize>
            // 0x001d | 60<slotPos> | PUSH1 slotPos | slotPos impl 0 <runSize>
            // 0x001f | 51          | MLOAD         | slot impl 0 <runSize>
            // 0x0020 | 55          | SSTORE        | 0 <runSize>
            // 0x0021 | f3          | RETURN        | <runSize>
            // :: runtime code (57 bytes)
            // :::: copy calldata to memory
            // 0x0000 | 36         | CALLDATASIZE   | <cds>
            // 0x0001 | 5f         | PUSH0          | 0 <cds>
            // 0x0002 | 5f         | PUSH0          | 0 0 <cds>
            // 0x0003 | 37         | CALLDATACOPY   |
            // :::: delegatecall to implementation
            // 0x0004 | 5f         | PUSH0          | 0
            // 0x0005 | 5f         | PUSH0          | 0 0
            // 0x0006 | 36         | CALLDATASIZE   | <cds> 0 0
            // 0x0007 | 5f         | PUSH0          | 0 <cds> 0 0
            // 0x0008 | 7f<slot>   | PUSH32 slot    | <slot> 0 <cds> 0 0
            // 0x0029 | 54         | SLOAD          | <implementation> 0 <cds> 0 0
            // 0x002a | 5a         | GAS            | <gas> <implementation> 0 <cds> 0 0
            // 0x002b | f4         | DELEGATECALL   | <success>
            // :::: copy returndata to memory
            // 0x002c | 3d         | RETURNDATASIZE | <rds> <success>
            // 0x002d | 5f         | PUSH0          | 0 <rds> <success>
            // 0x002e | 5f         | PUSH0          | 0 0 <rds> <success>
            // 0x002f | 3e         | RETURNDATACOPY | <success>
            // 0x0030 | 5f         | PUSH0          | 0 <success>
            // 0x0031 | 3d         | RETURNDATASIZE | <rds> 0 <success>
            // :::: check delegatecall result
            // 0x0032 | 91         | SWAP2          | <success> 0 <rds>
            // 0x0033 | 60 0x36    | PUSH1 0x36     | <dest> <success> 0 <rds>
            // 0x0035 | 57         | JUMPI          | 0 <rds>
            // :::: delegatecall failed
            // 0x0036 | fd         | REVERT         |
            // :::: delegatecall succeeded
            // 0x0037 | 5b         | JUMPDEST       | 0 <rds>
            // 0x0038 | f3         | RETURN         |
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x60, 0xca3e2076cc3735a920a3ca505d382bbc545af43d5f5f3e5f3d91603757fd5bf3)
            mstore(0x40, 0x60095155f3365f5f375f5f365f7f360894a13ba1a3210667c828492db98d)
            mstore(0x22, implementation)
            mstore(0x0e, 0x60395f8160225f3973) // runtime code size = 0x39 (57 bytes)
            instance := create2(value, 0x25, 0x5b, salt)
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero slot.
        }
        if (instance == address(0)) {
            revert Errors.FailedDeployment();
        }
        return instance;
    }

    /// @dev Clones a deterministic minimal ERC1967 proxy with `implementation` and `salt`.
    function cloneDeterministicERC1967(address implementation, bytes32 salt) internal returns (address) {
        return cloneDeterministicERC1967(implementation, salt, 0);
    }

    /// @dev Returns the initialization code hash of the minimal ERC1967 proxy of `implementation`.
    function ERC1967ProxyCodeHash(address implementation) internal pure returns (bytes32 hash) {
        assembly ("memory-safe") {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x60, 0xca3e2076cc3735a920a3ca505d382bbc545af43d5f5f3e5f3d91603757fd5bf3)
            mstore(0x40, 0x60095155f3365f5f375f5f365f7f360894a13ba1a3210667c828492db98d)
            mstore(0x22, implementation)
            mstore(0x0e, 0x60395f8160225f3973) // runtime code size = 0x39 (57 bytes)
            hash := keccak256(0x25, 0x5b)
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero slot.
        }
        return hash;
    }
}
