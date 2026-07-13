import { Address, concat, Hex, keccak256, toBytes } from 'viem';

export const erc1967ProxyCode = (implementation: Address): Hex =>
  concat([
    '0x60395f8160475f3973',
    implementation,
    '0x807f',
    keccak256(toBytes('Upgraded(address)')), // topic0 for the ERC-1967 Upgraded event that upstream ERC1967Clones emits at deployment.
    '0x5f5fa260095155f3365f5f375f5f365f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d5f5f3e5f3d91603757fd5bf3',
  ]);
