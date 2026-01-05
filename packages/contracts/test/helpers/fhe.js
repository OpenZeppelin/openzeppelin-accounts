const { fhevm, ethers } = require('hardhat');
const ACL_ABI = require('@fhevm/host-contracts/artifacts/contracts/ACL.sol/ACL.json').abi;

const getAclAddress = async () => fhevm.getRelayerMetadata().then(metadata => metadata.ACLAddress);

const allowHandle = async (from, to, handle) =>
  getAclAddress()
    .then(aclAddress => ethers.getContractAt(ACL_ABI, aclAddress))
    .then(aclContract => aclContract.connect(from).allow(handle, to));

module.exports = {
  getAclAddress,
  allowHandle,
};
