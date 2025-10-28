const { ethers } = require('ethers');

const Enum = (...options) => Object.fromEntries(options.map((key, i) => [key, BigInt(i)]));
const EnumTyped = (...options) => Object.fromEntries(options.map((key, i) => [key, ethers.Typed.uint8(i)]));

module.exports = {
  Enum,
  EnumTyped,
  ERC7579OperationState: Enum('Unknown', 'Scheduled', 'Ready', 'Expired', 'Executed', 'Canceled'),
};
