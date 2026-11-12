const { ethers } = require('hardhat');

const ERC7964_MAGIC = '0x79647964796479647964';

function encodeERC7964Header(structIndex, application) {
  const magic = ethers.getBytes(ERC7964_MAGIC, 10);
  const structIndexBytes = ethers.zeroPadValue(ethers.toBeHex(structIndex), 2);
  const applicationBytes = ethers.getBytes(application, 20);
  return ethers.concat([magic, structIndexBytes, applicationBytes]);
}

module.exports = {
  encodeERC7964Header,
};
