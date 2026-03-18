const { ethers } = require('hardhat');

const ERC7964_MAGIC = '0x796479647964796479';

function encodeERC7964Header(fields, structIndex, application) {
  const magic = ethers.getBytes(ERC7964_MAGIC, 9);
  const fieldsBytes = ethers.getBytes(fields, 1);
  const structIndexBytes = ethers.zeroPadValue(ethers.toBeHex(structIndex), 2);
  const applicationBytes = ethers.getBytes(application, 20);
  return ethers.concat([magic, fieldsBytes, structIndexBytes, applicationBytes]);
}

module.exports = {
  encodeERC7964Header,
};
