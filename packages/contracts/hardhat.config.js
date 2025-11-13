// - COMPILER:      compiler version (default: 0.8.27)
// - HARDFORK:      hardfork version (default: prague)

const { argv } = require('yargs/yargs')()
  .env('')
  .options({
    compiler: {
      type: 'string',
      default: '0.8.27',
    },
    hardfork: {
      type: 'string',
      default: 'prague',
    },
  });

require('@fhevm/hardhat-plugin');
require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
require('hardhat-exposed');
require('hardhat-predeploy');
require('solidity-coverage');
require('../../lib/@openzeppelin-contracts/hardhat/remappings');

module.exports = {
  solidity: {
    version: argv.compiler,
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: argv.hardfork,
    },
  },
  networks: {
    hardhat: {
      hardfork: argv.hardfork,
    },
  },
  exposed: {
    imports: true,
    initializers: true,
  },
  paths: {
    sources: 'src',
  },
};
