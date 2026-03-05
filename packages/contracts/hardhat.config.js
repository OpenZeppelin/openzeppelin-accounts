// - COMPILER:      compiler version (default: 0.8.27)
// - HARDFORK:      hardfork version (default: prague)
// - FHE:           enable FHE compilation (default: false)

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
    fhe: {
      type: 'boolean',
      default: false,
    },
  });

if (argv.fhe) require('@fhevm/hardhat-plugin');
require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
require('hardhat-exposed');
require('hardhat-predeploy');
require('solidity-coverage');
require('./hardhat/remappings');

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
  },
  paths: {
    sources: 'src',
    tests: argv.fhe ? 'test-fhe' : 'test',
  },
};
