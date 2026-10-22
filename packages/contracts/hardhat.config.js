// - COMPILER:      compiler version (default: 0.8.27)
// - HARDFORK:      hardfork version (default: prague)
// - FHE:           enable FHE compilation (default: false)
// - COMPILE_MODE:  production drops the metadata hash so artifacts match the Foundry deployments (default: development)

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
    compileMode: {
      type: 'string',
      choices: ['production', 'development'],
      default: 'development',
    },
  });

if (argv.fhe) require('@fhevm/hardhat-plugin');
require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
require('hardhat-exposed');
require('hardhat-predeploy');
require('solidity-coverage');
require('solidity-docgen');
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
      // Same as `bytecode_hash` and `cbor_metadata` in foundry.toml, used for deterministic deployments
      ...(argv.compileMode === 'production' && { metadata: { bytecodeHash: 'none', appendCBOR: false } }),
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
  docgen: require('./docs/config'),
};
