const { ethers, predeploy } = require('hardhat');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const { getDomain } = require('../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { ERC4337Helper } = require('../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { PackedUserOperation } = require('../../../lib/@openzeppelin-contracts/test/helpers/eip712-types');

const { shouldBehaveLikeAccountCore } = require('../../../lib/@openzeppelin-contracts/test/account/Account.behavior');
const {
  shouldBehaveLikeAccountERC7579,
} = require('../../../lib/@openzeppelin-contracts/test/account/extensions/AccountERC7579.behavior');
const {
  shouldBehaveLikeERC1271,
} = require('../../../lib/@openzeppelin-contracts/test/utils/cryptography/ERC1271.behavior');

async function fixture() {
  // EOAs and environment
  const [other] = await ethers.getSigners();
  const target = await ethers.deployContract('CallReceiverMock');
  const anotherTarget = await ethers.deployContract('CallReceiverMock');

  // ERC-7579 validator
  const validator = await ethers.deployContract('$ERC7579ValidatorMock');

  // ERC-4337 signer
  const signer = ethers.Wallet.createRandom();

  // ERC-4337 account
  const helper = new ERC4337Helper();
  const mock = await helper.newAccount('$OpenAccountMock', [
    validator.target,
    ethers.solidityPacked(['address'], [signer.address]),
  ]);

  // ERC-4337 Entrypoint domain
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  return { helper, validator, mock, entrypointDomain, signer, target, anotherTarget, other };
}

describe('OpenAccount', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));

    this.signer.signMessage = message =>
      ethers.Wallet.prototype.signMessage
        .bind(this.signer)(message)
        .then(sign => ethers.concat([this.validator.target, sign]));
    this.signer.signTypedData = (domain, types, values) =>
      ethers.Wallet.prototype.signTypedData
        .bind(this.signer)(domain, types, values)
        .then(sign => ethers.concat([this.validator.target, sign]));
    this.signUserOp = userOp =>
      ethers.Wallet.prototype.signTypedData
        .bind(this.signer)(this.entrypointDomain, { PackedUserOperation }, userOp.packed)
        .then(signature => Object.assign(userOp, { signature }));

    this.userOp = { nonce: ethers.zeroPadBytes(ethers.hexlify(this.validator.target), 32) };
  });

  shouldBehaveLikeAccountCore();
  shouldBehaveLikeAccountERC7579({ withHooks: false });
  shouldBehaveLikeERC1271();
});
