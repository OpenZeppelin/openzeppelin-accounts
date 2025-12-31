const { ethers, predeploy } = require('hardhat');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { expect } = require('chai');

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
const {
  MODULE_TYPE_VALIDATOR,
  encodeMode,
  CALL_TYPE_CALL,
  encodeSingle,
  encodeBatch,
  CALL_TYPE_BATCH,
  MODULE_TYPE_EXECUTOR,
} = require('../../../lib/@openzeppelin-contracts/test/helpers/erc7579');

async function fixture() {
  // EOAs and environment
  const [other] = await ethers.getSigners();
  const target = await ethers.deployContract('CallReceiverMock');
  const anotherTarget = await ethers.deployContract('CallReceiverMock');

  // ERC-7579 modules
  const validator = await ethers.deployContract('$ERC7579ValidatorMock');
  const executor = await ethers.deployContract('$ERC7579ExecutorMock');

  // ERC-4337 signer
  const signer = ethers.Wallet.createRandom();

  // ERC-4337 account
  const helper = new ERC4337Helper();
  const mock = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  const deploy = mock.deploy;
  mock.deploy = async function (...args) {
    await deploy.call(this, ...args);
    await this.initialize(
      [MODULE_TYPE_VALIDATOR],
      [validator.target],
      [ethers.solidityPacked(['address'], [signer.address])],
      ethers.ZeroHash,
      '0x',
    );
  };

  // ERC-4337 Entrypoint domain
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  return { helper, validator, executor, mock, entrypointDomain, signer, target, anotherTarget, other };
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

  it('initializes with multiple modules and no configuration call', async function () {
    const newMock = await this.helper.newAccount('$OpenAccount', ['OpenAccount', '1']).then(m => m.deploy());

    await newMock.initialize(
      [MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR],
      [this.validator.target, this.executor.target],
      [ethers.solidityPacked(['address'], [this.signer.address]), '0x'],
      ethers.ZeroHash,
      '0x',
    );

    await expect(newMock.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
    await expect(newMock.isModuleInstalled(MODULE_TYPE_EXECUTOR, this.executor.target, '0x')).to.eventually.be.true;
  });

  it('executes single call during initialization', async function () {
    const newMock = await this.helper.newAccount('$OpenAccount', ['OpenAccount', '1']).then(m => m.deploy());

    await expect(
      newMock.initialize(
        [MODULE_TYPE_VALIDATOR],
        [this.validator.target],
        [ethers.solidityPacked(['address'], [this.signer.address])],
        encodeMode({
          callType: CALL_TYPE_CALL,
        }),
        encodeSingle(this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [42n, 100n])),
      ),
    )
      .to.emit(this.target, 'MockFunctionCalledWithArgs')
      .withArgs(42n, 100n);

    await expect(newMock.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
  });

  it('executes batch calls during initialization', async function () {
    const newMock = await this.helper.newAccount('$OpenAccount', ['OpenAccount', '1']).then(m => m.deploy());

    await expect(
      newMock.initialize(
        [MODULE_TYPE_VALIDATOR],
        [this.validator.target],
        [ethers.solidityPacked(['address'], [this.signer.address])],
        encodeMode({
          callType: CALL_TYPE_BATCH,
        }),
        encodeBatch(
          [this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [10n, 20n])],
          [this.anotherTarget, 0, this.anotherTarget.interface.encodeFunctionData('mockFunctionWithArgs', [30n, 40n])],
        ),
      ),
    )
      .to.emit(this.target, 'MockFunctionCalledWithArgs')
      .withArgs(10n, 20n)
      .to.emit(this.anotherTarget, 'MockFunctionCalledWithArgs')
      .withArgs(30n, 40n);

    await expect(newMock.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
  });

  shouldBehaveLikeAccountCore();
  shouldBehaveLikeAccountERC7579({ withHooks: false });
  shouldBehaveLikeERC1271();
});
