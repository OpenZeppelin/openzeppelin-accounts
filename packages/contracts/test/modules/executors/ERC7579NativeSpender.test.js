const { ethers, predeploy } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { ERC4337Helper } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_EXECUTOR } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const time = require('../../../../../lib/@openzeppelin-contracts/test/helpers/time');

const { shouldBehaveLikeERC7579Module } = require('../ERC7579Module.behavior');

async function fixture() {
  const [other, spender1, spender2, recipient1, recipient2] = await ethers.getSigners();

  // Deploy ERC-7579 native spender module
  const mock = await ethers.deployContract('$ERC7579NativeSpender');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();

  // ERC-7579 account
  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));
  const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
    mockAccount.connect(asEntrypoint),
  );

  const moduleType = MODULE_TYPE_EXECUTOR;

  await mockAccount.deploy();

  // Fund the account with native tokens
  const initialBalance = ethers.parseEther('100');
  await other.sendTransaction({
    to: mockAccount.address,
    value: initialBalance,
  });

  // Default spending configuration
  const limit = ethers.parseEther('10');
  const renewPeriod = time.duration.days(7);
  const start = (await time.clock.timestamp()) + time.duration.weeks(1);

  const installData = ethers.AbiCoder.defaultAbiCoder().encode(
    ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
    [[spender1.address], [start], [limit], [renewPeriod]],
  );

  return {
    moduleType,
    mock,
    mockAccount,
    mockFromAccount,
    mockAccountFromEntrypoint,
    other,
    spender1,
    spender2,
    recipient1,
    recipient2,
    initialBalance,
    limit,
    renewPeriod,
    start,
    installData,
  };
}

describe('ERC7579NativeSpender', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();

  describe('installed', function () {
    it('tracks installation status', async function () {
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.true;
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
    });
  });

  describe('installation', function () {
    it('installs with single spender configuration', async function () {
      await expect(this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData))
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(this.mockAccount.address, this.spender1.address, this.start, this.limit, this.renewPeriod);

      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(this.start);
      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(this.limit);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(
        this.renewPeriod,
      );
    });

    it('installs with multiple spender configurations', async function () {
      const multiSpenderInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [
          [this.spender1.address, this.spender2.address],
          [0n, this.start],
          [this.limit, ethers.parseEther('5')],
          [this.renewPeriod, time.duration.days(30)],
        ],
      );

      const currentTime = await time.clock.timestamp();
      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, multiSpenderInstallData),
      )
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(this.mockAccount.address, this.spender1.address, currentTime, this.limit, this.renewPeriod)
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(
          this.mockAccount.address,
          this.spender2.address,
          this.start,
          ethers.parseEther('5'),
          time.duration.days(30),
        );

      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(2n);
    });

    it('reverts if arrays have mismatched lengths', async function () {
      const invalidInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [
          [this.spender1.address, this.spender2.address], // 2 spenders
          [this.start], // 1 start
          [this.limit], // 1 limit
          [this.renewPeriod], // 1 renewPeriod
        ],
      );

      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, invalidInstallData),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderMismatchedInitDataLengths');
    });

    it('reverts if spenders array is empty', async function () {
      const emptyInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[], [], [], []],
      );

      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, emptyInstallData),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderEmptySpenders');
    });

    it('reverts if renewPeriod is zero', async function () {
      const invalidRenewPeriodData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender1.address], [this.start], [this.limit], [0]], // renewPeriod = 0
      );

      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, invalidRenewPeriodData),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidRenewPeriod');
    });

    it('reverts if start is in the past (different from current config)', async function () {
      const beforeTx = await time.clock.timestamp();
      const pastStartData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender1.address], [beforeTx], [this.limit], [this.renewPeriod]],
      );

      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, pastStartData),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidStart');
    });

    it('reverts if already installed', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await expect(this.mockFromAccount.onInstall(this.installData)).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579NativeSpenderAlreadyInstalled',
      );
    });

    it('reverts if initData is invalid (too short)', async function () {
      const invalidInitData = '0x1234'; // Too short

      await expect(
        this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, invalidInitData),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidInitData');
    });
  });

  describe('uninstallation', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('clears spending configurations', async function () {
      const installationBefore = await this.mock.installation(this.mockAccount.address);

      const tx = await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');
      await expect(tx).to.emit(this.mock, 'ERC7579NativeSpendingConfigCleared').withArgs(this.mockAccount.address);

      const installationAfter = await this.mock.installation(this.mockAccount.address);
      expect(installationAfter).to.equal(installationBefore + 1n);
    });

    it('allows reinstallation with fresh configuration', async function () {
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      const newStart = (await time.clock.timestamp()) + 1n;
      const newLimit = ethers.parseEther('20');
      const newRenewPeriod = time.duration.days(14);
      const newInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender2.address], [newStart], [newLimit], [newRenewPeriod]],
      );

      await expect(this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, newInstallData)).to
        .not.be.reverted;

      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);
      await expect(this.mock.start(this.mockAccount.address, this.spender2.address)).to.eventually.equal(newStart);
      await expect(this.mock.limit(this.mockAccount.address, this.spender2.address)).to.eventually.equal(newLimit);
    });

    it('old storage becomes inaccessible after nonce increment', async function () {
      await time.increaseTo.timestamp(this.start);

      // Create some spending history
      const amount = ethers.parseEther('5');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount);

      // Verify data is accessible with installation nonce 0
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount);
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(this.start);

      // Uninstall (advances nonce to 1)
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(1n);

      // Old data should return 0/default values (reads from installation nonce 1, not 0)
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(0n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
    });

    it('old storage remains inaccessible across multiple reinstalls', async function () {
      await time.increaseTo.timestamp(this.start);

      const firstAmount = ethers.parseEther('3');
      await this.mock
        .connect(this.spender1)
        .transferFrom(this.mockAccount.address, this.recipient1.address, firstAmount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(
        firstAmount,
      );

      // Uninstall (nonce becomes 1)
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Second installation with different configuration
      const secondStart = (await time.clock.timestamp()) + time.duration.days(1);
      const secondInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender2.address], [secondStart], [ethers.parseEther('20')], [time.duration.days(14)]],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, secondInstallData);
      await time.increaseTo.timestamp(secondStart);

      const secondAmount = ethers.parseEther('15');
      await this.mock
        .connect(this.spender2)
        .transferFrom(this.mockAccount.address, this.recipient1.address, secondAmount);

      // First installation data should still be inaccessible
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);

      // Second installation data should be accessible
      await expect(this.mock.spent(this.mockAccount.address, this.spender2.address, 0)).to.eventually.equal(
        secondAmount,
      );
      await expect(this.mock.start(this.mockAccount.address, this.spender2.address)).to.eventually.equal(secondStart);

      // Uninstall again (nonce becomes 2)
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Third installation with original spender
      const thirdStart = (await time.clock.timestamp()) + time.duration.days(1);
      const thirdInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender1.address], [thirdStart], [ethers.parseEther('5')], [time.duration.days(3)]],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, thirdInstallData);

      // All previous spending data should be inaccessible
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender2.address, 0)).to.eventually.equal(0n);

      // Only new configuration is accessible
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(thirdStart);
      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(
        ethers.parseEther('5'),
      );
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(
        time.duration.days(3),
      );
    });

    it('old spenders list becomes empty after uninstall', async function () {
      // Module already installed with one spender by beforeEach, uninstall it first
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Install with multiple spenders
      const multiSpenderStart = (await time.clock.timestamp()) + time.duration.days(1);
      const multiSpenderInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [
          [this.spender1.address, this.spender2.address, this.other.address],
          [multiSpenderStart, multiSpenderStart, multiSpenderStart],
          [this.limit, ethers.parseEther('5'), ethers.parseEther('15')],
          [this.renewPeriod, this.renewPeriod, this.renewPeriod],
        ],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, multiSpenderInstallData);

      // Verify 3 spenders are registered
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(3n);
      const spendersList = await this.mock.spenders(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(spendersList).to.have.lengthOf(3);

      // Uninstall
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Spenders count should be 0 (reading from new nonce)
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(0n);
      const emptySpendersList = await this.mock.spenders(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(emptySpendersList).to.have.lengthOf(0);

      // Reinstall with different spenders
      const newStart = (await time.clock.timestamp()) + time.duration.days(1);
      const newInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.recipient1.address], [newStart], [this.limit], [this.renewPeriod]],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, newInstallData);

      // Only new spender should be in the list
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);
      const newSpendersList = await this.mock.spenders(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(newSpendersList).to.have.lengthOf(1);
      expect(newSpendersList[0]).to.equal(this.recipient1.address);
    });

    it('old spending data across multiple periods becomes inaccessible', async function () {
      // Module already installed by beforeEach
      await time.increaseTo.timestamp(this.start);

      // Spend in period 0
      const period0Amount = ethers.parseEther('7');
      await this.mock
        .connect(this.spender1)
        .transferFrom(this.mockAccount.address, this.recipient1.address, period0Amount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(
        period0Amount,
      );

      // Move to period 1 and spend
      await time.increaseBy.timestamp(this.renewPeriod);
      const period1Amount = ethers.parseEther('8');
      await this.mock
        .connect(this.spender1)
        .transferFrom(this.mockAccount.address, this.recipient1.address, period1Amount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(
        period1Amount,
      );

      // Move to period 2 and spend
      await time.increaseBy.timestamp(this.renewPeriod);
      const period2Amount = ethers.parseEther('6');
      await this.mock
        .connect(this.spender1)
        .transferFrom(this.mockAccount.address, this.recipient1.address, period2Amount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 2)).to.eventually.equal(
        period2Amount,
      );

      // Verify all periods have data
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(
        period0Amount,
      );
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(
        period1Amount,
      );
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 2)).to.eventually.equal(
        period2Amount,
      );

      // Uninstall
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // All period data should be inaccessible (returns 0)
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 2)).to.eventually.equal(0n);

      // Reinstall
      const newStart = (await time.clock.timestamp()) + time.duration.days(1);
      const reinstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender1.address], [newStart], [this.limit], [this.renewPeriod]],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, reinstallData);
      await time.increaseTo.timestamp(newStart);

      // Old period data should still be inaccessible
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(0n);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 2)).to.eventually.equal(0n);

      // New spending should start fresh
      const newAmount = ethers.parseEther('4');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, newAmount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(newAmount);
    });
  });

  describe('spenders management', function () {
    beforeEach(async function () {
      const multiSpenderInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [
          [this.spender1.address, this.spender2.address],
          [this.start, this.start],
          [this.limit, ethers.parseEther('5')],
          [this.renewPeriod, this.renewPeriod],
        ],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, multiSpenderInstallData);
    });

    it('returns correct spenders count', async function () {
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(2n);
    });

    it('returns spenders slice', async function () {
      const allSpenders = await this.mock.spenders(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(allSpenders).to.have.lengthOf(2);
      expect(allSpenders).to.include(this.spender1.address);
      expect(allSpenders).to.include(this.spender2.address);
    });

    it('returns partial spenders slice', async function () {
      const partialSpenders = await this.mock.spenders(this.mockAccount.address, 0, 1);
      expect(partialSpenders).to.have.lengthOf(1);
    });
  });

  describe('spending configuration', function () {
    beforeEach(async function () {
      const multiSpenderInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [
          [this.spender1.address, this.spender2.address],
          [this.start, this.start],
          [this.limit, ethers.parseEther('5')],
          [this.renewPeriod, this.renewPeriod],
        ],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, multiSpenderInstallData);
    });

    it('allows account to update spending configuration', async function () {
      const newLimit = ethers.parseEther('15');
      const newRenewPeriod = time.duration.days(14);

      const tx = await this.mockFromAccount.setSpendingConfig(
        this.spender1.address,
        this.start + time.duration.days(3),
        newLimit,
        ethers.Typed.uint48(newRenewPeriod),
      );
      await expect(tx)
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(
          this.mockAccount.address,
          this.spender1.address,
          this.start + time.duration.days(3),
          newLimit,
          newRenewPeriod,
        );

      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(
        this.start + time.duration.days(3),
      );
      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(newLimit);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(
        newRenewPeriod,
      );
    });

    it('allows setting a future start time', async function () {
      const futureStart = (await time.clock.timestamp()) + time.duration.years(3);
      await this.mockFromAccount.setSpendingConfig(
        this.spender2.address,
        futureStart,
        this.limit,
        ethers.Typed.uint48(this.renewPeriod),
      );

      await expect(this.mock.start(this.mockAccount.address, this.spender2.address)).to.eventually.equal(futureStart);
    });

    it('allows setting 0 start time resolving to current time', async function () {
      const tx = await this.mockFromAccount.setSpendingConfig(this.spender1.address, 0, this.limit, this.renewPeriod);
      const currentTime = await time.clock.timestamp();
      await expect(tx)
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(this.mockAccount.address, this.spender1.address, currentTime, this.limit, this.renewPeriod);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(currentTime);
    });

    it('reverts when trying to set limit to 0', async function () {
      await time.increaseTo.timestamp(this.start);
      await expect(
        this.mockFromAccount.setSpendingConfig(this.spender1.address, 0, ethers.Typed.uint48(this.renewPeriod)),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidLimit');
    });

    it('removes spender configuration', async function () {
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(2n);

      const tx = await this.mockFromAccount.unsetSpendingConfig(this.spender1.address);
      await expect(tx)
        .to.emit(this.mock, 'ERC7579NativeSpendingConfigUnset')
        .withArgs(this.mockAccount.address, this.spender1.address);

      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);
      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
    });

    it('reverts when trying to remove last spender', async function () {
      // Remove first spender
      await this.mockFromAccount.unsetSpendingConfig(this.spender1.address);
      await expect(this.mock.spendersCount(this.mockAccount.address)).to.eventually.equal(1n);

      // Try to remove last spender
      await expect(this.mockFromAccount.unsetSpendingConfig(this.spender2.address)).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579NativeSpenderEmptySpenders',
      );
    });

    it('clears spent data', async function () {
      await time.increaseTo.timestamp(this.start);

      const amount = ethers.parseEther('3');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount);

      await this.mockFromAccount.unsetSpendingConfig(this.spender1.address);

      await expect(this.mock.limit(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.start(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.spender1.address)).to.eventually.equal(0n);
    });
  });

  describe('period calculations', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('returns correct period at start time', async function () {
      const [start, period] = await this.mock.periodAt(this.mockAccount.address, this.spender1.address, this.start);
      expect(start).to.equal(this.start);
      expect(period).to.equal(0n);
    });

    it('returns correct period after one renewal period', async function () {
      const timepoint = this.start + this.renewPeriod;
      const [start, period] = await this.mock.periodAt(this.mockAccount.address, this.spender1.address, timepoint);
      expect(start).to.equal(this.start);
      expect(period).to.equal(1n);
    });

    it('returns correct period after multiple renewal periods', async function () {
      const timepoint = this.start + this.renewPeriod * 5n;
      const [start, period] = await this.mock.periodAt(this.mockAccount.address, this.spender1.address, timepoint);
      expect(start).to.equal(this.start);
      expect(period).to.equal(5n);
    });

    it('reverts if timepoint is before start', async function () {
      const timepoint = this.start - 100n;
      await expect(
        this.mock.periodAt(this.mockAccount.address, this.spender1.address, timepoint),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpendingConfigNotStarted');
    });

    it('reverts if spender config is not set', async function () {
      await expect(
        this.mock.periodAt(this.mockAccount.address, this.spender2.address, await time.clock.timestamp()),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpendingConfigNotSet');
    });
  });

  describe('spending tracking', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await time.increaseTo.timestamp(this.start);
    });

    it('returns zero spent for first period', async function () {
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
    });

    it('returns correct spending info at current period', async function () {
      const [spending, available] = await this.mock.spendingAt(this.mockAccount.address, this.spender1.address, 0);
      expect(spending).to.equal(0n);
      expect(available).to.equal(this.limit);
    });

    it('tracks spent amount after transfer', async function () {
      const amount = ethers.parseEther('3');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount);

      const [spending, available] = await this.mock.spendingAt(this.mockAccount.address, this.spender1.address, 0);
      expect(spending).to.equal(amount);
      expect(available).to.equal(this.limit - amount);
    });

    it('resets spending in new period', async function () {
      const amount = ethers.parseEther('3');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount);

      await time.increaseBy.timestamp(this.renewPeriod);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(0n);

      const [spending, available] = await this.mock.spendingAt(this.mockAccount.address, this.spender1.address, 1);
      expect(spending).to.equal(0n);
      expect(available).to.equal(this.limit);
    });

    it('maintains separate spending per spender', async function () {
      await this.mockFromAccount.setSpendingConfig(
        this.spender2.address,
        this.start + time.duration.days(3),
        ethers.parseEther('5'),
        ethers.Typed.uint48(this.renewPeriod),
      );

      await time.increaseTo.timestamp(this.start + time.duration.days(3));

      const amount1 = ethers.parseEther('3');
      const amount2 = ethers.parseEther('4');

      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount1);
      await this.mock.connect(this.spender2).transferFrom(this.mockAccount.address, this.recipient1.address, amount2);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount1);
      await expect(this.mock.spent(this.mockAccount.address, this.spender2.address, 0)).to.eventually.equal(amount2);
    });

    it('tracks spending for different start times', async function () {
      const amount1 = ethers.parseEther('3');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount1);

      // Verify with original start
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount1);
      await expect(
        this.mock['spent(address,address,uint256,uint256)'](
          this.mockAccount.address,
          this.spender1.address,
          0,
          this.start,
        ),
      ).to.eventually.equal(amount1);

      // Change start time
      const newStart = (await time.clock.timestamp()) + time.duration.days(1);
      await this.mockFromAccount.setSpendingConfig(
        this.spender1.address,
        newStart,
        this.limit,
        ethers.Typed.uint48(this.renewPeriod),
      );
      await time.increaseTo.timestamp(newStart);

      // Spend with new start
      const amount2 = ethers.parseEther('4');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount2);

      // Old start should still have old spending
      await expect(
        this.mock['spent(address,address,uint256,uint256)'](
          this.mockAccount.address,
          this.spender1.address,
          0,
          this.start,
        ),
      ).to.eventually.equal(amount1);

      // New start should have new spending
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount2);
      await expect(
        this.mock['spent(address,address,uint256,uint256)'](
          this.mockAccount.address,
          this.spender1.address,
          0,
          newStart,
        ),
      ).to.eventually.equal(amount2);
    });
  });

  describe('transferFrom', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await time.increaseTo.timestamp(this.start);
    });

    it('transfers native tokens from account to recipient', async function () {
      const amount = ethers.parseEther('3');
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount, amount]);
    });

    it('updates spent amount after transfer', async function () {
      const amount = ethers.parseEther('3');
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount, amount]);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount);
    });

    it('allows multiple transfers within limit', async function () {
      const amount1 = ethers.parseEther('3');
      const amount2 = ethers.parseEther('4');

      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount1),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount1, amount1]);
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount2),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount2, amount2]);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(
        amount1 + amount2,
      );
    });

    it('reverts if amount exceeds available limit', async function () {
      const amount = this.limit + 1n;
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');
    });

    it('reverts if cumulative amount exceeds limit', async function () {
      const amount1 = ethers.parseEther('6');
      const amount2 = ethers.parseEther('5'); // Total: 11 ETH > 10 ETH limit

      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount1),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount1, amount1]);
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount2),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');
    });

    it('allows spending up to exact limit', async function () {
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, this.limit),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-this.limit, this.limit]);

      const [spending, available] = await this.mock.spendingAt(this.mockAccount.address, this.spender1.address, 0);
      expect(spending).to.equal(this.limit);
      expect(available).to.equal(0n);
    });

    it('allows spending again after period renewal', async function () {
      const amount = this.limit;
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount, amount]);

      await time.increaseBy.timestamp(this.renewPeriod);

      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount, amount]);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(amount);
    });

    it('reverts if called before config start time', async function () {
      const futureStart = this.start + time.duration.years(3);
      await this.mockFromAccount.setSpendingConfig(
        this.spender2.address,
        futureStart,
        this.limit,
        ethers.Typed.uint48(this.renewPeriod),
      );

      await expect(
        this.mock.connect(this.spender2).transferFrom(this.mockAccount.address, this.recipient1.address, 1),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpendingConfigNotStarted');
    });

    it('respects updated limits', async function () {
      const newLimit = ethers.parseEther('5');
      const futureStart = (await time.clock.timestamp()) + time.duration.days(1);
      await this.mockFromAccount.setSpendingConfig(
        this.spender1.address,
        futureStart,
        newLimit,
        ethers.Typed.uint48(this.renewPeriod),
      );
      await time.increaseTo.timestamp(futureStart);

      const amount = ethers.parseEther('6');
      await expect(
        this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');

      await expect(
        this.mock
          .connect(this.spender1)
          .transferFrom(this.mockAccount.address, this.recipient1.address, ethers.parseEther('4')),
      ).to.not.be.reverted;
    });
  });

  describe('batchTransferFrom', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await time.increaseTo.timestamp(this.start);
    });

    it('transfers to multiple recipients', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('3'), ethers.parseEther('4')];
      const totalAmount = amounts.reduce((a, b) => a + b, 0n);

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.changeEtherBalances(
        [this.mockAccount, this.recipient1, this.recipient2],
        [-totalAmount, amounts[0], amounts[1]],
      );
    });

    it('updates spent amount for total of batch transfers', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('3'), ethers.parseEther('4')];
      const totalAmount = amounts.reduce((a, b) => a + b, 0n);

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.changeEtherBalances(
        [this.mockAccount, this.recipient1, this.recipient2],
        [-totalAmount, amounts[0], amounts[1]],
      );

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(
        totalAmount,
      );
    });

    it('reverts if arrays have mismatched lengths', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('3')]; // Only 1 amount for 2 recipients

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderMismatchedBatchLengths');
    });

    it('reverts if total amount exceeds available limit', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('6'), ethers.parseEther('5')]; // Total: 11 ETH > 10 ETH limit

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');
    });

    it('allows batch transfer up to exact limit', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('6'), ethers.parseEther('4')]; // Total: 10 ETH = limit

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.changeEtherBalances(
        [this.mockAccount, this.recipient1, this.recipient2],
        [-this.limit, amounts[0], amounts[1]],
      );

      const [spending, available] = await this.mock.spendingAt(this.mockAccount.address, this.spender1.address, 0);
      expect(spending).to.equal(this.limit);
      expect(available).to.equal(0n);
    });

    it('handles empty arrays', async function () {
      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, [], []),
      ).to.changeEtherBalances([this.mockAccount], [0n]);
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
    });

    it('allows batch transfer after period renewal', async function () {
      const tos = [this.recipient1.address];
      const amounts = [this.limit];
      await this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts);

      await time.increaseBy.timestamp(this.renewPeriod);

      await expect(
        this.mock.connect(this.spender1).batchTransferFrom(this.mockAccount.address, tos, amounts),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-this.limit, this.limit]);

      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 1)).to.eventually.equal(this.limit);
    });
  });

  describe('installation nonce', function () {
    it('returns installation nonce for account', async function () {
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(0n);
    });

    it('increments installation nonce on uninstall', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);

      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(0n);

      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(1n);
    });

    it('invalidates old spending data after uninstall/reinstall', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await time.increaseTo.timestamp(this.start);

      const amount = ethers.parseEther('3');
      await this.mock.connect(this.spender1).transferFrom(this.mockAccount.address, this.recipient1.address, amount);

      // Verify spending was tracked
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(amount);

      // Uninstall
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Reinstall with same spender
      const newStart = (await time.clock.timestamp()) + 1n;
      const reinstallData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['address[]', 'uint48[]', 'uint160[]', 'uint48[]'],
        [[this.spender1.address], [newStart], [this.limit], [this.renewPeriod]],
      );
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, reinstallData);

      // Old spending should not be accessible (new installation nonce)
      await expect(this.mock.spent(this.mockAccount.address, this.spender1.address, 0)).to.eventually.equal(0n);
    });
  });
});
