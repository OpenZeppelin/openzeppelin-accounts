const { ethers, predeploy } = require('hardhat');
const { expect } = require('chai');
const { loadFixture, time } = require('@nomicfoundation/hardhat-network-helpers');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { getDomain } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { ERC4337Helper } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const {
  MODULE_TYPE_EXECUTOR,
  CALL_TYPE_CALL,
  EXEC_TYPE_DEFAULT,
  encodeMode,
  encodeSingle,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const {
  NonNativeSigner,
  MultiERC7913SigningKey,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/signers');
const { MAX_UINT64 } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/constants');
const { ERC7579OperationState } = require('../../helpers/enums');
const { ScheduleRecover, CancelRecover } = require('../../helpers/eip712-types');

const { shouldBehaveLikeERC7579Module } = require('../ERC7579Module.behavior');

// Prepare guardians in advance
const guardian1 = ethers.Wallet.createRandom();
const guardian2 = ethers.Wallet.createRandom();
const guardian3 = ethers.Wallet.createRandom();
const nonGuardian = ethers.Wallet.createRandom();

async function fixture() {
  const [other] = await ethers.getSigners();

  // Deploy social recovery executor module
  const mock = await ethers.deployContract('ERC7579SocialRecoveryExecutor');
  const target = await ethers.deployContract('CallReceiverMock');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();

  // Prepare guardians with weights
  const guardians = [guardian1.address, guardian2.address, guardian3.address];
  const weights = [1, 2, 3];
  const threshold = 3;

  // Create multi-guardian signer
  const multiGuardian = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2, guardian3], weights));

  // Prepare module installation data
  const delay = time.duration.days(10);
  const expiration = time.duration.years(1);
  const executorArgs = ethers.solidityPacked(['uint32', 'uint32'], [delay, expiration]);
  const multisigArgs = ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes[]', 'uint256', 'uint256[]'],
    [guardians, threshold, weights],
  );

  const installData = ethers.concat([
    ethers.toBeHex(ethers.dataLength(executorArgs), 2), // uint16 length prefix
    executorArgs,
    ethers.toBeHex(ethers.dataLength(multisigArgs), 2), // uint16 length prefix
    multisigArgs,
  ]);

  // ERC-7579 account with EIP-712 support
  const validator = await ethers.deployContract('$ERC7579ValidatorMock');
  const mockAccount = await helper.newAccount('$OpenAccount', [
    validator.target,
    ethers.solidityPacked(['address'], [ethers.Wallet.createRandom().address]),
  ]);
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));
  const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
    mockAccount.connect(asEntrypoint),
  );

  await mockAccount.deploy();

  const args = [42, '0x1234'];
  const data = target.interface.encodeFunctionData('mockFunctionWithArgs', args);
  const calldata = encodeSingle(target, 0, data);
  const mode = encodeMode({ callType: CALL_TYPE_CALL, execType: EXEC_TYPE_DEFAULT });

  return {
    moduleType: MODULE_TYPE_EXECUTOR,
    mock,
    mockAccount,
    mockFromAccount,
    mockAccountFromEntrypoint,
    target,
    installData,
    args,
    data,
    calldata,
    mode,
    delay,
    expiration,
    guardians,
    nonGuardian: nonGuardian.address,
    weights,
    threshold,
    multiGuardian,
    other,
  };
}

describe('ERC7579SocialRecoveryExecutor', function () {
  const salt = ethers.ZeroHash;

  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();

  describe('installation', function () {
    it('sets initial guardians, weights, threshold, delay, and expiration on installation', async function () {
      const tx = await this.mockAccountFromEntrypoint.installModule(
        this.moduleType,
        this.mock.target,
        this.installData,
      );

      const now = await time.latest();

      for (const guardian of this.guardians) {
        expect(tx).to.emit(this.mock, 'ERC7913SignerAdded').withArgs(this.mockAccount.address, guardian);
      }

      expect(tx).to.emit(this.mock, 'ERC7913ThresholdSet').withArgs(this.mockAccount.address, this.threshold);
      expect(tx)
        .to.emit(this.mock, 'ERC7579ExecutorDelayUpdated')
        .withArgs(this.mockAccount.address, this.delay, now)
        .to.emit(this.mock, 'ERC7579ExecutorExpirationUpdated')
        .withArgs(this.mockAccount.address, this.expiration);

      await expect(this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal(
        this.guardians,
      );

      await expect(
        Promise.all(this.guardians.map(guardian => this.mock.signerWeight(this.mockAccount.address, guardian))),
      ).to.eventually.deep.equal(this.weights);
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(this.threshold);
    });

    it('reverts when installing twice', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);

      await expect(this.mockFromAccount.onInstall(this.installData)).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579DelayedExecutorAlreadyInstalled',
      );
    });

    it('cleans up guardians, weights, threshold, delay, and expiration on uninstallation', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);

      const now = await time.latest();
      const tx = await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      expect(tx)
        .to.emit(this.mock, 'ERC7579ExecutorDelayUpdated')
        .withArgs(this.mockAccount.address, 0, now + this.delay)
        .to.emit(this.mock, 'ERC7579ExecutorExpirationUpdated')
        .withArgs(this.mockAccount.address, 0);

      await expect(this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal([]);
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(0);

      await expect(
        Promise.all(this.guardians.map(guardian => this.mock.signerWeight(this.mockAccount.address, guardian))),
      ).to.eventually.deep.equal(Array(this.guardians.length).fill(0));
    });
  });

  describe('guardian management (alias functions)', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    describe('getGuardians', function () {
      it('returns all guardians', async function () {
        await expect(this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal(
          this.guardians,
        );
      });

      it('returns guardians in a range', async function () {
        const result = await this.mock.getGuardians(this.mockAccount.address, 0, 2);
        expect(result).to.deep.equal([this.guardians[0], this.guardians[1]]);
      });
    });

    describe('getGuardianCount', function () {
      it('returns the correct guardian count', async function () {
        await expect(this.mock.getGuardianCount(this.mockAccount.address)).to.eventually.equal(3);
      });

      it('returns 0 for accounts without guardians', async function () {
        await expect(this.mock.getGuardianCount(this.other.address)).to.eventually.equal(0);
      });
    });

    describe('isGuardian', function () {
      it('returns true for existing guardians', async function () {
        await expect(this.mock.isGuardian(this.mockAccount.address, this.guardians[0])).to.eventually.be.true;
        await expect(this.mock.isGuardian(this.mockAccount.address, this.guardians[1])).to.eventually.be.true;
        await expect(this.mock.isGuardian(this.mockAccount.address, this.guardians[2])).to.eventually.be.true;
      });

      it('returns false for non-guardians', async function () {
        await expect(this.mock.isGuardian(this.mockAccount.address, this.nonGuardian)).to.eventually.be.false;
      });
    });

    describe('addGuardians', function () {
      it('can add guardians', async function () {
        const newGuardians = [this.nonGuardian];

        const guardiansBefore = await this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64);

        const tx = await this.mockFromAccount.addGuardians(newGuardians);
        for (const guardian of newGuardians) {
          await expect(tx)
            .to.emit(this.mock, 'ERC7913SignerAdded')
            .withArgs(this.mockAccount.address, guardian.toLowerCase());
        }

        const guardiansAfter = await this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64);

        expect(guardiansAfter.length).to.equal(guardiansBefore.length + 1);
        expect(guardiansAfter).to.include(this.nonGuardian.toLowerCase());

        await expect(this.mock.isGuardian(this.mockAccount.address, this.nonGuardian)).to.eventually.be.true;

        // Reverts if the guardian already exists
        await expect(this.mockFromAccount.addGuardians(newGuardians))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigAlreadyExists')
          .withArgs(this.nonGuardian.toLowerCase());
      });
    });

    describe('removeGuardians', function () {
      it('can remove guardians', async function () {
        const removedGuardians = [this.guardians[0]];

        const guardiansBefore = await this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64);

        const tx = await this.mockFromAccount.removeGuardians(removedGuardians);
        for (const guardian of removedGuardians) {
          await expect(tx)
            .to.emit(this.mock, 'ERC7913SignerRemoved')
            .withArgs(this.mockAccount.address, guardian.toLowerCase());
        }

        const guardiansAfter = await this.mock.getGuardians(this.mockAccount.address, 0, MAX_UINT64);

        expect(guardiansAfter.length).to.equal(guardiansBefore.length - 1);
        expect(guardiansAfter).to.not.include(this.guardians[0]);

        await expect(this.mock.isGuardian(this.mockAccount.address, this.guardians[0])).to.eventually.be.false;

        // Reverts if the guardian doesn't exist
        await expect(this.mockFromAccount.removeGuardians(removedGuardians))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner')
          .withArgs(this.guardians[0].toLowerCase());

        // Reverts if threshold becomes unreachable after removal
        // First remove guardian[0] (weight 1), leaving weights [2, 3] = total 5
        // Then set threshold to 5 to match total
        await this.mockFromAccount.setThreshold(5);

        // Now try to remove guardian[1] (weight 2), which would leave only weight 3 < threshold 5
        await expect(this.mockFromAccount.removeGuardians([this.guardians[1]]))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnreachableThreshold')
          .withArgs(3, 5);
      });
    });
  });

  describe('social recovery flow', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    describe('startRecovery', function () {
      it('schedules a recovery operation with valid guardian signatures', async function () {
        const domain = await getDomain(this.mockAccount);
        const multiGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));
        const multisignature = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        const tx = await this.mock.startRecovery(
          this.mockAccount.address,
          salt,
          this.mode,
          this.calldata,
          multisignature,
        );
        const now = await time.latest();

        await expect(tx)
          .to.emit(this.mock, 'ERC7579ExecutorOperationScheduled')
          .withArgs(
            this.mockAccount.address,
            this.mock.hashOperation(this.mockAccount.address, salt, this.mode, this.calldata),
            salt,
            this.mode,
            this.calldata,
            now + this.delay,
          );

        await expect(this.mock.state(this.mockAccount.address, salt, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Scheduled,
        );
      });

      it('reverts with invalid guardian signatures', async function () {
        const domain = await getDomain(this.mockAccount);
        const nonGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([nonGuardian]));
        const multisignature = await nonGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await expect(
          this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579SocialRecoveryExecutorInvalidSchedule');
      });

      it('reverts when guardian signatures do not meet threshold', async function () {
        const domain = await getDomain(this.mockAccount);
        const singleGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1]));
        const multisignature = await singleGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await expect(
          this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579SocialRecoveryExecutorInvalidSchedule');
      });

      it('reverts when trying to schedule duplicate operation', async function () {
        const domain = await getDomain(this.mockAccount);
        const multiGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));
        const multisignature = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature);

        await expect(
          this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });
    });

    describe('executeRecovery', function () {
      beforeEach(async function () {
        const domain = await getDomain(this.mockAccount);
        const multiGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));
        const multisignature = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature);
      });

      it('reverts before delay passes', async function () {
        await expect(
          this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });

      it('executes recovery after delay passes', async function () {
        await time.increase(this.delay);

        await expect(this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata))
          .to.emit(this.target, 'MockFunctionCalledWithArgs')
          .withArgs(...this.args);

        await expect(this.mock.state(this.mockAccount.address, salt, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Executed,
        );
      });

      it('reverts if operation has expired', async function () {
        await time.increase(this.delay + this.expiration);

        await expect(
          this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });

      it('can be executed by anyone once ready', async function () {
        await time.increase(this.delay);

        await expect(
          this.mock.connect(this.other).executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        )
          .to.emit(this.target, 'MockFunctionCalledWithArgs')
          .withArgs(...this.args);
      });

      it('reverts when trying to execute already-executed operation', async function () {
        await time.increase(this.delay);
        await this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata);

        await expect(
          this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });
    });

    describe('cancelRecovery', function () {
      beforeEach(async function () {
        const domain = await getDomain(this.mockAccount);
        const multiGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));
        const multisignature = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await this.mock.startRecovery(this.mockAccount.address, salt, this.mode, this.calldata, multisignature);
      });

      it('can be canceled by the account owner', async function () {
        await expect(this.mockFromAccount.cancelRecovery(this.mockAccount.address, salt, this.mode, this.calldata))
          .to.emit(this.mock, 'ERC7579ExecutorOperationCanceled')
          .withArgs(
            this.mockAccount.address,
            this.mock.hashOperation(this.mockAccount.address, salt, this.mode, this.calldata),
          );

        await expect(this.mock.state(this.mockAccount.address, salt, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Canceled,
        );
      });

      it('can be canceled by guardians with valid signatures', async function () {
        const domain = await getDomain(this.mockAccount);

        const guardiansSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));
        const multisignature = await guardiansSigner.signTypedData(
          domain,
          {
            CancelRecover,
          },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await expect(
          this.mock.cancelRecovery(
            this.mockAccount.address,
            salt,
            this.mode,
            this.calldata,
            ethers.Typed.bytes(multisignature),
          ),
        )
          .to.emit(this.mock, 'ERC7579ExecutorOperationCanceled')
          .withArgs(
            this.mockAccount.address,
            this.mock.hashOperation(this.mockAccount.address, salt, this.mode, this.calldata),
          );

        await expect(this.mock.state(this.mockAccount.address, salt, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Canceled,
        );
      });

      it('reverts when canceling with invalid guardian signatures', async function () {
        const domain = await getDomain(this.mockAccount);
        const nonGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([nonGuardian]));
        const multisignature = await nonGuardianSigner.signTypedData(
          domain,
          {
            CancelRecover,
          },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await expect(
          this.mock.cancelRecovery(
            this.mockAccount.address,
            salt,
            this.mode,
            this.calldata,
            ethers.Typed.bytes(multisignature),
          ),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579SocialRecoveryExecutorInvalidCancel');
      });

      it('reverts when guardian signatures do not meet threshold for cancellation', async function () {
        const domain = await getDomain(this.mockAccount);
        const singleGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1]));
        const multisignature = await singleGuardianSigner.signTypedData(
          domain,
          {
            CancelRecover,
          },
          {
            executor: this.mock.target,
            salt: salt,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );

        await expect(
          this.mock.cancelRecovery(
            this.mockAccount.address,
            salt,
            this.mode,
            this.calldata,
            ethers.Typed.bytes(multisignature),
          ),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579SocialRecoveryExecutorInvalidCancel');
      });

      it('reverts when non-account, non-guardian tries to cancel', async function () {
        await expect(
          this.mock.connect(this.other).cancelRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.reverted;
      });

      it('reverts when trying to cancel already-canceled operation', async function () {
        await this.mockFromAccount.cancelRecovery(this.mockAccount.address, salt, this.mode, this.calldata);

        await expect(
          this.mockFromAccount.cancelRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });

      it('reverts when trying to cancel after execution', async function () {
        await time.increase(this.delay);
        await this.mock.executeRecovery(this.mockAccount.address, salt, this.mode, this.calldata);

        await expect(
          this.mockFromAccount.cancelRecovery(this.mockAccount.address, salt, this.mode, this.calldata),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ExecutorUnexpectedOperationState');
      });
    });

    describe('multiple concurrent recovery operations', function () {
      it('can schedule multiple operations with different salts', async function () {
        const salt1 = ethers.id('salt1');
        const salt2 = ethers.id('salt2');

        const domain = await getDomain(this.mockAccount);
        const multiGuardianSigner = new NonNativeSigner(new MultiERC7913SigningKey([guardian1, guardian2]));

        // Schedule first operation
        const sig1 = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt1,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );
        await this.mock.startRecovery(this.mockAccount.address, salt1, this.mode, this.calldata, sig1);

        // Schedule second operation
        const sig2 = await multiGuardianSigner.signTypedData(
          domain,
          { ScheduleRecover },
          {
            executor: this.mock.target,
            salt: salt2,
            mode: this.mode,
            recoveryCalldata: this.calldata,
          },
        );
        await this.mock.startRecovery(this.mockAccount.address, salt2, this.mode, this.calldata, sig2);

        // Both should be in Scheduled state
        await expect(this.mock.state(this.mockAccount.address, salt1, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Scheduled,
        );
        await expect(this.mock.state(this.mockAccount.address, salt2, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Scheduled,
        );

        // Execute both
        await time.increase(this.delay);
        await this.mock.executeRecovery(this.mockAccount.address, salt1, this.mode, this.calldata);
        await this.mock.executeRecovery(this.mockAccount.address, salt2, this.mode, this.calldata);

        await expect(this.mock.state(this.mockAccount.address, salt1, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Executed,
        );
        await expect(this.mock.state(this.mockAccount.address, salt2, this.mode, this.calldata)).to.eventually.equal(
          ERC7579OperationState.Executed,
        );
      });
    });
  });
});
