const { ethers, fhevm } = require('hardhat');
const { expect } = require('chai');
const { FhevmType } = require('@fhevm/hardhat-plugin');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');

const { allowHandle } = require('../helpers/fhe');
const { MAX_UINT32 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');

function shouldBehaveLikeERC7579MultisigConfidential() {
  it('sets initial signers and threshold on installation', async function () {
    await expect(this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData))
      .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
      .withArgs(this.mockAccount.address, this.signerHandles[0])
      .withArgs(this.mockAccount.address, this.signerHandles[1])
      .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
      .withArgs(this.mockAccount.address, anyValue);

    await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(
      this.signer.signingKey.signers.length,
    );

    const threshold = await this.mockFromAccount.threshold(this.mockAccount.address);
    await allowHandle(this.accountAsSigner, this.signers[0].address, threshold);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, this.signers[0]),
    ).to.eventually.eq(this.threshold);
  });

  it('reverts when installing twice', async function () {
    await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    await expect(this.mockFromAccount.onInstall(this.installData)).to.be.revertedWithCustomError(
      this.mock,
      'ERC7579MultisigAlreadyInstalled',
    );
  });

  it('reverts when installing with empty signers', async function () {
    const encryptedThreshold = await fhevm
      .createEncryptedInput(this.mock.target, this.mockAccount.address)
      .add32(1)
      .encrypt();

    const emptyInstallData = ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes', 'bytes32[]', 'bytes32'],
      [encryptedThreshold.inputProof, [], encryptedThreshold.handles[0]],
    );

    await expect(this.mockFromAccount.onInstall(emptyInstallData)).to.be.revertedWithCustomError(
      this.mock,
      'ERC7579MultisigEmptySigners',
    );
  });

  it('cleans up signers and threshold on uninstallation', async function () {
    await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

    const signerCount = await this.mock.getSignerCount(this.mockAccount.address);
    expect(signerCount).to.equal(0);

    await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(ethers.ZeroHash);
  });

  describe('addSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can add EOA signers', async function () {
      const signersBefore = await this.mock.getSignerCount(this.mockAccount.address);

      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(this.nonSigners[0].address);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await expect(this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
        .withArgs(this.mockAccount.address, newSigner);

      await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(signersBefore + 1n);
      await expect(this.mock.isSigner(this.mockAccount.address, newSigner)).to.eventually.be.true;
      await allowHandle(this.accountAsSigner, this.signers[0].address, newSigner);
      const decryptedId = await fhevm.userDecryptEuint(
        FhevmType.euint256,
        newSigner,
        this.mockAccount.address,
        this.signers[0],
      );
      expect(ethers.getAddress(ethers.hexlify(ethers.toBeHex(decryptedId), 20))).to.eq(this.nonSigners[0].address);
    });

    it('can add ERC-7913 signers', async function () {
      const signersBefore = await this.mock.getSignerCount(this.mockAccount.address);

      // Encrypt the signer: ERC-7913 keys are hashed with keccak256, then cast to uint256
      const signerId = ethers.keccak256(this.nonSigners[1].bytes);
      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(signerId);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await expect(this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
        .withArgs(this.mockAccount.address, newSigner);

      await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(signersBefore + 1n);
      await expect(this.mock.isSigner(this.mockAccount.address, newSigner)).to.eventually.be.true;
      await allowHandle(this.accountAsSigner, this.signers[0].address, newSigner);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint256, newSigner, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(signerId);
    });

    it('reverts when adding a duplicate handle', async function () {
      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(this.nonSigners[0].address);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof);

      await expect(
        this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigDuplicateHandle');
    });
  });

  describe('removeSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can remove EOA signers', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);

      const tx = await this.mockFromAccount.removeSigners([signers[0]]);
      await expect(tx)
        .to.emit(this.mock, 'ERC7579MultisigSignerRemoved')
        .withArgs(this.mockAccount.address, signers[0]);

      await expect(this.mock.isSigner(this.mockAccount.address, signers[0])).to.eventually.be.false;
      await allowHandle(this.accountAsSigner, this.signers[0].address, signers[0]);
      const decryptedId = await fhevm.userDecryptEuint(
        FhevmType.euint256,
        signers[0],
        this.mockAccount.address,
        this.signers[0],
      );
      expect(ethers.getAddress(ethers.hexlify(ethers.toBeHex(decryptedId), 20))).to.eq(this.signers[0].address);
    });

    it('can remove ERC-7913 signers', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);

      const tx = await this.mockFromAccount.removeSigners([signers[1]]);
      await expect(tx)
        .to.emit(this.mock, 'ERC7579MultisigSignerRemoved')
        .withArgs(this.mockAccount.address, signers[1]);

      await expect(this.mock.isSigner(this.mockAccount.address, signers[1])).to.eventually.be.false;
      await allowHandle(this.accountAsSigner, this.signers[0].address, signers[1]);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint256, signers[1], this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(ethers.keccak256(this.signers[1].bytes));
    });

    it('reverts when removing a signer that does not exist', async function () {
      await expect(this.mockFromAccount.removeSigners([ethers.id('random handle')])).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579MultisigNonexistentSigner',
      );
    });

    it('reverts when there are no signers left', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await expect(
        this.mockFromAccount.removeSigners(signers.map(signer => ethers.hexlify(signer))),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigEmptySigners');
    });
  });

  describe('setThreshold', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can set threshold', async function () {
      const newThreshold = 2;

      const thresholdInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      thresholdInput.add32(newThreshold);
      const encryptedThreshold = await thresholdInput.encrypt();

      await expect(this.mockFromAccount.setThreshold(encryptedThreshold.handles[0], encryptedThreshold.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
        .withArgs(this.mockAccount.address, anyValue);

      const threshold = await this.mock.threshold(this.mockAccount.address);
      await allowHandle(this.accountAsSigner, this.signers[0].address, threshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(newThreshold);
    });

    it('caps threshold at the number of signers', async function () {
      const newThreshold = 3;

      const thresholdInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      thresholdInput.add32(newThreshold);
      const encryptedThreshold = await thresholdInput.encrypt();

      await expect(this.mockFromAccount.setThreshold(encryptedThreshold.handles[0], encryptedThreshold.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
        .withArgs(this.mockAccount.address, anyValue);

      const threshold = await this.mock.threshold(this.mockAccount.address);
      await allowHandle(this.accountAsSigner, this.signers[0].address, threshold);
      const totalSigners = await this.mock.getSignerCount(this.mockAccount.address);
      expect(totalSigners).to.be.lessThan(newThreshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(totalSigners);
    });
  });
}

module.exports = {
  shouldBehaveLikeERC7579MultisigConfidential,
};
