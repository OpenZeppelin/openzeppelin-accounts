const { ethers, fhevm, predeploy } = require('hardhat');
const { expect } = require('chai');
const { FhevmType } = require('@fhevm/hardhat-plugin');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');

const { impersonate } = require('../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { ERC4337Helper } = require('../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const {
  NonNativeSigner,
  MultiERC7913SigningKey,
} = require('../../../../lib/@openzeppelin-contracts/test/helpers/signers');

const { shouldBehaveLikeERC7579Module } = require('./ERC7579Module.behavior');
const { allowHandle } = require('../helpers/fhe');
const { MAX_UINT32 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();
const signerECDSA3 = ethers.Wallet.createRandom();

describe('ERC7579MultisigWeightedConfidential', function () {
  beforeEach(async function () {
    // Deploy ERC-7579 multisig weighted confidential module
    const mock = await ethers.deployContract('$ERC7579MultisigWeightedConfidentialMock');

    // ERC-4337 env
    const helper = new ERC4337Helper();
    await helper.wait();

    // ERC-7579 account
    const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
    const accountAsSigner = await impersonate(mockAccount.address);
    const mockFromAccount = mock.connect(accountAsSigner);
    const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
      mockAccount.connect(asEntrypoint),
    );

    await mockAccount.deploy();

    // Prepare plaintext signers, weights, and threshold
    const signers = [signerECDSA1.address, signerECDSA2.address];
    const weights = [1, 2]; // Signer 1 has weight 1, signer 2 has weight 2
    const threshold = 2; // Require total weight of 2
    const multiSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, signerECDSA2]));

    // Encrypt signers, weights, and threshold using fhevm
    const input = fhevm.createEncryptedInput(mock.target, mockAccount.address);
    input.add32(threshold);
    signers.forEach(signer => input.addAddress(signer));
    weights.forEach(weight => input.add16(weight));
    const encrypted = await input.encrypt();
    const encryptedThreshold = encrypted.handles.at(0);
    const signerHandles = encrypted.handles.slice(1, 1 + signers.length);
    const weightHandles = encrypted.handles.slice(1 + signers.length);
    const inputProof = encrypted.inputProof;

    Object.assign(this, {
      moduleType: MODULE_TYPE_VALIDATOR,
      mock,
      mockAccount,
      accountAsSigner,
      mockFromAccount,
      mockAccountFromEntrypoint,
      installData: ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes', 'bytes32[]', 'bytes32', 'bytes32[]'],
        [
          inputProof,
          signerHandles.map(handle => ethers.hexlify(handle)),
          encryptedThreshold,
          weightHandles.map(handle => ethers.hexlify(handle)),
        ],
      ),
      signers,
      signerHandles,
      weights,
      weightHandles,
      threshold,
      encryptedThreshold,
      multiSigner,
    });
  });

  shouldBehaveLikeERC7579Module();

  it('sets initial signers, weights, and threshold on installation', async function () {
    await expect(this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData))
      .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
      .withArgs(this.mockAccount.address, this.signerHandles[0])
      .withArgs(this.mockAccount.address, this.signerHandles[1])
      .to.emit(this.mock, 'ERC7579MultisigWeightChanged')
      .withArgs(this.mockAccount.address, this.signerHandles[0], anyValue)
      .withArgs(this.mockAccount.address, this.signerHandles[1], anyValue)
      .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
      .withArgs(this.mockAccount.address, anyValue);

    await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(this.signers.length);

    const threshold = await this.mockFromAccount.threshold(this.mockAccount.address);
    await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
    ).to.eventually.eq(this.threshold);

    // Verify weights
    for (let i = 0; i < this.signers.length; i++) {
      const receipt = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, this.signerHandles[i])
        .then(tx => tx.wait());
      const [[weight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(this.weights[i]);
    }

    // Verify total weight
    const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
    const [[totalWeight]] = receipt.logs
      .map(log => this.mock.interface.parseLog(log))
      .filter(log => log?.name === 'return$_totalWeight')
      .map(log => log.args.map(arg => ethers.hexlify(arg)));
    await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeight);
    const expectedTotalWeight = this.weights.reduce((sum, w) => sum + w, 0);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, signerECDSA1),
    ).to.eventually.eq(expectedTotalWeight);
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
      ['bytes', 'bytes32[]', 'bytes32', 'bytes32[]'],
      [encryptedThreshold.inputProof, [], encryptedThreshold.handles[0], []],
    );

    await expect(this.mockFromAccount.onInstall(emptyInstallData)).to.be.revertedWithCustomError(
      this.mock,
      'ERC7579MultisigEmptySigners',
    );
  });

  it('cleans up signers, weights, and threshold on uninstallation', async function () {
    await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

    const signerCount = await this.mock.getSignerCount(this.mockAccount.address);
    expect(signerCount).to.equal(0);

    const threshold = await this.mock.threshold(this.mockAccount.address);
    await expect(fhevm.publicDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address)).to.eventually.equal(
      0,
    );

    const totalExtraWeight = await this.mock.totalExtraWeight(this.mockAccount.address);
    await expect(
      fhevm.publicDecryptEuint(FhevmType.euint32, totalExtraWeight, this.mockAccount.address),
    ).to.eventually.equal(0);

    const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
    for (const signer of signers) {
      const extraWeight = await this.mock.extraWeight(this.mockAccount.address, signer);
      await allowHandle(this.accountAsSigner, signerECDSA1.address, extraWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.equal(0);
    }
  });

  describe('addSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can add signers with default weight of 1', async function () {
      const signersBefore = await this.mock.getSignerCount(this.mockAccount.address);

      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.addAddress(signerECDSA3.address);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await expect(this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
        .withArgs(this.mockAccount.address, newSigner);

      await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(signersBefore + 1n);
      await expect(this.mock.isSigner(this.mockAccount.address, newSigner)).to.eventually.be.true;
      await allowHandle(this.accountAsSigner, signerECDSA1.address, newSigner);
      await expect(fhevm.userDecryptEaddress(newSigner, this.mockAccount.address, signerECDSA1)).to.eventually.eq(
        signerECDSA3.address,
      );

      const receipt = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, newSigner)
        .then(tx => tx.wait());
      const [[weight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(1);
    });
  });

  describe('setSignerWeights', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can set signer weights', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const newWeights = [3, 4];

      const weightInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newWeights.forEach(weight => weightInput.add16(weight));
      const encryptedWeights = await weightInput.encrypt();
      const weightHandles = encryptedWeights.handles.map(handle => ethers.hexlify(handle));

      await expect(
        this.mockFromAccount.setSignerWeights(
          signerHandles.map(handle => ethers.hexlify(handle)),
          weightHandles,
          encryptedWeights.inputProof,
        ),
      )
        .to.emit(this.mock, 'ERC7579MultisigWeightChanged')
        .withArgs(this.mockAccount.address, signerHandles[0], anyValue)
        .withArgs(this.mockAccount.address, signerHandles[1], anyValue);

      // Verify weights were updated
      for (let i = 0; i < signerHandles.length; i++) {
        const receipt = await this.mockFromAccount
          .$_signerWeight(this.mockAccount.address, signerHandles[i])
          .then(tx => tx.wait());
        const [[weight]] = receipt.logs
          .map(log => this.mock.interface.parseLog(log))
          .filter(log => log?.name === 'return$_signerWeight')
          .map(log => log.args.map(arg => ethers.hexlify(arg)));
        await allowHandle(this.accountAsSigner, signerECDSA1.address, weight);
        await expect(
          fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, signerECDSA1),
        ).to.eventually.eq(newWeights[i]);
      }

      // Verify total weight was updated
      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeight);
      const expectedTotalWeight = newWeights.reduce((sum, w) => sum + w, 0);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(expectedTotalWeight);
    });

    it('reverts when signers and weights arrays have mismatched lengths', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const newWeights = [3]; // Only one weight for two signers

      const weightInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newWeights.forEach(weight => weightInput.add16(weight));
      const encryptedWeights = await weightInput.encrypt();
      const weightHandles = encryptedWeights.handles.map(handle => ethers.hexlify(handle));

      await expect(
        this.mockFromAccount.setSignerWeights(
          signerHandles.map(handle => ethers.hexlify(handle)),
          weightHandles,
          encryptedWeights.inputProof,
        ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigMismatchedSignerWeights');
    });

    it('reverts when setting weight for non-existent signer', async function () {
      const fakeSigner = ethers.keccak256(ethers.toUtf8Bytes('fake signer'));
      const newWeights = [3];

      const weightInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newWeights.forEach(weight => weightInput.add16(weight));
      const encryptedWeights = await weightInput.encrypt();
      const weightHandles = encryptedWeights.handles.map(handle => ethers.hexlify(handle));

      await expect(
        this.mockFromAccount.setSignerWeights([fakeSigner], weightHandles, encryptedWeights.inputProof),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner');
    });

    it('converts weight 0 to weight 1 (base weight)', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const newWeights = [0, 2]; // Weight 0 should become 1

      const weightInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newWeights.forEach(weight => weightInput.add16(weight));
      const encryptedWeights = await weightInput.encrypt();
      const weightHandles = encryptedWeights.handles.map(handle => ethers.hexlify(handle));

      await this.mockFromAccount.setSignerWeights(
        signerHandles.map(handle => ethers.hexlify(handle)),
        weightHandles,
        encryptedWeights.inputProof,
      );

      // Verify first signer has weight 1 (converted from 0)
      const receipt = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, signerHandles[0])
        .then(tx => tx.wait());
      const [[weight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(1);
    });
  });

  describe('removeSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can remove signers and updates total weight', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeightBefore]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeightBefore);
      const totalWeightBeforeDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint32,
        totalWeightBefore,
        this.mockAccount.address,
        signerECDSA1,
      );

      const receipt2 = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, signers[0])
        .then(tx => tx.wait());
      const [[weightToRemove]] = receipt2.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, weightToRemove);
      const weightToRemoveDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint16,
        weightToRemove,
        this.mockAccount.address,
        signerECDSA1,
      );

      await expect(this.mockFromAccount.removeSigners([signers[0]]))
        .to.emit(this.mock, 'ERC7579MultisigSignerRemoved')
        .withArgs(this.mockAccount.address, signers[0]);

      await expect(this.mock.isSigner(this.mockAccount.address, signers[0])).to.eventually.be.false;

      // Verify total weight was updated
      const receipt3 = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeightAfter]] = receipt3.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeightAfter);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeightAfter, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(totalWeightBeforeDecrypted - weightToRemoveDecrypted);

      const extraWeight = await this.mock.extraWeight(this.mockAccount.address, signers[0]);
      await allowHandle(this.accountAsSigner, signerECDSA1.address, extraWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.equal(0);
    });

    it('reverts when removing a signer that does not exist', async function () {
      await expect(
        this.mockFromAccount.removeSigners([ethers.keccak256(ethers.toUtf8Bytes('random handle'))]),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner');
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
      await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(newThreshold);
    });

    it('caps threshold at the total weight', async function () {
      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeight);
      const totalWeightDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint32,
        totalWeight,
        this.mockAccount.address,
        signerECDSA1,
      );

      const newThreshold = totalWeightDecrypted + 10n; // Threshold exceeds total weight

      const thresholdInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      thresholdInput.add32(newThreshold);
      const encryptedThreshold = await thresholdInput.encrypt();

      await expect(this.mockFromAccount.setThreshold(encryptedThreshold.handles[0], encryptedThreshold.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
        .withArgs(this.mockAccount.address, anyValue);

      const threshold = await this.mock.threshold(this.mockAccount.address);
      await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(totalWeightDecrypted);
    });
  });

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('validates signatures with weights meeting threshold', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));
      const signers = [];
      for (const handle of signerHandles) {
        signers.push(await fhevm.userDecryptEaddress(handle, this.mockAccount.address, signerECDSA1));
      }

      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      // Sign with signer 2 (weight 2) which should meet threshold of 2
      const signature = await signerECDSA2.signMessage(testMessage);

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          messageHash,
          [signerECDSA2.address],
          [ethers.hexlify(signerHandles[signers.findIndex(s => ethers.getAddress(s) === signerECDSA2.address)])],
          [signature],
        )
        .then(tx => tx.wait());

      const [[encryptedBool]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_validateMultisig')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      await allowHandle(this.accountAsSigner, signerECDSA1.address, encryptedBool);
      await expect(fhevm.userDecryptEbool(encryptedBool, this.mockAccount.address, signerECDSA1)).to.eventually.be.true;
    });

    it('validates multiple signatures with combined weights meeting threshold', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));
      const signers = [];
      for (const handle of signerHandles) {
        signers.push(await fhevm.userDecryptEaddress(handle, this.mockAccount.address, signerECDSA1));
      }

      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await this.multiSigner.signMessage(testMessage);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      // Combined weight: signer1 (1) + signer2 (2) = 3, threshold is 2
      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          messageHash,
          signingSigners.map(signer => ethers.getAddress(ethers.hexlify(signer.slice(0, 42)))),
          signingSigners.map(signer =>
            ethers.hexlify(
              signerHandles[signers.findIndex(handle => ethers.getAddress(signer) === ethers.getAddress(handle))],
            ),
          ),
          signatures.map(signature => ethers.hexlify(signature)),
        )
        .then(tx => tx.wait());

      const [[encryptedBool]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_validateMultisig')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      await allowHandle(this.accountAsSigner, signerECDSA1.address, encryptedBool);
      await expect(fhevm.userDecryptEbool(encryptedBool, this.mockAccount.address, signerECDSA1)).to.eventually.be.true;
    });

    it('does not validate when combined weights do not meet threshold', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));
      const signers = [];
      for (const handle of signerHandles) {
        signers.push(await fhevm.userDecryptEaddress(handle, this.mockAccount.address, signerECDSA1));
      }

      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      // Sign with signer 1 (weight 1), threshold is 2
      const signature = await signerECDSA1.signMessage(testMessage);

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          messageHash,
          [signerECDSA1.address],
          [ethers.hexlify(signerHandles[signers.findIndex(s => ethers.getAddress(s) === signerECDSA1.address)])],
          [signature],
        )
        .then(tx => tx.wait());

      const [[encryptedBool]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_validateMultisig')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      await allowHandle(this.accountAsSigner, signerECDSA1.address, encryptedBool);
      await expect(fhevm.userDecryptEbool(encryptedBool, this.mockAccount.address, signerECDSA1)).to.eventually.be
        .false;
    });

    it('does not validate invalid signatures', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));
      const signers = [];
      for (const handle of signerHandles) {
        signers.push(await fhevm.userDecryptEaddress(handle, this.mockAccount.address, signerECDSA1));
      }

      const testMessage = 'test';
      const multiSignature = await this.multiSigner.signMessage(testMessage);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          ethers.hashMessage('different message'),
          signingSigners.map(signer => ethers.getAddress(ethers.hexlify(signer.slice(0, 42)))),
          signingSigners.map(signer =>
            ethers.hexlify(
              signerHandles[signers.findIndex(handle => ethers.getAddress(signer) === ethers.getAddress(handle))],
            ),
          ),
          signatures.map(signature => ethers.hexlify(signature)),
        )
        .then(tx => tx.wait());

      const [[encryptedBool]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_validateMultisig')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      await allowHandle(this.accountAsSigner, signerECDSA1.address, encryptedBool);
      await expect(fhevm.userDecryptEbool(encryptedBool, this.mockAccount.address, signerECDSA1)).to.eventually.be
        .false;
    });
  });

  describe('weight management', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('tracks extra weight correctly', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const extraWeight1 = await this.mockFromAccount.extraWeight(this.mockAccount.address, signerHandles[0]);
      const extraWeight2 = await this.mockFromAccount.extraWeight(this.mockAccount.address, signerHandles[1]);

      await allowHandle(this.accountAsSigner, signerECDSA1.address, extraWeight1);
      await allowHandle(this.accountAsSigner, signerECDSA1.address, extraWeight2);

      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight1, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(this.weights[0] - 1);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight2, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(this.weights[1] - 1);

      const totalExtraWeight = await this.mockFromAccount.totalExtraWeight(this.mockAccount.address);
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalExtraWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalExtraWeight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(this.weights.reduce((sum, w) => sum + w, 0) - 2);
    });

    it('updates total weight when weights change', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      const newWeights = [5, 3]; // Total weight should be 8

      const weightInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newWeights.forEach(weight => weightInput.add16(weight));
      const encryptedWeights = await weightInput.encrypt();
      const weightHandles = encryptedWeights.handles.map(handle => ethers.hexlify(handle));

      await this.mockFromAccount.setSignerWeights(
        signerHandles.map(handle => ethers.hexlify(handle)),
        weightHandles,
        encryptedWeights.inputProof,
      );

      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, signerECDSA1.address, totalWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(8);
    });
  });
});
