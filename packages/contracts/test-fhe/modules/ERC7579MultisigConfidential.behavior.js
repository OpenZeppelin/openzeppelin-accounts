const { ethers, fhevm } = require('hardhat');
const { expect } = require('chai');
const { FhevmType } = require('@fhevm/hardhat-plugin');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');

const { allowHandle } = require('../helpers/fhe');
const { MAX_UINT32 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');
const {
  NonNativeSigner,
  MultiERC7913SigningKey,
} = require('../../../../lib/@openzeppelin-contracts/test/helpers/signers');

const toId = signer =>
  ethers.isAddress(ethers.hexlify(signer))
    ? BigInt(ethers.getAddress(ethers.hexlify(signer)))
    : BigInt(ethers.keccak256(signer));

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

function shouldBehaveLikeOperationDiscloser() {
  const operation = 'test operation';
  const operationHash = ethers.hashMessage(operation);

  describe('operation disclosure', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);

      this.requestDiscloseOperation = async (signer, runner = this.mock.runner) => {
        const decryptor = this.signers[0];
        const signerHandles = await this.mock.connect(runner).getSigners(this.mockAccount.address, 0, MAX_UINT32);
        await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, decryptor.address, handle)));

        const signerIds = [];
        for (const handle of signerHandles) {
          const decryptedId = await fhevm.userDecryptEuint(
            FhevmType.euint256,
            handle,
            this.mockAccount.address,
            decryptor,
          );
          signerIds.push(decryptedId);
        }

        const signature = await signer.signMessage(operation);
        const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
          ['bytes[]', 'bytes[]'],
          signature,
        );

        const receipt = await this.mock
          .requestDiscloseOperation(
            this.mockAccount.address,
            operationHash,
            signingSigners.map(signer => ethers.hexlify(signer)),
            signingSigners.map(signer => ethers.hexlify(signerHandles[signerIds.findIndex(id => id === toId(signer))])),
            signatures.map(sig => ethers.hexlify(sig)),
          )
          .then(tx => tx.wait());

        const [[, , , encryptedBool]] = receipt.logs
          .map(log => this.mock.interface.parseLog(log))
          .filter(log => log?.name === 'ERC7579MultisigOperationDiscloseRequested')
          .map(log => log.args.map(arg => ethers.hexlify(arg)));

        return {
          receipt,
          encryptedBool,
        };
      };
    });

    it('requestDiscloseOperation sets requested disclosure and requestedDisclosure returns non-zero handle', async function () {
      await expect(this.mock.requestedDisclosure(this.mock.runner.address, operationHash)).to.eventually.equal(
        ethers.ZeroHash,
      );

      const { encryptedBool, receipt } = await this.requestDiscloseOperation(
        new NonNativeSigner(new MultiERC7913SigningKey([...this.signers])),
      );
      expect(receipt)
        .to.emit(this.mock, 'ERC7579MultisigOperationDiscloseRequested')
        .withArgs(this.mock.runner.address, this.mockAccount.address, operationHash, anyValue);

      await expect(this.mock.requestedDisclosure(this.mock.runner.address, operationHash)).to.eventually.equal(
        encryptedBool,
      );
    });

    it('requestDisclosure can be called with validation result from _validateMultisig', async function () {
      const decryptor = this.signers[0];
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, decryptor.address, handle)));

      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(
          FhevmType.euint256,
          handle,
          this.mockAccount.address,
          decryptor,
        );
        signerIds.push(decryptedId);
      }

      const signer = new NonNativeSigner(new MultiERC7913SigningKey([...this.signers]));
      const signature = await signer.signMessage(operation);
      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes[]', 'bytes[]'], signature);

      // Call _validateMultisig separately through a test helper or directly
      const receipt = await this.mockFromAccount
        .$_validateMultisig(
          this.mockAccount.address,
          operationHash,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => ethers.hexlify(signerHandles[signerIds.findIndex(id => id === toId(signer))])),
          signatures.map(sig => ethers.hexlify(sig)),
        )
        .then(tx => tx.wait());

      // Extract the validation result (ebool)
      const [[validationResult]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_validateMultisig')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      // Verify disclosure hasn't been requested yet
      await expect(this.mock.requestedDisclosure(this.mock.runner.address, operationHash)).to.eventually.equal(
        ethers.ZeroHash,
      );

      // Request disclosure using the validation result directly
      const disclosureReceipt = await this.mock
        .requestDisclosure(this.mockAccount.address, operationHash, validationResult)
        .then(tx => tx.wait());

      // Verify the event was emitted
      expect(disclosureReceipt)
        .to.emit(this.mock, 'ERC7579MultisigOperationDiscloseRequested')
        .withArgs(this.mock.runner.address, this.mockAccount.address, operationHash, validationResult);

      // Verify disclosure was requested
      await expect(this.mock.requestedDisclosure(this.mock.runner.address, operationHash)).to.eventually.equal(
        validationResult,
      );

      // Now disclose the operation
      const decryptResult = await fhevm.publicDecrypt([validationResult]);
      await this.mock.discloseOperation(
        ethers.Typed.address(this.mock.runner.address),
        operationHash,
        decryptResult.decryptionProof,
      );

      // Verify it was disclosed
      await expect(this.mock.disclosed(operationHash)).to.eventually.be.true;
    });

    it('discloses operation and sets disclosed to true', async function () {
      await expect(this.mock.disclosed(operationHash)).to.eventually.be.false;

      const { encryptedBool } = await this.requestDiscloseOperation(
        new NonNativeSigner(new MultiERC7913SigningKey([...this.signers])),
      );

      const decryptResult = await fhevm.publicDecrypt([encryptedBool]);
      await this.mock.discloseOperation(
        ethers.Typed.address(this.mock.runner.address),
        operationHash,
        decryptResult.decryptionProof,
      );
      await expect(this.mock.disclosed(operationHash)).to.eventually.be.true;
    });

    it('does not override disclosure request when called by different runner', async function () {
      const { encryptedBool: encryptedBool1 } = await this.requestDiscloseOperation(
        new NonNativeSigner(new MultiERC7913SigningKey([...this.signers])),
      );

      await expect(this.mock.requestedDisclosure(this.mock.runner.address, operationHash)).to.eventually.equal(
        encryptedBool1,
      );

      // Second request from different runner
      const { encryptedBool: encryptedBool2 } = await this.requestDiscloseOperation(
        new NonNativeSigner(new MultiERC7913SigningKey([...this.signers])),
        this.other,
      );

      await expect(this.mock.requestedDisclosure(this.other.address, operationHash)).to.eventually.equal(
        encryptedBool2,
      );

      // Verify first request is still intact (not overridden)
      const decryptResult = await fhevm.publicDecrypt([encryptedBool1]);
      await this.mock.discloseOperation(operationHash, decryptResult.decryptionProof);
      await expect(this.mock.disclosed(operationHash)).to.eventually.be.true;
    });

    it('discloseOperation reverts with ERC7579MultisigUnknownDisclosure for unknown hash', async function () {
      const unknownHash = ethers.id('never requested');
      await expect(this.mock.discloseOperation(ethers.Typed.address(this.mock.runner.address), unknownHash, '0x'))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnknownDisclosure')
        .withArgs(unknownHash);
    });
  });
}

function shouldBehaveLikeERC7579MultisigConfidentialWeighted() {
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

    await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(
      this.signer.signingKey.signers.length,
    );

    const threshold = await this.mockFromAccount.threshold(this.mockAccount.address);
    await allowHandle(this.accountAsSigner, this.signers[0].address, threshold);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, this.signers[0]),
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
      await allowHandle(this.accountAsSigner, this.signers[0].address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(this.weights[i]);
    }

    // Verify total weight
    const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
    const [[totalWeight]] = receipt.logs
      .map(log => this.mock.interface.parseLog(log))
      .filter(log => log?.name === 'return$_totalWeight')
      .map(log => log.args.map(arg => ethers.hexlify(arg)));
    await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeight);
    const expectedTotalWeight = this.weights.reduce((sum, w) => sum + w, 0);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, this.signers[0]),
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

    await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(ethers.ZeroHash);
    await expect(this.mock.totalExtraWeight(this.mockAccount.address)).to.eventually.equal(ethers.ZeroHash);

    const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
    for (const signer of signers) {
      await expect(this.mock.extraWeight(this.mockAccount.address, signer)).to.eventually.equal(ethers.ZeroHash);
    }
  });

  describe('addSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can add EOA signers with default weight of 1', async function () {
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

      const receipt = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, newSigner)
        .then(tx => tx.wait());
      const [[weight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, this.signers[0].address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(1);
    });

    it('can add ERC-7913 signers with default weight of 1', async function () {
      const signersBefore = await this.mock.getSignerCount(this.mockAccount.address);

      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(ethers.keccak256(this.signers[1].bytes));
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
      ).to.eventually.eq(ethers.keccak256(this.signers[1].bytes));

      const receipt = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, newSigner)
        .then(tx => tx.wait());
      const [[weight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, this.signers[0].address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, this.signers[0]),
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
        await allowHandle(this.accountAsSigner, this.signers[0].address, weight);
        await expect(
          fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, this.signers[0]),
        ).to.eventually.eq(newWeights[i]);
      }

      // Verify total weight was updated
      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeight);
      const expectedTotalWeight = newWeights.reduce((sum, w) => sum + w, 0);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, this.signers[0]),
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
      const fakeSigner = ethers.id('fake signer');
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
      await allowHandle(this.accountAsSigner, this.signers[0].address, weight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, weight, this.mockAccount.address, this.signers[0]),
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
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeightBefore);
      const totalWeightBeforeDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint32,
        totalWeightBefore,
        this.mockAccount.address,
        this.signers[0],
      );

      const receipt2 = await this.mockFromAccount
        .$_signerWeight(this.mockAccount.address, signers[0])
        .then(tx => tx.wait());
      const [[weightToRemove]] = receipt2.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_signerWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, this.signers[0].address, weightToRemove);
      const weightToRemoveDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint16,
        weightToRemove,
        this.mockAccount.address,
        this.signers[0],
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
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeightAfter);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeightAfter, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(totalWeightBeforeDecrypted - weightToRemoveDecrypted);

      const extraWeight = await this.mock.extraWeight(this.mockAccount.address, signers[0]);
      await allowHandle(this.accountAsSigner, this.signers[0].address, extraWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight, this.mockAccount.address, this.signers[0]),
      ).to.eventually.equal(0);
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

    it('caps threshold at the total weight', async function () {
      const receipt = await this.mockFromAccount.$_totalWeight(this.mockAccount.address).then(tx => tx.wait());
      const [[totalWeight]] = receipt.logs
        .map(log => this.mock.interface.parseLog(log))
        .filter(log => log?.name === 'return$_totalWeight')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeight);
      const totalWeightDecrypted = await fhevm.userDecryptEuint(
        FhevmType.euint32,
        totalWeight,
        this.mockAccount.address,
        this.signers[0],
      );

      const newThreshold = totalWeightDecrypted + 10n; // Threshold exceeds total weight

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
      ).to.eventually.eq(totalWeightDecrypted);
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

      await allowHandle(this.accountAsSigner, this.signers[0].address, extraWeight1);
      await allowHandle(this.accountAsSigner, this.signers[0].address, extraWeight2);

      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight1, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(this.weights[0] - 1);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint16, extraWeight2, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(this.weights[1] - 1);

      const totalExtraWeight = await this.mockFromAccount.totalExtraWeight(this.mockAccount.address);
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalExtraWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalExtraWeight, this.mockAccount.address, this.signers[0]),
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
      await allowHandle(this.accountAsSigner, this.signers[0].address, totalWeight);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, totalWeight, this.mockAccount.address, this.signers[0]),
      ).to.eventually.eq(8);
    });
  });
}

module.exports = {
  toId,
  shouldBehaveLikeERC7579MultisigConfidential,
  shouldBehaveLikeERC7579MultisigConfidentialWeighted,
  shouldBehaveLikeOperationDiscloser,
};
