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
  P256SigningKey,
} = require('../../../../lib/@openzeppelin-contracts/test/helpers/signers');

const { shouldBehaveLikeERC7579Module } = require('../../test/modules/ERC7579Module.behavior');
const { allowHandle } = require('../helpers/fhe');
const { MAX_UINT32 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');

const TEST_MESSAGE = ethers.id('OpenZeppelin');
const TEST_MESSAGE_HASH = ethers.hashMessage(TEST_MESSAGE);

const WRONG_MESSAGE = ethers.id('Nope');
const WRONG_MESSAGE_HASH = ethers.hashMessage(WRONG_MESSAGE);

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();

// Prepare P256 signers for ERC-7913 tests
const aliceP256 = new NonNativeSigner(P256SigningKey.random());
const bobP256 = new NonNativeSigner(P256SigningKey.random());

describe('ERC7579MultisigConfidential', function () {
  beforeEach(async function () {
    // Deploy ERC-7579 multisig confidential module
    const mock = await ethers.deployContract('$ERC7579MultisigConfidentialMock');

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

    // Deploy ERC-7913 verifier
    const verifier = await ethers.deployContract('ERC7913P256Verifier');

    aliceP256.bytes = ethers.concat([
      verifier.target,
      aliceP256.signingKey.publicKey.qx,
      aliceP256.signingKey.publicKey.qy,
    ]);
    bobP256.bytes = ethers.concat([verifier.target, bobP256.signingKey.publicKey.qx, bobP256.signingKey.publicKey.qy]);

    // Prepare signer bytes for encryption and multi-signer
    const threshold = 1;
    const multiSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, aliceP256]));

    // Encrypt signers and threshold using fhevm
    // EOA: cast to uint256, ERC-7913: hash with keccak256 then cast to uint256
    const input = fhevm.createEncryptedInput(mock.target, mockAccount.address);
    input.add32(threshold);
    input.add256(signerECDSA1.address); // EOA: cast to uint256
    input.add256(ethers.keccak256(aliceP256.bytes)); // ERC-7913: hash then cast
    const encrypted = await input.encrypt();
    const signerHandles = encrypted.handles.slice(1);

    Object.assign(this, {
      moduleType: MODULE_TYPE_VALIDATOR,
      mock,
      mockAccount,
      accountAsSigner,
      mockFromAccount,
      mockAccountFromEntrypoint,
      installData: ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes', 'bytes32[]', 'bytes32'],
        [encrypted.inputProof, signerHandles.map(handle => ethers.hexlify(handle)), encrypted.handles.at(0)],
      ),
      signerHandles,
      threshold,
      multiSigner,
      verifier,
    });
  });

  shouldBehaveLikeERC7579Module();

  it('sets initial signers and threshold on installation', async function () {
    await expect(this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData))
      .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
      .withArgs(this.mockAccount.address, this.signerHandles[0])
      .withArgs(this.mockAccount.address, this.signerHandles[1])
      .to.emit(this.mock, 'ERC7579MultisigThresholdSet')
      .withArgs(this.mockAccount.address, anyValue);

    await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(
      this.multiSigner.signingKey.signers.length,
    );

    const threshold = await this.mockFromAccount.threshold(this.mockAccount.address);
    await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
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
      newSignerInput.add256(signerECDSA2.address);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await expect(this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
        .withArgs(this.mockAccount.address, newSigner);

      await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(signersBefore + 1n);
      await expect(this.mock.isSigner(this.mockAccount.address, newSigner)).to.eventually.be.true;
      await allowHandle(this.accountAsSigner, signerECDSA1.address, newSigner);
      const decryptedId = await fhevm.userDecryptEuint(
        FhevmType.euint256,
        newSigner,
        this.mockAccount.address,
        signerECDSA1,
      );
      expect(ethers.getAddress(ethers.hexlify(ethers.toBeHex(decryptedId), 20))).to.eq(signerECDSA2.address);
    });

    it('can add ERC-7913 signers', async function () {
      const signersBefore = await this.mock.getSignerCount(this.mockAccount.address);

      // Encrypt the signer: ERC-7913 keys are hashed with keccak256, then cast to uint256
      const signerId = ethers.keccak256(bobP256.bytes);
      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(signerId);
      const encryptedNewSigner = await newSignerInput.encrypt();
      const newSigner = ethers.hexlify(encryptedNewSigner.handles[0]);

      await expect(this.mockFromAccount.addSigners([newSigner], encryptedNewSigner.inputProof))
        .to.emit(this.mock, 'ERC7579MultisigSignerAdded')
        .withArgs(this.mockAccount.address, newSigner);

      await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(signersBefore + 1n);
      await expect(this.mock.isSigner(this.mockAccount.address, newSigner)).to.eventually.be.true;
      await allowHandle(this.accountAsSigner, signerECDSA1.address, newSigner);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint256, newSigner, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(signerId);
    });

    it('reverts when adding a duplicate handle', async function () {
      const newSignerInput = fhevm.createEncryptedInput(this.mock.target, this.mockAccount.address);
      newSignerInput.add256(signerECDSA2.address);
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
      await allowHandle(this.accountAsSigner, signerECDSA1.address, signers[0]);
      const decryptedId = await fhevm.userDecryptEuint(
        FhevmType.euint256,
        signers[0],
        this.mockAccount.address,
        signerECDSA1,
      );
      expect(ethers.getAddress(ethers.hexlify(ethers.toBeHex(decryptedId), 20))).to.eq(signerECDSA1.address);
    });

    it('can remove ERC-7913 signers', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);

      const tx = await this.mockFromAccount.removeSigners([signers[1]]);
      await expect(tx)
        .to.emit(this.mock, 'ERC7579MultisigSignerRemoved')
        .withArgs(this.mockAccount.address, signers[1]);

      await expect(this.mock.isSigner(this.mockAccount.address, signers[1])).to.eventually.be.false;
      await allowHandle(this.accountAsSigner, signerECDSA1.address, signers[1]);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint256, signers[1], this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(ethers.keccak256(aliceP256.bytes));
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
      await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
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
      await allowHandle(this.accountAsSigner, signerECDSA1.address, threshold);
      const totalSigners = await this.mock.getSignerCount(this.mockAccount.address);
      expect(totalSigners).to.be.lessThan(newThreshold);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint32, threshold, this.mockAccount.address, signerECDSA1),
      ).to.eventually.eq(totalSigners);
    });
  });

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('validates multiple signatures meeting threshold', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));

      // Get signer IDs for matching
      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(
          FhevmType.euint256,
          handle,
          this.mockAccount.address,
          signerECDSA1,
        );
        signerIds.push(decryptedId);
      }

      const multiSignature = await this.multiSigner.signMessage(TEST_MESSAGE);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          TEST_MESSAGE_HASH,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => {
            // For EOA: signer is address bytes, convert to uint256
            // For ERC-7913: signer is verifier||key bytes, hash then convert to uint256
            const signerIndex = signerIds.findIndex(id =>
              id === ethers.isAddress(ethers.hexlify(signer))
                ? ethers.getAddress(ethers.hexlify(signer))
                : ethers.keccak256(signer),
            );
            return ethers.hexlify(signerHandles[signerIndex]);
          }),
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

    it('does not validate invalid signatures', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));

      // Get signer IDs for matching
      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(
          FhevmType.euint256,
          handle,
          this.mockAccount.address,
          signerECDSA1,
        );
        signerIds.push(decryptedId);
      }

      const multiSignature = await this.multiSigner.signMessage(TEST_MESSAGE);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          WRONG_MESSAGE_HASH,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => {
            // For EOA: signer is address bytes, convert to uint256
            // For ERC-7913: signer is verifier||key bytes, hash then convert to uint256
            const signerIndex = signerIds.findIndex(id =>
              id === ethers.isAddress(ethers.hexlify(signer))
                ? ethers.getAddress(ethers.hexlify(signer))
                : ethers.keccak256(signer),
            );
            return ethers.hexlify(signerHandles[signerIndex]);
          }),
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
});
