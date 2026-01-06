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

const { shouldBehaveLikeERC7579Module } = require('../../test/modules/ERC7579Module.behavior');
const { allowHandle } = require('../helpers/fhe');
const { MAX_UINT32 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();
const signerECDSA3 = ethers.Wallet.createRandom();

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

    // Prepare plaintext signers and threshold
    const signers = [signerECDSA1.address, signerECDSA2.address];
    const threshold = 1;
    const multiSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, signerECDSA2]));

    // Encrypt signers and threshold using fhevm
    const input = fhevm.createEncryptedInput(mock.target, mockAccount.address);
    input.add32(threshold);
    signers.forEach(signer => input.addAddress(signer));
    const encrypted = await input.encrypt();
    const encryptedThreshold = encrypted.handles.at(0);
    const signerHandles = encrypted.handles.slice(1);
    const inputProof = encrypted.inputProof;

    Object.assign(this, {
      moduleType: MODULE_TYPE_VALIDATOR,
      mock,
      mockAccount,
      accountAsSigner,
      mockFromAccount,
      mockAccountFromEntrypoint,
      installData: ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes', 'bytes32[]', 'bytes32'],
        [inputProof, signerHandles.map(handle => ethers.hexlify(handle)), encryptedThreshold],
      ),
      signers,
      signerHandles,
      threshold,
      encryptedThreshold,
      multiSigner,
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

    await expect(this.mock.getSignerCount(this.mockAccount.address)).to.eventually.equal(this.signers.length);

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

    it('can add signers', async function () {
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
    });
  });

  describe('removeSigners', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('can remove signers', async function () {
      const signers = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);

      const tx = await this.mockFromAccount.removeSigners([signers[0]]);
      await expect(tx)
        .to.emit(this.mock, 'ERC7579MultisigSignerRemoved')
        .withArgs(this.mockAccount.address, signers[0]);

      await expect(this.mock.isSigner(this.mockAccount.address, signers[0])).to.eventually.be.false;
      await allowHandle(this.accountAsSigner, signerECDSA1.address, signers[0]);
      await expect(fhevm.userDecryptEaddress(signers[0], this.mockAccount.address, signerECDSA1)).to.eventually.eq(
        signerECDSA1.address,
      );
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
});
