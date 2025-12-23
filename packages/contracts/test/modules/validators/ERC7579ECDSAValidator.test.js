const { ethers, predeploy } = require('hardhat');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { expect } = require('chai');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { ERC4337Helper } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');

const { shouldBehaveLikeERC7579Module, shouldBehaveLikeERC7579Validator } = require('../ERC7579Module.behavior');

async function fixture() {
  const [other] = await ethers.getSigners();

  // Deploy ERC-7579 ECDSA validator module
  const mock = await ethers.deployContract('$ERC7579ECDSAValidator');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  // Prepare signer
  const signer = ethers.Wallet.createRandom();
  const signUserOp = userOp =>
    signer
      .signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed)
      .then(signature => Object.assign(userOp, { signature }));

  // Prepare module installation data
  const installData = ethers.solidityPacked(['address'], [signer.address]);

  // ERC-7579 account
  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));

  // Additional signers for testing
  const newSigner = ethers.Wallet.createRandom();
  const newSignerInstallData = ethers.solidityPacked(['address'], [newSigner.address]);

  return {
    moduleType: MODULE_TYPE_VALIDATOR,
    mock,
    mockFromAccount,
    mockAccount,
    other,
    signer,
    newSigner,
    signUserOp,
    installData,
    newSignerInstallData,
  };
}

describe('ERC7579ECDSAValidator', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();
  shouldBehaveLikeERC7579Validator();

  describe('signer management', function () {
    describe('signer', function () {
      it('returns zero address for uninstalled account', async function () {
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(ethers.ZeroAddress);
      });

      it('returns configured signer after installation', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);
      });

      it('returns zero address after uninstallation', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await this.mockFromAccount.onUninstall('0x');
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(ethers.ZeroAddress);
      });
    });

    describe('onInstall', function () {
      it('sets signer on first installation', async function () {
        await expect(this.mockFromAccount.onInstall(this.installData))
          .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.signer.address);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);
      });

      it('reverts when installing twice', async function () {
        await this.mockFromAccount.onInstall(this.installData);

        // Subsequent installation should revert
        await expect(this.mockFromAccount.onInstall(this.newSignerInstallData)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579ECDSAValidatorAlreadyInstalled',
        );
      });

      it('reverts if data is too short', async function () {
        const shortData = '0x12345678901234567890123456789012345678'; // 19 bytes
        await expect(this.mockFromAccount.onInstall(shortData)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579ECDSAValidatorInvalidSignerLength',
        );
      });

      it('accepts data with exactly 20 bytes', async function () {
        const exactData = ethers.solidityPacked(['address'], [this.signer.address]);
        await expect(this.mockFromAccount.onInstall(exactData))
          .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.signer.address);
      });

      it('accepts data longer than 20 bytes and uses first 20 bytes', async function () {
        const longData = ethers.solidityPacked(['address', 'uint256'], [this.signer.address, 12345]);
        await expect(this.mockFromAccount.onInstall(longData))
          .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.signer.address);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);
      });

      it('reverts when trying to install with zero address', async function () {
        const zeroAddressData = ethers.solidityPacked(['address'], [ethers.ZeroAddress]);
        await expect(this.mockFromAccount.onInstall(zeroAddressData))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ECDSAValidatorInvalidSigner')
          .withArgs(ethers.ZeroAddress);
      });
    });

    describe('onUninstall', function () {
      it('clears signer when installed', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);

        await expect(this.mockFromAccount.onUninstall('0x'))
          .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
          .withArgs(this.mockAccount.address, ethers.ZeroAddress);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(ethers.ZeroAddress);
      });

      it('does nothing when no signer is configured', async function () {
        // Should not emit event when no signer is configured (no-op)
        await expect(this.mockFromAccount.onUninstall('0x')).to.not.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet');

        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(ethers.ZeroAddress);
      });
    });

    describe('setSigner', function () {
      beforeEach(async function () {
        await this.mockFromAccount.onInstall(this.installData);
      });

      it('allows account to set new signer', async function () {
        await expect(this.mockFromAccount.setSigner(this.mockAccount.address, this.newSigner.address))
          .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.newSigner.address);

        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.newSigner.address);
      });

      it('reverts when trying to set signer to zero address', async function () {
        await expect(this.mockFromAccount.setSigner(this.mockAccount.address, ethers.ZeroAddress))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ECDSAValidatorInvalidSigner')
          .withArgs(ethers.ZeroAddress);
      });

      it('reverts when called by unauthorized address', async function () {
        await expect(this.mock.connect(this.other).setSigner(this.mockAccount.address, this.newSigner.address))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ECDSAValidatorNotAuthorized')
          .withArgs(this.other.address, this.mockAccount.address);
      });

      it('reverts when trying to set signer for different account', async function () {
        await expect(this.mockFromAccount.setSigner(this.other.address, this.newSigner.address))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ECDSAValidatorNotAuthorized')
          .withArgs(this.mockAccount.address, this.other.address);
      });
    });
  });

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    describe('_rawERC7579Validation', function () {
      it('validates correct ECDSA signature', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.signer.signMessage(message);

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.true;
      });

      it('rejects signature from wrong signer', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.newSigner.signMessage(message); // Wrong signer

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.false;
      });

      it('rejects invalid signature format', async function () {
        const hash = ethers.hashMessage('Hello, world!');
        const invalidSignature = '0x1234'; // Too short

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, invalidSignature)).to
          .eventually.be.false;
      });

      it('rejects signature for account with no signer', async function () {
        // Uninstall to clear signer
        await this.mockFromAccount.onUninstall('0x');

        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.signer.signMessage(message);

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.false;
      });
    });

    describe('validateUserOp', function () {
      it('validates user operation with correct signature', async function () {
        const userOp = await this.mockAccount
          .createUserOp({
            sender: this.mockAccount.address,
            nonce: 0,
            initCode: '0x',
            callData: '0x',
            accountGasLimits: ethers.solidityPacked(['uint128', 'uint128'], [150000, 150000]),
            preVerificationGas: 21000,
            gasFees: ethers.solidityPacked(['uint128', 'uint128'], [1000000000, 1000000000]),
            paymasterAndData: '0x',
            signature: '0x',
          })
          .then(op => this.signUserOp(op));

        await expect(this.mockFromAccount.validateUserOp(userOp.packed, userOp.hash())).to.eventually.equal(0);
      });

      it('rejects user operation with invalid signature', async function () {
        const userOp = await this.mockAccount.createUserOp({
          sender: this.mockAccount.address,
          nonce: 0,
          initCode: '0x',
          callData: '0x',
          accountGasLimits: ethers.solidityPacked(['uint128', 'uint128'], [150000, 150000]),
          preVerificationGas: 21000,
          gasFees: ethers.solidityPacked(['uint128', 'uint128'], [1000000000, 1000000000]),
          paymasterAndData: '0x',
          signature: '0x1234', // Invalid signature
        });

        await expect(this.mockFromAccount.validateUserOp(userOp.packed, userOp.hash())).to.eventually.equal(1);
      });
    });
  });

  it('handles reinstallation after uninstallation', async function () {
    // Install
    await expect(this.mockFromAccount.onInstall(this.installData))
      .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
      .withArgs(this.mockAccount.address, this.signer.address);
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);

    // Uninstall
    await expect(this.mockFromAccount.onUninstall('0x'))
      .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
      .withArgs(this.mockAccount.address, ethers.ZeroAddress);
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(ethers.ZeroAddress);

    // Reinstall with different signer
    await expect(this.mockFromAccount.onInstall(this.newSignerInstallData))
      .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
      .withArgs(this.mockAccount.address, this.newSigner.address);
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.newSigner.address);
  });

  it('handles multiple setSigner calls', async function () {
    await this.mockFromAccount.onInstall(this.installData);

    // Change signer multiple times
    await expect(this.mockFromAccount.setSigner(this.mockAccount.address, this.newSigner.address))
      .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
      .withArgs(this.mockAccount.address, this.newSigner.address);
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.newSigner.address);

    await expect(this.mockFromAccount.setSigner(this.mockAccount.address, this.signer.address))
      .to.emit(this.mock, 'ERC7579ECDSAValidatorSignerSet')
      .withArgs(this.mockAccount.address, this.signer.address);
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);

    // Attempting to set to zero address should fail
    await expect(this.mockFromAccount.setSigner(this.mockAccount.address, ethers.ZeroAddress))
      .to.be.revertedWithCustomError(this.mock, 'ERC7579ECDSAValidatorInvalidSigner')
      .withArgs(ethers.ZeroAddress);

    // Signer should remain unchanged
    await expect(this.mock.signer(this.mockAccount.address)).to.eventually.equal(this.signer.address);
  });
});
