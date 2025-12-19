const { ethers, predeploy } = require('hardhat');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { expect } = require('chai');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const {
  ERC4337Helper,
  SIG_VALIDATION_SUCCESS,
  SIG_VALIDATION_FAILURE,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const { NonNativeSigner, P256SigningKey } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/signers');

const { shouldBehaveLikeERC7579Module, shouldBehaveLikeERC7579Validator } = require('../ERC7579Module.behavior');

async function fixture() {
  const [other] = await ethers.getSigners();

  // Deploy ERC-7579 P256 validator module
  const mock = await ethers.deployContract('$ERC7579P256Validator');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  // Prepare P256 signer
  const p256SigningKey = P256SigningKey.random();
  const signer = new NonNativeSigner(p256SigningKey);
  const signUserOp = userOp =>
    signer
      .signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed)
      .then(signature => Object.assign(userOp, { signature }));

  // Prepare module installation data (qx, qy coordinates)
  const installData = ethers.solidityPacked(
    ['bytes32', 'bytes32'],
    [p256SigningKey.publicKey.qx, p256SigningKey.publicKey.qy],
  );

  // ERC-7579 account
  const mockAccount = await helper.newAccount('$AccountERC7579');
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));

  // Additional signers for testing
  const newP256SigningKey = P256SigningKey.random();
  const newSigner = new NonNativeSigner(newP256SigningKey);
  const newSignerInstallData = ethers.solidityPacked(
    ['bytes32', 'bytes32'],
    [newP256SigningKey.publicKey.qx, newP256SigningKey.publicKey.qy],
  );

  // User operation template
  const userOp = {
    sender: mockAccount.address,
    nonce: 0,
    initCode: '0x',
    callData: '0x',
    accountGasLimits: ethers.solidityPacked(['uint128', 'uint128'], [150000, 150000]),
    preVerificationGas: 21000,
    gasFees: ethers.solidityPacked(['uint128', 'uint128'], [1000000000, 1000000000]),
    paymasterAndData: '0x',
    signature: '0x',
  };

  // Invalid signature for testing
  const invalidSignature = '0x1234';

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
    userOp,
    invalidSignature,
    p256SigningKey,
    newP256SigningKey,
  };
}

describe('ERC7579P256Validator', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();
  shouldBehaveLikeERC7579Validator();

  describe('signer management', function () {
    describe('signer', function () {
      it('returns zero coordinates for uninstalled account', async function () {
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          ethers.ZeroHash,
          ethers.ZeroHash,
        ]);
      });

      it('returns configured signer coordinates after installation', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          this.p256SigningKey.publicKey.qx,
          this.p256SigningKey.publicKey.qy,
        ]);
      });

      it('returns zero coordinates after uninstallation', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await this.mockFromAccount.onUninstall('0x');
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          ethers.ZeroHash,
          ethers.ZeroHash,
        ]);
      });
    });

    describe('onInstall', function () {
      it('sets signer on first installation', async function () {
        await expect(this.mockFromAccount.onInstall(this.installData)).to.not.be.reverted;
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          this.p256SigningKey.publicKey.qx,
          this.p256SigningKey.publicKey.qy,
        ]);
      });

      it('reverts when installing twice', async function () {
        await this.mockFromAccount.onInstall(this.installData);

        // Subsequent installation should revert
        await expect(this.mockFromAccount.onInstall(this.newSignerInstallData)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579P256ValidatorAlreadyInstalled',
        );
      });

      it('reverts if data is too short', async function () {
        const shortData = '0x' + '12'.repeat(63); // 63 bytes
        await expect(this.mockFromAccount.onInstall(shortData)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579P256ValidatorInvalidSignerLength',
        );
      });

      it('accepts data with exactly 64 bytes', async function () {
        const exactData = ethers.solidityPacked(
          ['bytes32', 'bytes32'],
          [this.p256SigningKey.publicKey.qx, this.p256SigningKey.publicKey.qy],
        );
        await expect(this.mockFromAccount.onInstall(exactData))
          .to.emit(this.mock, 'ERC7579P256ValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.p256SigningKey.publicKey.qx, this.p256SigningKey.publicKey.qy);
      });

      it('accepts data longer than 64 bytes and uses first 64 bytes', async function () {
        const longData = ethers.solidityPacked(
          ['bytes32', 'bytes32', 'uint256'],
          [this.p256SigningKey.publicKey.qx, this.p256SigningKey.publicKey.qy, 12345],
        );
        await expect(this.mockFromAccount.onInstall(longData))
          .to.emit(this.mock, 'ERC7579P256ValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.p256SigningKey.publicKey.qx, this.p256SigningKey.publicKey.qy);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          this.p256SigningKey.publicKey.qx,
          this.p256SigningKey.publicKey.qy,
        ]);
      });

      it('reverts with invalid P256 public key', async function () {
        const invalidQx = ethers.ZeroHash;
        const invalidQy = '0x0000000000000000000000000000000000000000000000000000000000000001';
        const invalidData = ethers.solidityPacked(['bytes32', 'bytes32'], [invalidQx, invalidQy]);

        await expect(this.mockFromAccount.onInstall(invalidData)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579P256ValidatorInvalidPublicKey',
        );
      });

      it('reverts when trying to install with zero coordinates', async function () {
        const zeroData = ethers.solidityPacked(['bytes32', 'bytes32'], [ethers.ZeroHash, ethers.ZeroHash]);
        await expect(this.mockFromAccount.onInstall(zeroData))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorInvalidPublicKey')
          .withArgs(ethers.ZeroHash, ethers.ZeroHash);
      });
    });

    describe('onUninstall', function () {
      it('clears signer when installed', async function () {
        await this.mockFromAccount.onInstall(this.installData);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          this.p256SigningKey.publicKey.qx,
          this.p256SigningKey.publicKey.qy,
        ]);

        await expect(this.mockFromAccount.onUninstall('0x'))
          .to.emit(this.mock, 'ERC7579P256ValidatorSignerSet')
          .withArgs(this.mockAccount.address, ethers.ZeroHash, ethers.ZeroHash);
        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          ethers.ZeroHash,
          ethers.ZeroHash,
        ]);
      });

      it('does nothing when no signer is configured', async function () {
        // Should not emit event when no signer is configured (no-op)
        await expect(this.mockFromAccount.onUninstall('0x')).to.not.emit(this.mock, 'ERC7579P256ValidatorSignerSet');

        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          ethers.ZeroHash,
          ethers.ZeroHash,
        ]);
      });
    });

    describe('setSigner', function () {
      beforeEach(async function () {
        await this.mockFromAccount.onInstall(this.installData);
      });

      it('allows account to set new signer', async function () {
        await expect(
          this.mockFromAccount.setSigner(
            this.mockAccount.address,
            this.newP256SigningKey.publicKey.qx,
            this.newP256SigningKey.publicKey.qy,
          ),
        )
          .to.emit(this.mock, 'ERC7579P256ValidatorSignerSet')
          .withArgs(this.mockAccount.address, this.newP256SigningKey.publicKey.qx, this.newP256SigningKey.publicKey.qy);

        await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
          this.newP256SigningKey.publicKey.qx,
          this.newP256SigningKey.publicKey.qy,
        ]);
      });

      it('reverts when trying to set signer to zero coordinates', async function () {
        await expect(this.mockFromAccount.setSigner(this.mockAccount.address, ethers.ZeroHash, ethers.ZeroHash))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorInvalidPublicKey')
          .withArgs(ethers.ZeroHash, ethers.ZeroHash);
      });

      it('reverts when called by unauthorized address', async function () {
        await expect(
          this.mock
            .connect(this.other)
            .setSigner(
              this.mockAccount.address,
              this.newP256SigningKey.publicKey.qx,
              this.newP256SigningKey.publicKey.qy,
            ),
        )
          .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorNotAuthorized')
          .withArgs(this.other.address, this.mockAccount.address);
      });

      it('reverts when trying to set signer for different account', async function () {
        await expect(
          this.mockFromAccount.setSigner(
            this.other.address,
            this.newP256SigningKey.publicKey.qx,
            this.newP256SigningKey.publicKey.qy,
          ),
        )
          .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorNotAuthorized')
          .withArgs(this.mockAccount.address, this.other.address);
      });

      it('reverts when setting invalid P256 public key', async function () {
        const invalidQx = ethers.ZeroHash;
        const invalidQy = '0x0000000000000000000000000000000000000000000000000000000000000001';

        await expect(this.mockFromAccount.setSigner(this.mockAccount.address, invalidQx, invalidQy))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorInvalidPublicKey')
          .withArgs(invalidQx, invalidQy);
      });
    });
  });

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    describe('_rawERC7579Validation', function () {
      it('validates correct P256 signature', async function () {
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
      it('validates user operation with correct P256 signature', async function () {
        const userOp = await this.mockAccount.createUserOp(this.userOp).then(op => this.signUserOp(op));

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(SIG_VALIDATION_SUCCESS);
      });

      it('rejects user operation with invalid P256 signature', async function () {
        const userOp = await this.mockAccount.createUserOp({
          ...this.userOp,
          signature: this.invalidSignature,
        });

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(SIG_VALIDATION_FAILURE);
      });

      it('rejects user operation with signature from wrong P256 key', async function () {
        // Create userOp but sign with wrong signer
        const userOp = await this.mockAccount.createUserOp(this.userOp);
        const wrongSignature = await this.newSigner.signTypedData(
          await getDomain(predeploy.entrypoint.v09),
          { PackedUserOperation },
          userOp.packed,
        );
        userOp.signature = wrongSignature;

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(SIG_VALIDATION_FAILURE);
      });
    });

    describe('isValidSignatureWithSender', function () {
      it('returns magic value for valid P256 signature', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.signer.signMessage(message);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0x1626ba7e');
      });

      it('returns failure value for invalid P256 signature', async function () {
        const hash = ethers.hashMessage('Hello, world!');
        const signature = this.invalidSignature;

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });

      it('returns failure value for signature from wrong P256 key', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.newSigner.signMessage(message);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });
    });
  });

  describe('edge cases and integration', function () {
    it('handles reinstallation after uninstallation', async function () {
      // Install
      await this.mockFromAccount.onInstall(this.installData);
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        this.p256SigningKey.publicKey.qx,
        this.p256SigningKey.publicKey.qy,
      ]);

      // Uninstall
      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        ethers.ZeroHash,
        ethers.ZeroHash,
      ]);

      // Reinstall with different signer
      await this.mockFromAccount.onInstall(this.newSignerInstallData);
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        this.newP256SigningKey.publicKey.qx,
        this.newP256SigningKey.publicKey.qy,
      ]);
    });

    it('handles multiple setSigner calls', async function () {
      await this.mockFromAccount.onInstall(this.installData);

      // Change signer multiple times
      await this.mockFromAccount.setSigner(
        this.mockAccount.address,
        this.newP256SigningKey.publicKey.qx,
        this.newP256SigningKey.publicKey.qy,
      );
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        this.newP256SigningKey.publicKey.qx,
        this.newP256SigningKey.publicKey.qy,
      ]);

      await this.mockFromAccount.setSigner(
        this.mockAccount.address,
        this.p256SigningKey.publicKey.qx,
        this.p256SigningKey.publicKey.qy,
      );
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        this.p256SigningKey.publicKey.qx,
        this.p256SigningKey.publicKey.qy,
      ]);

      // Attempting to set to zero coordinates should fail
      await expect(this.mockFromAccount.setSigner(this.mockAccount.address, ethers.ZeroHash, ethers.ZeroHash))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579P256ValidatorInvalidPublicKey')
        .withArgs(ethers.ZeroHash, ethers.ZeroHash);

      // Signer should remain unchanged
      await expect(this.mock.signer(this.mockAccount.address)).to.eventually.deep.equal([
        this.p256SigningKey.publicKey.qx,
        this.p256SigningKey.publicKey.qy,
      ]);
    });
  });
});
