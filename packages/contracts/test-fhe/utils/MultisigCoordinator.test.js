const { ethers, fhevm, predeploy } = require('hardhat');
const { expect } = require('chai');
const { FhevmType } = require('@fhevm/hardhat-plugin');

const { impersonate } = require('../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { ERC4337Helper } = require('../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const { NonNativeSigner, P256SigningKey } = require('../../../../lib/@openzeppelin-contracts/test/helpers/signers');
const { getDomain } = require('../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { allowHandle: fheAllowHandle } = require('../helpers/fhe');
const { capitalize } = require('../../../../lib/@openzeppelin-contracts/test/helpers/strings');
const {
  MAX_UINT16,
  MAX_UINT32,
  MAX_UINT64,
  MAX_UINT128,
} = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');
const { AllowHandle, AllowHandleTransient } = require('../../test/helpers/eip712');

// Pre-generated wallets
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();
const aliceP256 = new NonNativeSigner(P256SigningKey.random());

describe('MultisigCoordinator', function () {
  beforeEach(async function () {
    // Deploy coordinator
    const coordinator = await ethers.deployContract('$MultisigCoordinatorMock');

    // ERC-4337 env
    const helper = new ERC4337Helper();
    await helper.wait();

    // ERC-7579 account
    const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
    const accountAsSigner = await impersonate(mockAccount.address);
    const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
      mockAccount.connect(asEntrypoint),
    );
    await mockAccount.deploy();

    // ERC-7913 P256 verifier
    const verifier = await ethers.deployContract('ERC7913P256Verifier');
    aliceP256.bytes = ethers.concat([
      verifier.target,
      aliceP256.signingKey.publicKey.qx,
      aliceP256.signingKey.publicKey.qy,
    ]);

    // Multisig validator
    const multisig = await ethers.deployContract('$ERC7579MultisigValidator');

    // Install the multisig with two signers: one EOA, one ERC-7913 P256
    const installData = ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes[]', 'uint64'],
      [[ethers.getBytes(signerECDSA1.address), aliceP256.bytes], 1n],
    );
    await mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, multisig.target, installData);

    // Register the multisig in the coordinator
    await coordinator.connect(accountAsSigner).setMultisig(multisig.target);

    // Account's EIP-712 domain
    const accountDomain = await getDomain(mockAccount);

    // Helper: encrypt a uint64 value for the account and return the on-chain handle.
    // Uses staticCall to capture the return value, then sends the real tx.
    const encryptHandle = async value => {
      const input = fhevm.createEncryptedInput(coordinator.target, mockAccount.address);
      input.add64(value);
      const {
        handles: [encHandle],
        inputProof,
      } = await input.encrypt();
      const handle = await coordinator
        .connect(accountAsSigner)
        .asEuint64.staticCall(mockAccount.address, encHandle, inputProof);
      await coordinator.connect(accountAsSigner).asEuint64(mockAccount.address, encHandle, inputProof);
      return handle;
    };

    Object.assign(this, {
      coordinator,
      multisig,
      mockAccount,
      accountAsSigner,
      mockAccountFromEntrypoint,
      verifier,
      accountDomain,
      encryptHandle,
    });
  });

  describe('setMultisig', function () {
    it('registers the multisig for the calling account', async function () {
      expect(await this.coordinator.multisig(this.mockAccount.address)).to.equal(this.multisig.target);
    });

    it('emits MultisigCoordinatorMultisigSet', async function () {
      const newMultisig = await ethers.deployContract('$ERC7579MultisigValidator');
      await expect(this.coordinator.connect(this.accountAsSigner).setMultisig(newMultisig.target))
        .to.emit(this.coordinator, 'MultisigCoordinatorMultisigSet')
        .withArgs(this.mockAccount.address, newMultisig.target);
    });

    it('reverts for the zero address', async function () {
      await expect(
        this.coordinator.connect(this.accountAsSigner).setMultisig(ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidMultisig');
    });
  });

  describe('as** functions', function () {
    for (const [type, value] of [
      ['bool', true],
      ['uint8', 255n],
      ['uint16', MAX_UINT16],
      ['uint32', MAX_UINT32],
      ['uint64', MAX_UINT64],
      ['uint128', MAX_UINT128],
      ['uint256', ethers.MaxUint256],
      ['address', ethers.Wallet.createRandom().address],
    ]) {
      it(`asE${type}: verify the input proof and grants ACL to coordinator and account`, async function () {
        const input = fhevm.createEncryptedInput(this.coordinator.target, this.mockAccount.address);
        input[`add${capitalize(type.replace('uint', ''))}`](value);
        const {
          handles: [encHandle],
          inputProof,
        } = await input.encrypt();

        const receipt = await this.coordinator
          .connect(this.accountAsSigner)
          [`$_asE${type}`](this.mockAccount.address, encHandle, inputProof)
          .then(tx => tx.wait());
        const [[handle]] = receipt.logs
          .map(log => this.coordinator.interface.parseLog(log))
          .filter(log => log?.name === `return$_asE${type}`)
          .map(log => log.args.map(arg => ethers.hexlify(arg)));

        await fheAllowHandle(this.accountAsSigner, signerECDSA1.address, handle);
        const isUint = type.startsWith('uint');
        const args = [handle, this.mockAccount.address, signerECDSA1];
        if (isUint) args.unshift(FhevmType[`e${type}`]);
        await expect(fhevm[`userDecryptE${isUint ? 'uint' : type}`](...args)).to.eventually.equal(value);
      });
    }
  });

  describe.only('allowHandle', function () {
    beforeEach(async function () {
      this.handle = await this.encryptHandle(42n);
    });

    describe('with the account as sender (empty signer)', function () {
      it('grants ACL to the recipient', async function () {
        await this.coordinator
          .connect(this.accountAsSigner)
          .allowHandle(this.mockAccount.address, this.handle, signerECDSA2.address);

        const decrypted = await fhevm.userDecryptEuint(
          FhevmType.euint64,
          this.handle,
          this.mockAccount.address,
          signerECDSA2,
        );
        expect(decrypted).to.equal(42n);
      });

      it('grants ACL when msg.sender is a registered signer EOA', async function () {
        const signerECDSA1AsSigner = await impersonate(signerECDSA1.address);
        await this.coordinator
          .connect(signerECDSA1AsSigner)
          .allowHandle(this.mockAccount.address, this.handle, signerECDSA2.address);

        const decrypted = await fhevm.userDecryptEuint(
          FhevmType.euint64,
          this.handle,
          this.mockAccount.address,
          signerECDSA2,
        );
        expect(decrypted).to.equal(42n);
      });

      it('reverts if msg.sender is neither the account nor a registered signer', async function () {
        const [other] = await ethers.getSigners();
        await expect(
          this.coordinator.connect(other).allowHandle(this.mockAccount.address, this.handle, signerECDSA2.address),
        ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSigner');
      });
    });

    describe('with a registered EOA signer and EIP-712 signature (signer = 20 bytes)', function () {
      it('grants ACL to the recipient when the signature is valid', async function () {
        const signerBytes = ethers.getBytes(signerECDSA1.address);
        const signature = await signerECDSA1.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: this.handle,
            to: signerECDSA2.address,
          },
        );

        await this.coordinator.allowHandle(
          this.mockAccount.address,
          signerBytes,
          signature,
          this.handle,
          signerECDSA2.address,
        );

        const decrypted = await fhevm.userDecryptEuint(
          FhevmType.euint64,
          this.handle,
          this.mockAccount.address,
          signerECDSA2,
        );
        expect(decrypted).to.equal(42n);
      });

      it('reverts if the signer is not registered in the multisig', async function () {
        const signerBytes = ethers.getBytes(signerECDSA2.address); // not registered
        const signature = await signerECDSA2.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: this.handle,
            to: signerECDSA2.address,
          },
        );

        await expect(
          this.coordinator.allowHandle(
            this.mockAccount.address,
            signerBytes,
            signature,
            this.handle,
            signerECDSA2.address,
          ),
        ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSigner');
      });

      it('reverts if the signature is over the wrong data', async function () {
        const signerBytes = ethers.getBytes(signerECDSA1.address);
        const wrongSignature = await signerECDSA1.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: ethers.ZeroHash, // wrong handle
            to: signerECDSA2.address,
          },
        );

        await expect(
          this.coordinator.allowHandle(
            this.mockAccount.address,
            signerBytes,
            wrongSignature,
            this.handle,
            signerECDSA2.address,
          ),
        ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSignature');
      });
    });

    describe('with a registered ERC-7913 signer and P256 signature (signer > 20 bytes)', function () {
      it('grants ACL to the recipient when the signature is valid', async function () {
        const signature = await aliceP256.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: this.handle,
            to: signerECDSA2.address,
          },
        );

        await this.coordinator.allowHandle(
          this.mockAccount.address,
          aliceP256.bytes,
          signature,
          this.handle,
          signerECDSA2.address,
        );

        const decrypted = await fhevm.userDecryptEuint(
          FhevmType.euint64,
          this.handle,
          this.mockAccount.address,
          signerECDSA2,
        );
        expect(decrypted).to.equal(42n);
      });

      it('reverts if the ERC-7913 signer is not registered in the multisig', async function () {
        const bobP256 = new NonNativeSigner(P256SigningKey.random());
        bobP256.bytes = ethers.concat([
          this.verifier.target,
          bobP256.signingKey.publicKey.qx,
          bobP256.signingKey.publicKey.qy,
        ]);

        const signature = await bobP256.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: this.handle,
            to: signerECDSA2.address,
          },
        );

        await expect(
          this.coordinator.allowHandle(
            this.mockAccount.address,
            bobP256.bytes,
            signature,
            this.handle,
            signerECDSA2.address,
          ),
        ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSigner');
      });

      it('reverts if the ERC-7913 signature is over the wrong data', async function () {
        const wrongSignature = await aliceP256.signTypedData(
          this.accountDomain,
          { AllowHandle },
          {
            account: this.mockAccount.address,
            handle: ethers.ZeroHash, // wrong handle
            to: signerECDSA2.address,
          },
        );

        await expect(
          this.coordinator.allowHandle(
            this.mockAccount.address,
            aliceP256.bytes,
            wrongSignature,
            this.handle,
            signerECDSA2.address,
          ),
        ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSignature');
      });
    });

    it('reverts if the multisig module is not installed in the account', async function () {
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.multisig.target, '0x');

      await expect(
        this.coordinator
          .connect(this.accountAsSigner)
          .allowHandle(this.mockAccount.address, this.handle, signerECDSA2.address),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidMultisigModule');
    });

    it('reverts if no multisig is registered for the account', async function () {
      const helper = new ERC4337Helper();
      await helper.wait();
      const otherAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
      await otherAccount.deploy();

      // otherAccount has no setMultisig call — multisig() returns address(0)
      await expect(
        this.coordinator.allowHandle(otherAccount.address, this.handle, signerECDSA2.address),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidMultisigModule');
    });
  });

  describe('allowHandleTransient', function () {
    beforeEach(async function () {
      this.handle = await this.encryptHandle(99n);
    });

    it('succeeds when called by the account', async function () {
      await expect(
        this.coordinator
          .connect(this.accountAsSigner)
          .allowHandleTransient(this.mockAccount.address, this.handle, signerECDSA2.address),
      ).to.not.be.reverted;
    });

    it('succeeds when called by a registered signer EOA', async function () {
      const signerECDSA1AsSigner = await impersonate(signerECDSA1.address);
      await expect(
        this.coordinator
          .connect(signerECDSA1AsSigner)
          .allowHandleTransient(this.mockAccount.address, this.handle, signerECDSA2.address),
      ).to.not.be.reverted;
    });

    it('succeeds with a registered EOA signer and EIP-712 signature', async function () {
      const signerBytes = ethers.getBytes(signerECDSA1.address);
      const signature = await signerECDSA1.signTypedData(
        this.accountDomain,
        { AllowHandleTransient },
        {
          account: this.mockAccount.address,
          handle: this.handle,
          to: signerECDSA2.address,
        },
      );

      await expect(
        this.coordinator.allowHandleTransient(
          this.mockAccount.address,
          signerBytes,
          signature,
          this.handle,
          signerECDSA2.address,
        ),
      ).to.not.be.reverted;
    });

    it('succeeds with a registered ERC-7913 signer and P256 signature', async function () {
      const signature = await aliceP256.signTypedData(
        this.accountDomain,
        { AllowHandleTransient },
        {
          account: this.mockAccount.address,
          handle: this.handle,
          to: signerECDSA2.address,
        },
      );

      await expect(
        this.coordinator.allowHandleTransient(
          this.mockAccount.address,
          aliceP256.bytes,
          signature,
          this.handle,
          signerECDSA2.address,
        ),
      ).to.not.be.reverted;
    });

    it('reverts if msg.sender is neither the account nor a registered signer', async function () {
      const [other] = await ethers.getSigners();
      await expect(
        this.coordinator
          .connect(other)
          .allowHandleTransient(this.mockAccount.address, this.handle, signerECDSA2.address),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSigner');
    });

    it('reverts if the signature is invalid', async function () {
      const signerBytes = ethers.getBytes(signerECDSA1.address);
      const wrongSignature = await signerECDSA1.signTypedData(
        this.accountDomain,
        { AllowHandleTransient },
        {
          account: this.mockAccount.address,
          handle: ethers.ZeroHash, // wrong handle
          to: signerECDSA2.address,
        },
      );

      await expect(
        this.coordinator.allowHandleTransient(
          this.mockAccount.address,
          signerBytes,
          wrongSignature,
          this.handle,
          signerECDSA2.address,
        ),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidSignature');
    });

    it('reverts if the multisig module is not installed in the account', async function () {
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.multisig.target, '0x');

      await expect(
        this.coordinator
          .connect(this.accountAsSigner)
          .allowHandleTransient(this.mockAccount.address, this.handle, signerECDSA2.address),
      ).to.be.revertedWithCustomError(this.coordinator, 'MultisigCoordinatorInvalidMultisigModule');
    });
  });
});
