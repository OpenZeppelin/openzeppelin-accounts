const { ethers, predeploy } = require('hardhat');
const { loadFixture, time } = require('@nomicfoundation/hardhat-network-helpers');
const { expect } = require('chai');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const {
  ERC4337Helper,
  SIG_VALIDATION_FAILURE,
  packValidationData,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const { ValidationRange } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/enums');

const { shouldBehaveLikeERC7579Module } = require('../ERC7579Module.behavior');

// Encode the session key signature: abi.encode(bytes key, bytes keySignature)
const encodeSessionKeySig = (key, keySignature) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes'], [key, keySignature]);

// Encode the install data: abi.encode(bytes[] keys, uint48[] starts, uint48[] ends)
const encodeInstallData = (keys, starts, ends) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint48[]', 'uint48[]'], [keys, starts, ends]);

// Largest timepoint that fits in the 47 bits available in ERC-4337 validation data
const MAX_TIMEPOINT = (1n << 47n) - 1n;

async function fixture() {
  const [other] = await ethers.getSigners();

  const mock = await ethers.deployContract('$ERC7579SessionKeysValidator');

  // ERC-4337 environment
  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  // Session keys: 20-byte ECDSA addresses used as ERC-7913 keys (length == 20 path)
  const sessionKey = ethers.Wallet.createRandom();
  const key = ethers.solidityPacked(['address'], [sessionKey.address]);

  const otherSessionKey = ethers.Wallet.createRandom();
  const otherKey = ethers.solidityPacked(['address'], [otherSessionKey.address]);

  // starts=0 resolves to clock() at install time; ends=0 resolves to type(uint48).max >> 1
  const installData = encodeInstallData([key], [0], [0]);

  // Wrap an ECDSA typed-data signature in the ERC-7913 session key format
  const signUserOp = async userOp => {
    const keySignature = await sessionKey.signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed);
    return Object.assign(userOp, { signature: encodeSessionKeySig(key, keySignature) });
  };

  // Wrap an ECDSA signMessage call in the ERC-7913 session key format
  const signMessage = async message => {
    const keySignature = await sessionKey.signMessage(message);
    return encodeSessionKeySig(key, keySignature);
  };

  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));

  const userOpTemplate = {
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

  return {
    moduleType: MODULE_TYPE_VALIDATOR,
    mock,
    mockFromAccount,
    mockAccount,
    other,
    sessionKey,
    otherSessionKey,
    key,
    otherKey,
    signUserOp,
    signMessage,
    installData,
    userOp: userOpTemplate,
    entrypointDomain,
  };
}

describe('ERC7579SessionKeysValidator', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();

  describe('clock', function () {
    it('returns the current block timestamp', async function () {
      const currentTime = await time.latest();
      await expect(this.mock.clock()).to.eventually.equal(currentTime);
    });

    it('CLOCK_MODE returns mode=timestamp', async function () {
      await expect(this.mock.CLOCK_MODE()).to.eventually.equal('mode=timestamp');
    });
  });

  describe('installation nonce', function () {
    it('starts at 0 for a fresh account', async function () {
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(0n);
    });

    it('increments each time the module is uninstalled', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(1n);

      await this.mockFromAccount.onInstall(this.installData);
      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(2n);
    });
  });

  describe('onInstall', function () {
    it('registers session keys with explicit validity range', async function () {
      const now = BigInt(await time.latest());
      const from = now + 10n;
      const until = now + 3600n;
      const data = encodeInstallData([this.key], [from], [until]);

      await this.mockFromAccount.onInstall(data);

      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
      const [retFrom, retUntil] = await this.mock.validity(this.mockAccount.address, this.key);
      expect(retFrom).to.equal(from);
      expect(retUntil).to.equal(until);
    });

    it('uses the current timestamp when start is 0', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      const [from] = await this.mock.validity(this.mockAccount.address, this.key);
      const currentTime = BigInt(await time.latest());
      expect(from).to.be.within(currentTime - 1n, currentTime);
    });

    it('uses type(uint48).max >> 1 as expiry when end is 0', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      const [, until] = await this.mock.validity(this.mockAccount.address, this.key);
      expect(until).to.equal(MAX_TIMEPOINT);
    });

    it('reverts when end exceeds 47 bits', async function () {
      const now = BigInt(await time.latest());
      const data = encodeInstallData([this.key], [now], [MAX_TIMEPOINT + 1n]);
      await expect(this.mockFromAccount.onInstall(data))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysInvalidValidity')
        .withArgs(now, MAX_TIMEPOINT + 1n);
    });

    it('reverts when start exceeds 47 bits', async function () {
      const data = encodeInstallData([this.key], [MAX_TIMEPOINT + 1n], [0n]);
      await expect(this.mockFromAccount.onInstall(data))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysInvalidValidity')
        .withArgs(MAX_TIMEPOINT + 1n, MAX_TIMEPOINT);
    });

    it('reverts when start is after end', async function () {
      const now = BigInt(await time.latest());
      const data = encodeInstallData([this.key], [now + 100n], [now + 99n]);
      await expect(this.mockFromAccount.onInstall(data))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysInvalidValidity')
        .withArgs(now + 100n, now + 99n);
    });

    it('emits ERC7579SessionKeysERC7913KeySet for each registered key', async function () {
      const now = BigInt(await time.latest());
      const from = now + 10n;
      const until = now + 3600n;
      const data = encodeInstallData([this.key, this.otherKey], [from, from], [until, until]);

      await expect(this.mockFromAccount.onInstall(data))
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet')
        .withArgs(this.mockAccount.address, this.key, from, until)
        .and.to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet')
        .withArgs(this.mockAccount.address, this.otherKey, from, until);
    });

    it('reverts when init data is too short', async function () {
      const shortData = '0x' + '00'.repeat(0xbf); // 191 bytes, 1 below the 192-byte minimum
      await expect(this.mockFromAccount.onInstall(shortData)).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579SessionKeysInvalidInitData',
      );
    });

    it('reverts when array lengths do not match', async function () {
      const data = ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes[]', 'uint48[]', 'uint48[]'],
        [[this.key], [0n, 100n], [0n]], // starts has 2 elements, keys and ends have 1
      );
      await expect(this.mockFromAccount.onInstall(data)).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579SessionKeysMismatchedInitDataLengths',
      );
    });

    it('reverts when registering a duplicate key', async function () {
      const data = encodeInstallData([this.key, this.key], [0n, 0n], [0n, 0n]);
      await expect(this.mockFromAccount.onInstall(data))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysAlreadyRegisteredKey')
        .withArgs(this.key);
    });
  });

  describe('onUninstall', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    it('emits ERC7579SessionKeysCleared', async function () {
      await expect(this.mockFromAccount.onUninstall('0x'))
        .to.emit(this.mock, 'ERC7579SessionKeysCleared')
        .withArgs(this.mockAccount.address);
    });

    it('increments the installation nonce', async function () {
      const before = await this.mock.installation(this.mockAccount.address);
      await this.mockFromAccount.onUninstall('0x');
      const after = await this.mock.installation(this.mockAccount.address);
      expect(after).to.equal(before + 1n);
    });

    it('makes all registered keys inaccessible', async function () {
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
    });

    it('empties the keys list', async function () {
      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.keys(this.mockAccount.address, 0, ethers.MaxUint256)).to.eventually.deep.equal([]);
    });
  });

  describe('addKeys', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    it('adds new session keys to the account', async function () {
      const now = BigInt(await time.latest());
      const from = now;
      const until = now + 3600n;

      await expect(this.mockFromAccount.addKeys([this.otherKey], [from], [until]))
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet')
        .withArgs(this.mockAccount.address, this.otherKey, from, until);

      await expect(this.mock.isKey(this.mockAccount.address, this.otherKey)).to.eventually.be.true;
    });

    it('reverts when adding an already-registered key', async function () {
      await expect(this.mockFromAccount.addKeys([this.key], [0n], [0n]))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysAlreadyRegisteredKey')
        .withArgs(this.key);
    });

    it('reverts with mismatched array lengths', async function () {
      await expect(this.mockFromAccount.addKeys([this.otherKey], [0n, 100n], [0n])).to.be.revertedWithCustomError(
        this.mock,
        'ERC7579SessionKeysMismatchedInitDataLengths',
      );
    });
  });

  describe('removeKeys', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    it('removes a registered session key', async function () {
      await expect(this.mockFromAccount.removeKeys([this.key]))
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeyUnset')
        .withArgs(this.mockAccount.address, this.key);

      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
    });

    it('clears the validity range on removal', async function () {
      await this.mockFromAccount.removeKeys([this.key]);
      const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
      expect(from).to.equal(0n);
      expect(until).to.equal(0n);
    });

    it('reverts when removing a nonexistent key', async function () {
      await expect(this.mockFromAccount.removeKeys([this.otherKey]))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysNonexistentKey')
        .withArgs(this.otherKey);
    });
  });

  describe('isKey', function () {
    it('returns false for an unregistered key', async function () {
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
    });

    it('returns true for a registered key', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
    });

    it('returns false after the key is removed', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      await this.mockFromAccount.removeKeys([this.key]);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
    });
  });

  describe('isValid', function () {
    it('returns false for an unregistered key', async function () {
      await expect(this.mock.isValid(this.mockAccount.address, this.key)).to.eventually.be.false;
    });

    it('returns true for an active key with no expiry', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      await expect(this.mock.isValid(this.mockAccount.address, this.key)).to.eventually.be.true;
    });

    it('returns false for an expired key', async function () {
      const now = BigInt(await time.latest());
      const until = now + 100n;
      await this.mockFromAccount.onInstall(encodeInstallData([this.key], [now], [until]));

      await time.increaseTo(until + 1n);

      await expect(this.mock.isValid(this.mockAccount.address, this.key)).to.eventually.be.false;
    });

    it('returns false for a key not yet active', async function () {
      const now = BigInt(await time.latest());
      const from = now + 3600n;
      const until = now + 7200n;
      await this.mockFromAccount.onInstall(encodeInstallData([this.key], [from], [until]));

      await expect(this.mock.isValid(this.mockAccount.address, this.key)).to.eventually.be.false;
    });
  });

  describe('validity', function () {
    it('returns a zero range for an unregistered key', async function () {
      const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
      expect(from).to.equal(0n);
      expect(until).to.equal(0n);
    });

    it('returns the configured validity range', async function () {
      const now = BigInt(await time.latest());
      const from = now + 10n;
      const until = now + 3600n;
      await this.mockFromAccount.onInstall(encodeInstallData([this.key], [from], [until]));

      const [retFrom, retUntil] = await this.mock.validity(this.mockAccount.address, this.key);
      expect(retFrom).to.equal(from);
      expect(retUntil).to.equal(until);
    });
  });

  describe('keys', function () {
    it('returns an empty array when no keys are registered', async function () {
      await expect(this.mock.keys(this.mockAccount.address, 0, ethers.MaxUint256)).to.eventually.deep.equal([]);
    });

    it('returns all registered keys', async function () {
      const data = encodeInstallData([this.key, this.otherKey], [0n, 0n], [0n, 0n]);
      await this.mockFromAccount.onInstall(data);

      const registered = await this.mock.keys(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(registered).to.have.lengthOf(2);
      expect(registered).to.include(this.key);
      expect(registered).to.include(this.otherKey);
    });

    it('supports paginated access via startIdx and endIdx', async function () {
      const data = encodeInstallData([this.key, this.otherKey], [0n, 0n], [0n, 0n]);
      await this.mockFromAccount.onInstall(data);

      const page = await this.mock.keys(this.mockAccount.address, 0, 1);
      expect(page).to.have.lengthOf(1);
    });
  });

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockFromAccount.onInstall(this.installData);
    });

    describe('_rawERC7579Validation', function () {
      it('validates a correct session key signature', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const keySignature = await this.sessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.key, keySignature);

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.true;
      });

      it('rejects a signature for an unregistered key', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const keySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.otherKey, keySignature);

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.false;
      });

      it('rejects a signature from the wrong signer for a registered key', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const wrongKeySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.key, wrongKeySignature);

        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, signature)).to
          .eventually.be.false;
      });

      it('rejects an invalid (too short) signature format', async function () {
        const hash = ethers.hashMessage('Hello, world!');
        await expect(this.mockFromAccount.$_rawERC7579Validation(this.mockAccount.address, hash, '0x1234')).to
          .eventually.be.false;
      });
    });

    describe('_validateUserOp', function () {
      it('returns packed validation data with success authorizer for a valid signature', async function () {
        const userOp = await this.mockAccount.createUserOp(this.userOp).then(op => this.signUserOp(op));
        const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
        const expectedReturn = ethers.toBigInt(packValidationData(from - 1n, until, true, ValidationRange.Timestamp));

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(expectedReturn);
      });

      it('returns SIG_VALIDATION_FAILURE for an invalid signature format', async function () {
        const userOp = await this.mockAccount.createUserOp({ ...this.userOp, signature: '0x1234' });

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(SIG_VALIDATION_FAILURE);
      });

      it('returns SIG_VALIDATION_FAILURE for an unregistered session key', async function () {
        const userOp = await this.mockAccount.createUserOp(this.userOp);
        const keySignature = await this.otherSessionKey.signTypedData(
          this.entrypointDomain,
          { PackedUserOperation },
          userOp.packed,
        );
        userOp.signature = encodeSessionKeySig(this.otherKey, keySignature);

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(SIG_VALIDATION_FAILURE);
      });

      it('packs failure authorizer with validity range when signature is wrong for a registered key', async function () {
        const userOp = await this.mockAccount.createUserOp(this.userOp);
        const wrongKeySignature = await this.otherSessionKey.signTypedData(
          this.entrypointDomain,
          { PackedUserOperation },
          userOp.packed,
        );
        userOp.signature = encodeSessionKeySig(this.key, wrongKeySignature);

        const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
        const expectedReturn = ethers.toBigInt(packValidationData(from - 1n, until, false, ValidationRange.Timestamp));

        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(expectedReturn);
      });

      it('packs the expired validity range and lets the EntryPoint reject it', async function () {
        const now = BigInt(await time.latest());
        const from = now;
        const until = now + 100n;
        await this.mockFromAccount.addKeys([this.otherKey], [from], [until]);
        await time.increaseTo(until + 1n);

        const userOp = await this.mockAccount.createUserOp(this.userOp);
        const keySignature = await this.otherSessionKey.signTypedData(
          this.entrypointDomain,
          { PackedUserOperation },
          userOp.packed,
        );
        userOp.signature = encodeSessionKeySig(this.otherKey, keySignature);

        const expectedReturn = ethers.toBigInt(packValidationData(from - 1n, until, true, ValidationRange.Timestamp));
        await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
          .to.emit(this.mockFromAccount, 'return$_validateUserOp')
          .withArgs(expectedReturn);
      });
    });

    describe('isValidSignatureWithSender', function () {
      it('returns magic value for a valid session key signature', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const signature = await this.signMessage(message);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0x1626ba7e');
      });

      it('returns failure for an invalid signature format', async function () {
        const hash = ethers.hashMessage('Hello, world!');
        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, '0x1234'),
        ).to.eventually.equal('0xffffffff');
      });

      it('returns failure for a signature from the wrong signer', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const wrongKeySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.key, wrongKeySignature);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });

      it('returns failure for an expired session key', async function () {
        const now = BigInt(await time.latest());
        const until = now + 100n;
        await this.mockFromAccount.addKeys([this.otherKey], [now], [until]);
        await time.increaseTo(until + 1n);

        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const keySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.otherKey, keySignature);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });

      it('returns failure for a session key not yet active', async function () {
        const now = BigInt(await time.latest());
        const from = now + 3600n;
        const until = now + 7200n;
        await this.mockFromAccount.addKeys([this.otherKey], [from], [until]);

        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const keySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.otherKey, keySignature);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });

      it('returns failure for an unregistered session key', async function () {
        const message = 'Hello, world!';
        const hash = ethers.hashMessage(message);
        const keySignature = await this.otherSessionKey.signMessage(message);
        const signature = encodeSessionKeySig(this.otherKey, keySignature);

        await expect(
          this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
        ).to.eventually.equal('0xffffffff');
      });
    });
  });

  describe('reinstallation', function () {
    it('allows re-installing with the same keys after uninstall', async function () {
      await this.mockFromAccount.onInstall(this.installData);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;

      await this.mockFromAccount.onUninstall('0x');
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;

      await this.mockFromAccount.onInstall(this.installData);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
    });

    it('rejects signatures after uninstall even before re-registering keys', async function () {
      await this.mockFromAccount.onInstall(this.installData);

      const message = 'Hello, world!';
      const hash = ethers.hashMessage(message);
      const signature = await this.signMessage(message);

      await expect(
        this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
      ).to.eventually.equal('0x1626ba7e');

      await this.mockFromAccount.onUninstall('0x');

      await expect(
        this.mockFromAccount.isValidSignatureWithSender(this.other.address, hash, signature),
      ).to.eventually.equal('0xffffffff');
    });
  });
});
