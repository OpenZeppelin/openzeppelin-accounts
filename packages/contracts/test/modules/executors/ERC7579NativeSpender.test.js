const { ethers, predeploy } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const {
  ERC4337Helper,
  SIG_VALIDATION_FAILURE,
  packValidationData,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const {
  MODULE_TYPE_VALIDATOR,
  MODULE_TYPE_EXECUTOR,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const { ValidationRange } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/enums');
const time = require('../../../../../lib/@openzeppelin-contracts/test/helpers/time');

const { shouldBehaveLikeERC7579Module } = require('../ERC7579Module.behavior');

// ERC-7579 single-execution mode (CALLTYPE_SINGLE, EXECTYPE_DEFAULT, zero selector, zero payload)
const SINGLE_MODE = ethers.ZeroHash;
// CALLTYPE_BATCH = 0x01 in the first byte
const BATCH_MODE = '0x01' + '00'.repeat(31);

// Encode first-install (validator role) data: (bytes[] keys, uint48[] starts, uint48[] ends)
const encodeKeysInstall = (keys, starts, ends) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint48[]', 'uint48[]'], [keys, starts, ends]);

// Encode second-install (executor role) data: (bytes[] keys, uint160[] limits, uint48[] renewPeriods)
const encodeConfigInstall = (keys, limits, renewPeriods) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint160[]', 'uint48[]'], [keys, limits, renewPeriods]);

// Encode an ERC-7913 session-key signature: abi.encode(bytes key, bytes keySignature)
const encodeSessionKeySig = (key, keySignature) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes'], [key, keySignature]);

// Encode the executionCalldata for CALLTYPE_SINGLE: abi.encodePacked(target, value, data)
const encodeSingle = (target, value, data) =>
  ethers.solidityPacked(['address', 'uint256', 'bytes'], [target, value, data]);

async function fixture() {
  const [other, recipient1, recipient2] = await ethers.getSigners();

  // Deploy the dual-role module
  const mock = await ethers.deployContract('$ERC7579NativeSpender');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  // ERC-7579 account
  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  await mockAccount.deploy();
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));
  const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
    mockAccount.connect(asEntrypoint),
  );

  // Session keys: 20-byte ECDSA addresses used as ERC-7913 keys (length == 20 path)
  const sessionKey = ethers.Wallet.createRandom().connect(ethers.provider);
  const key = ethers.solidityPacked(['address'], [sessionKey.address]);

  const otherSessionKey = ethers.Wallet.createRandom().connect(ethers.provider);
  const otherKey = ethers.solidityPacked(['address'], [otherSessionKey.address]);

  // Fund the account, the session key (for direct EOA self-call gas), and other
  await other.sendTransaction({ to: mockAccount.address, value: ethers.parseEther('100') });
  await other.sendTransaction({ to: sessionKey.address, value: ethers.parseEther('1') });
  await other.sendTransaction({ to: otherSessionKey.address, value: ethers.parseEther('1') });

  // Default spending configuration for `key`
  const limit = ethers.parseEther('10');
  const renewPeriod = time.duration.days(7);
  const start = 0n; // 0 -> resolved to current clock at install
  const end = 0n; // 0 -> stored as type(uint48).max

  const keysInstallData = encodeKeysInstall([key], [start], [end]);
  const configInstallData = encodeConfigInstall([key], [limit], [renewPeriod]);

  // Install module under both module types (validator first, then executor with config bundle)
  const installBoth = async (keysData = keysInstallData, configData = configInstallData) => {
    await mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, mock.target, keysData);
    await mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, mock.target, configData);
  };

  // ERC-4337 nonce key that routes validation through the spender module (used as validator)
  const validatorNonceKey = BigInt(mock.target) << 32n;

  // Build a UserOp that calls `account.execute(SINGLE, encodeSingle(mock, 0, transferFromCall))`
  const buildSpendUserOp = async ({
    key: usedKey = key,
    signer = sessionKey,
    to = recipient1.address,
    amount,
    batch = false,
    tos,
    amounts,
  } = {}) => {
    const innerCall = batch
      ? mock.interface.encodeFunctionData('batchTransferFrom', [mockAccount.address, usedKey, tos, amounts])
      : mock.interface.encodeFunctionData('transferFrom', [mockAccount.address, usedKey, to, amount]);
    const execCalldata = encodeSingle(mock.target, 0, innerCall);
    const callData = mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);

    const nonce = await predeploy.entrypoint.v09.getNonce(mockAccount.address, validatorNonceKey);
    const userOp = await mockAccount.createUserOp({ callData, nonce });
    const keySignature = await signer.signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed);
    userOp.signature = encodeSessionKeySig(usedKey, keySignature);
    return userOp;
  };

  return {
    moduleType: MODULE_TYPE_VALIDATOR, // For shouldBehaveLikeERC7579Module
    mock,
    mockAccount,
    mockFromAccount,
    mockAccountFromEntrypoint,
    other,
    recipient1,
    recipient2,
    sessionKey,
    otherSessionKey,
    key,
    otherKey,
    limit,
    renewPeriod,
    start,
    end,
    keysInstallData,
    configInstallData,
    installData: keysInstallData, // alias used by shouldBehaveLikeERC7579Module
    installBoth,
    buildSpendUserOp,
    entrypointDomain,
  };
}

describe('ERC7579NativeSpender', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();

  describe('isModuleType', function () {
    it('returns true for both validator and executor', async function () {
      await expect(this.mock.isModuleType(MODULE_TYPE_VALIDATOR)).to.eventually.be.true;
      await expect(this.mock.isModuleType(MODULE_TYPE_EXECUTOR)).to.eventually.be.true;
    });

    it('returns false for other module types', async function () {
      await expect(this.mock.isModuleType(0)).to.eventually.be.false;
      await expect(this.mock.isModuleType(3)).to.eventually.be.false;
      await expect(this.mock.isModuleType(99)).to.eventually.be.false;
    });
  });

  describe('isValidSignatureWithSender', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('always returns 0xffffffff (ERC-1271 signing disabled)', async function () {
      const message = 'hello';
      const hash = ethers.hashMessage(message);
      const keySignature = await this.sessionKey.signMessage(message);
      const signature = encodeSessionKeySig(this.key, keySignature);
      await expect(this.mock.isValidSignatureWithSender(this.other.address, hash, signature)).to.eventually.equal(
        '0xffffffff',
      );
    });

    it('returns 0xffffffff even for an empty signature', async function () {
      await expect(this.mock.isValidSignatureWithSender(this.other.address, ethers.ZeroHash, '0x')).to.eventually.equal(
        '0xffffffff',
      );
    });
  });

  describe('installed', function () {
    it('starts false', async function () {
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
    });

    it('flips true after the first install registers a key', async function () {
      await this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, this.mock.target, this.keysInstallData);
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.true;
    });

    it('flips false again after uninstall', async function () {
      await this.installBoth();
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.mock.target, '0x');
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
    });
  });

  describe('onInstall', function () {
    describe('first call (validator install)', function () {
      it('registers keys via the parent and emits the key-set event', async function () {
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, this.mock.target, this.keysInstallData),
        ).to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet');

        await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
        // Limit/renewPeriod remain 0 until the executor install configures them
        await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(0n);
        await expect(this.mock.renewPeriod(this.mockAccount.address, this.key)).to.eventually.equal(0n);
      });

      it('reverts when the first install registers zero keys', async function () {
        const emptyKeys = encodeKeysInstall([], [], []);
        await expect(this.mockFromAccount.onInstall(emptyKeys)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579NativeSpenderEmptyKeys',
        );
      });

      it('reverts with ERC7579NativeSpenderInvalidStart when a start is in the past', async function () {
        const bad = encodeKeysInstall([this.key], [1n], [0n]);
        await expect(this.mockFromAccount.onInstall(bad))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidStart')
          .withArgs(1n);
      });

      it('bubbles ERC7579SessionKeysMismatchedInitDataLengths for inconsistent first-install arrays', async function () {
        const bad = encodeKeysInstall([this.key, this.otherKey], [0n], [0n, 0n]);
        await expect(this.mockFromAccount.onInstall(bad)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579SessionKeysMismatchedInitDataLengths',
        );
      });
    });

    describe('second call (executor install)', function () {
      beforeEach(async function () {
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_VALIDATOR,
          this.mock.target,
          this.keysInstallData,
        );
      });

      it('writes the spending config for each registered key', async function () {
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, this.configInstallData),
        )
          .to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
          .withArgs(this.mockAccount.address, this.key, this.limit, this.renewPeriod);

        await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(this.limit);
        await expect(this.mock.renewPeriod(this.mockAccount.address, this.key)).to.eventually.equal(this.renewPeriod);
      });

      it('reverts on mismatched array lengths', async function () {
        const bad = encodeConfigInstall([this.key], [this.limit], [this.renewPeriod, this.renewPeriod]);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderMismatchedInitDataLengths');
      });

      it('reverts when a configured key was not registered by the first install', async function () {
        const bad = encodeConfigInstall([this.otherKey], [this.limit], [this.renewPeriod]);
        await expect(this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysNonexistentKey')
          .withArgs(this.otherKey);
      });

      it('reverts on zero limit', async function () {
        const bad = encodeConfigInstall([this.key], [0n], [this.renewPeriod]);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidLimit');
      });

      it('reverts on zero renewPeriod', async function () {
        const bad = encodeConfigInstall([this.key], [this.limit], [0n]);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidRenewPeriod');
      });

      it('reverts on a too-short config bundle', async function () {
        const shortData = '0x' + '00'.repeat(0xbf); // 191 bytes
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, shortData),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidInitData');
      });

      it('reverts when the config bundle has zero keys', async function () {
        const empty = encodeConfigInstall([], [], []);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, empty),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderEmptyKeys');
      });

      it('leaves keys not mentioned in the config bundle with zero limits', async function () {
        // Register two keys in the first install (re-do beforeEach with extra key)
        await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.mock.target, '0x');
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_VALIDATOR,
          this.mock.target,
          encodeKeysInstall([this.key, this.otherKey], [0n, 0n], [0n, 0n]),
        );

        // Configure only `key`, leave `otherKey` with default zero limit
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_EXECUTOR,
          this.mock.target,
          encodeConfigInstall([this.key], [this.limit], [this.renewPeriod]),
        );

        await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(this.limit);
        await expect(this.mock.limit(this.mockAccount.address, this.otherKey)).to.eventually.equal(0n);
      });
    });

    describe('third call (reconfiguration ban)', function () {
      it('reverts with AlreadyInstalled when onInstall is invoked after the executor install', async function () {
        await this.installBoth();
        await expect(
          this.mockFromAccount.onInstall(
            encodeConfigInstall([this.key], [ethers.parseEther('25')], [time.duration.days(3)]),
          ),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderAlreadyInstalled');
      });

      it('reverts even when targeting a different (unconfigured) key', async function () {
        // Register two keys, configure only the first. A follow-up install targeting the second
        // is still rejected: reconfiguration is banned wholesale at this nonce.
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_VALIDATOR,
          this.mock.target,
          encodeKeysInstall([this.key, this.otherKey], [0n, 0n], [0n, 0n]),
        );
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_EXECUTOR,
          this.mock.target,
          encodeConfigInstall([this.key], [this.limit], [this.renewPeriod]),
        );

        await expect(
          this.mockFromAccount.onInstall(encodeConfigInstall([this.otherKey], [this.limit], [this.renewPeriod])),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderAlreadyInstalled');
      });
    });
  });

  describe('onUninstall', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('increments the installation nonce', async function () {
      const before = await this.mock.installation(this.mockAccount.address);
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.mock.target, '0x');
      await expect(this.mock.installation(this.mockAccount.address)).to.eventually.equal(before + 1n);
    });

    it('makes old config unreachable from accessors', async function () {
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.mock.target, '0x');
      await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(0n);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.key)).to.eventually.equal(0n);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
    });
  });

  describe('addKeysWithConfig', function () {
    beforeEach(async function () {
      // Fully installed with the default `key`; add more via the post-install helper
      await this.installBoth();
    });

    it('adds new keys with policy in a single call', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig([this.otherKey], [0n], [0n], [this.limit], [this.renewPeriod]),
      )
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet')
        .and.to.emit(this.mock, 'ERC7579NativeSpendingConfigSet')
        .withArgs(this.mockAccount.address, this.otherKey, this.limit, this.renewPeriod);

      await expect(this.mock.isKey(this.mockAccount.address, this.otherKey)).to.eventually.be.true;
      await expect(this.mock.limit(this.mockAccount.address, this.otherKey)).to.eventually.equal(this.limit);
    });

    it('reverts on mismatched array lengths (limits vs keys)', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig([this.otherKey], [0n], [0n], [], [this.renewPeriod]),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderMismatchedInitDataLengths');
    });

    it('reverts on mismatched array lengths (starts vs keys)', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig([this.otherKey], [0n, 0n], [0n], [this.limit], [this.renewPeriod]),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysMismatchedInitDataLengths');
    });
  });

  describe('_addKeys past-start ban', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('reverts addKeysWithConfig when start is in the past', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig([this.otherKey], [1n], [0n], [this.limit], [this.renewPeriod]),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidStart')
        .withArgs(1n);
    });

    it('reverts addKeys (parent public) when start is in the past', async function () {
      await expect(this.mockFromAccount.addKeys([this.otherKey], [1n], [0n]))
        .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderInvalidStart')
        .withArgs(1n);
    });

    it('allows start = 0 (resolves to clock())', async function () {
      await this.mockFromAccount.addKeysWithConfig([this.otherKey], [0n], [0n], [this.limit], [this.renewPeriod]);
      const [from] = await this.mock.validity(this.mockAccount.address, this.otherKey);
      expect(from).to.be.gt(0n);
    });

    it('allows start in the future', async function () {
      const future = BigInt(await time.clock.timestamp()) + time.duration.days(1);
      await this.mockFromAccount.addKeysWithConfig([this.otherKey], [future], [0n], [this.limit], [this.renewPeriod]);
      const [from] = await this.mock.validity(this.mockAccount.address, this.otherKey);
      expect(from).to.equal(future);
    });

    it('allows re-adding a removed key with start = 0', async function () {
      await this.mockFromAccount.removeKeys([this.key]);
      await this.mockFromAccount.addKeysWithConfig([this.key], [0n], [0n], [this.limit], [this.renewPeriod]);
      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
      await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(this.limit);
    });
  });

  describe('removeKeys', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('removes the key and clears its spending config', async function () {
      await expect(this.mockFromAccount.removeKeys([this.key]))
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeyUnset')
        .withArgs(this.mockAccount.address, this.key)
        .and.to.emit(this.mock, 'ERC7579NativeSpendingConfigUnset')
        .withArgs(this.mockAccount.address, this.key);

      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
      await expect(this.mock.limit(this.mockAccount.address, this.key)).to.eventually.equal(0n);
      await expect(this.mock.renewPeriod(this.mockAccount.address, this.key)).to.eventually.equal(0n);
    });

    it('preserves spending history at the historical start timepoint', async function () {
      const amount = ethers.parseEther('3');
      const before = await this.mock.validity(this.mockAccount.address, this.key);
      const historicalStart = before[0];

      await this.mock
        .connect(this.sessionKey)
        .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, amount);
      await expect(
        this.mock['spent(address,bytes,uint256,uint256)'](this.mockAccount.address, this.key, 0, historicalStart),
      ).to.eventually.equal(amount);

      await this.mockFromAccount.removeKeys([this.key]);

      // After removal, validity returns (0, 0) so the convenience accessor reads from start=0 (returns 0)
      await expect(this.mock.spent(this.mockAccount.address, this.key, 0)).to.eventually.equal(0n);
      // Historical data is still readable through the explicit-start overload
      await expect(
        this.mock['spent(address,bytes,uint256,uint256)'](this.mockAccount.address, this.key, 0, historicalStart),
      ).to.eventually.equal(amount);
    });
  });

  describe('transferFrom (EOA self-call)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('transfers when called by the EOA holder of the key', async function () {
      const amount = ethers.parseEther('3');
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, amount),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-amount, amount]);
      await expect(this.mock.spent(this.mockAccount.address, this.key, 0)).to.eventually.equal(amount);
    });

    it('reverts when called by an EOA that does not match the key', async function () {
      await expect(
        this.mock.connect(this.other).transferFrom(this.mockAccount.address, this.key, this.recipient1.address, 1n),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderUnauthorized')
        .withArgs(this.other.address, this.key);
    });

    it('reverts when the key is unregistered (no validity range)', async function () {
      await expect(
        this.mock
          .connect(this.otherSessionKey)
          .transferFrom(this.mockAccount.address, this.otherKey, this.recipient1.address, 1n),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderUnauthorized')
        .withArgs(this.otherSessionKey.address, this.otherKey);
    });

    it('reverts when amount exceeds available limit', async function () {
      const amount = this.limit + 1n;
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, amount),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');
    });

    it('renews the limit on the next period', async function () {
      await this.mock
        .connect(this.sessionKey)
        .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, this.limit);
      await time.increaseBy.timestamp(this.renewPeriod);
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, this.limit),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1], [-this.limit, this.limit]);
      await expect(this.mock.spent(this.mockAccount.address, this.key, 1)).to.eventually.equal(this.limit);
    });

    it('reverts when the key is not yet active (future start)', async function () {
      const futureStart = BigInt(await time.clock.timestamp()) + time.duration.years(1);
      // Re-register `otherKey` with a future from
      await this.mockFromAccount.addKeysWithConfig(
        [this.otherKey],
        [futureStart],
        [0n],
        [this.limit],
        [this.renewPeriod],
      );
      await expect(
        this.mock
          .connect(this.otherSessionKey)
          .transferFrom(this.mockAccount.address, this.otherKey, this.recipient1.address, 1n),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderUnauthorized')
        .withArgs(this.otherSessionKey.address, this.otherKey);
    });

    it('reverts when the module is uninstalled as executor (validator-only install)', async function () {
      // Drop the executor role; the validator role still holds the keys.
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_EXECUTOR, this.mock.target, '0x');

      // The auth path still succeeds (key is registered, msg.sender matches), but `_execute`
      // calls `account.executeFromExecutor`, which the account rejects since this module is
      // no longer installed under MODULE_TYPE_EXECUTOR.
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.recipient1.address, 1n),
      ).to.be.reverted;
    });
  });

  describe('batchTransferFrom (EOA self-call)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('transfers to multiple recipients', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('3'), ethers.parseEther('4')];
      const total = amounts.reduce((a, b) => a + b, 0n);

      await expect(
        this.mock.connect(this.sessionKey).batchTransferFrom(this.mockAccount.address, this.key, tos, amounts),
      ).to.changeEtherBalances([this.mockAccount, this.recipient1, this.recipient2], [-total, amounts[0], amounts[1]]);
      await expect(this.mock.spent(this.mockAccount.address, this.key, 0)).to.eventually.equal(total);
    });

    it('reverts on mismatched array lengths', async function () {
      await expect(
        this.mock
          .connect(this.sessionKey)
          .batchTransferFrom(
            this.mockAccount.address,
            this.key,
            [this.recipient1.address, this.recipient2.address],
            [1n],
          ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeSpenderMismatchedBatchLengths');
    });

    it('reverts when the total exceeds available', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [this.limit, 1n];
      await expect(
        this.mock.connect(this.sessionKey).batchTransferFrom(this.mockAccount.address, this.key, tos, amounts),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579NativeInsufficientAvailable');
    });
  });

  describe('UserOp flow (validator + executor)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('processes a transferFrom UserOp end-to-end', async function () {
      const amount = ethers.parseEther('3');
      const userOp = await this.buildSpendUserOp({ amount });
      const before = await ethers.provider.getBalance(this.recipient1.address);

      await predeploy.entrypoint.v09.handleOps([userOp.packed], this.other.address);

      const after = await ethers.provider.getBalance(this.recipient1.address);
      expect(after - before).to.equal(amount);
      await expect(this.mock.spent(this.mockAccount.address, this.key, 0)).to.eventually.equal(amount);
    });

    it('processes a batchTransferFrom UserOp end-to-end', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('2'), ethers.parseEther('3')];
      const total = amounts.reduce((a, b) => a + b, 0n);
      const userOp = await this.buildSpendUserOp({ batch: true, tos, amounts });

      const beforeBalances = await Promise.all(tos.map(a => ethers.provider.getBalance(a)));
      await predeploy.entrypoint.v09.handleOps([userOp.packed], this.other.address);
      const afterBalances = await Promise.all(tos.map(a => ethers.provider.getBalance(a)));

      for (let i = 0; i < tos.length; i++) {
        expect(afterBalances[i] - beforeBalances[i]).to.equal(amounts[i]);
      }
      await expect(this.mock.spent(this.mockAccount.address, this.key, 0)).to.eventually.equal(total);
    });
  });

  describe('_validateUserOp (callData gate)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('packs success with validity range for a valid UserOp', async function () {
      const userOp = await this.buildSpendUserOp({ amount: 1n });
      const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
      const expectedReturn = ethers.toBigInt(packValidationData(from - 1n, until, true, ValidationRange.Timestamp));

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(expectedReturn);
    });

    it('returns SIG_VALIDATION_FAILURE when callData is empty', async function () {
      const userOp = await this.mockAccount.createUserOp({ callData: '0x' });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when callData is not execute()', async function () {
      const userOp = await this.mockAccount.createUserOp({ callData: '0xdeadbeef' + '00'.repeat(96) });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE for CALLTYPE_BATCH outer mode', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.key,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [BATCH_MODE, execCalldata]);
      const userOp = await this.mockAccount.createUserOp({ callData });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when target is not the module', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.key,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.other.address, 0, innerCall); // wrong target
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const userOp = await this.mockAccount.createUserOp({ callData });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when value is non-zero', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.key,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.mock.target, 1, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const userOp = await this.mockAccount.createUserOp({ callData });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when inner selector is unknown', async function () {
      // Any non-transferFrom / non-batchTransferFrom selector on the module triggers the gate.
      const innerCall = this.mock.interface.encodeFunctionData('addKeysWithConfig', [
        [this.otherKey],
        [0n],
        [0n],
        [this.limit],
        [this.renewPeriod],
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const userOp = await this.mockAccount.createUserOp({ callData });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when the callData key does not match the signature key', async function () {
      // Register a second key
      await this.mockFromAccount.addKeysWithConfig([this.otherKey], [0n], [0n], [this.limit], [this.renewPeriod]);

      // Sign with `key` but put `otherKey` in the callData
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.otherKey,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const userOp = await this.mockAccount.createUserOp({ callData });
      const keySignature = await this.sessionKey.signTypedData(
        this.entrypointDomain,
        { PackedUserOperation },
        userOp.packed,
      );
      userOp.signature = encodeSessionKeySig(this.key, keySignature); // signed by `key`, but inner uses `otherKey`

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });
  });
});
