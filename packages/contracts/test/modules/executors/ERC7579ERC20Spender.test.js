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

const SINGLE_MODE = ethers.ZeroHash;
const BATCH_MODE = '0x01' + '00'.repeat(31);

// First-install bundle: (bytes[] keys, uint48[] starts, uint48[] ends)
const encodeKeysInstall = (keys, starts, ends) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint48[]', 'uint48[]'], [keys, starts, ends]);

// Second-install bundle: (bytes[] keys, address[] tokens, uint160[] limits, uint48[] renewPeriods)
const encodeConfigInstall = (keys, tokens, limits, renewPeriods) =>
  ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes[]', 'address[]', 'uint160[]', 'uint48[]'],
    [keys, tokens, limits, renewPeriods],
  );

const encodeSessionKeySig = (key, keySignature) =>
  ethers.AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes'], [key, keySignature]);

const encodeSingle = (target, value, data) =>
  ethers.solidityPacked(['address', 'uint256', 'bytes'], [target, value, data]);

async function fixture() {
  const [other, recipient1, recipient2] = await ethers.getSigners();

  const mock = await ethers.deployContract('$ERC7579ERC20Spender');
  const token1 = await ethers.deployContract('$ERC20', ['Token1', 'TK1']);
  const token2 = await ethers.deployContract('$ERC20', ['Token2', 'TK2']);

  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  await mockAccount.deploy();
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));
  const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
    mockAccount.connect(asEntrypoint),
  );

  const sessionKey = ethers.Wallet.createRandom().connect(ethers.provider);
  const key = ethers.solidityPacked(['address'], [sessionKey.address]);
  const otherSessionKey = ethers.Wallet.createRandom().connect(ethers.provider);
  const otherKey = ethers.solidityPacked(['address'], [otherSessionKey.address]);

  const initialBalance = ethers.parseEther('100');
  await token1.$_mint(mockAccount.address, initialBalance);
  await token2.$_mint(mockAccount.address, initialBalance);
  await other.sendTransaction({ to: sessionKey.address, value: ethers.parseEther('1') });
  await other.sendTransaction({ to: otherSessionKey.address, value: ethers.parseEther('1') });

  const limit = ethers.parseEther('10');
  const renewPeriod = time.duration.days(7);
  const start = 0n; // 0 → clock()
  const end = 0n; // 0 → type(uint48).max

  const keysInstallData = encodeKeysInstall([key], [start], [end]);
  const configInstallData = encodeConfigInstall([key], [token1.target], [limit], [renewPeriod]);

  const installBoth = async (keysData = keysInstallData, configData = configInstallData) => {
    await mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, mock.target, keysData);
    await mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, mock.target, configData);
  };

  const validatorNonceKey = BigInt(mock.target) << 32n;

  const buildSpendUserOp = async ({
    key: usedKey = key,
    signer = sessionKey,
    token = token1.target,
    to = recipient1.address,
    amount,
    batch = false,
    tos,
    amounts,
  } = {}) => {
    const innerCall = batch
      ? mock.interface.encodeFunctionData('batchTransferFrom', [mockAccount.address, usedKey, token, tos, amounts])
      : mock.interface.encodeFunctionData('transferFrom', [mockAccount.address, usedKey, token, to, amount]);
    const execCalldata = encodeSingle(mock.target, 0, innerCall);
    const callData = mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);

    const nonce = await predeploy.entrypoint.v09.getNonce(mockAccount.address, validatorNonceKey);
    const userOp = await mockAccount.createUserOp({ callData, nonce, callGas: 500_000n });
    const keySignature = await signer.signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed);
    userOp.signature = encodeSessionKeySig(usedKey, keySignature);
    return userOp;
  };

  return {
    moduleType: MODULE_TYPE_VALIDATOR, // for shouldBehaveLikeERC7579Module
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
    token1,
    token2,
    initialBalance,
    limit,
    renewPeriod,
    start,
    end,
    keysInstallData,
    configInstallData,
    installData: keysInstallData,
    installBoth,
    buildSpendUserOp,
    entrypointDomain,
  };
}

describe('ERC7579ERC20Spender', function () {
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
      await expect(this.mock.isModuleType(99)).to.eventually.be.false;
    });
  });

  describe('isValidSignatureWithSender', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('always returns 0xffffffff (ERC-1271 disabled)', async function () {
      const hash = ethers.hashMessage('hello');
      const sig = encodeSessionKeySig(this.key, await this.sessionKey.signMessage('hello'));
      await expect(this.mock.isValidSignatureWithSender(this.other.address, hash, sig)).to.eventually.equal(
        '0xffffffff',
      );
    });
  });

  describe('installed / tokensCount', function () {
    it('starts uninstalled with zero tokens', async function () {
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
      await expect(this.mock.tokensCount(this.mockAccount.address)).to.eventually.equal(0n);
    });

    it('installed flips true after validator install; tokensCount stays 0', async function () {
      await this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, this.mock.target, this.keysInstallData);
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.true;
      await expect(this.mock.tokensCount(this.mockAccount.address)).to.eventually.equal(0n);
    });

    it('tokensCount goes up after executor install', async function () {
      await this.installBoth();
      await expect(this.mock.tokensCount(this.mockAccount.address)).to.eventually.equal(1n);
      const tokens = await this.mock.tokens(this.mockAccount.address, 0, ethers.MaxUint256);
      expect(tokens).to.deep.equal([this.token1.target]);
    });

    it('counts unique tokens across multi-token executor install', async function () {
      await this.installBoth(
        encodeKeysInstall([this.key, this.otherKey], [0n, 0n], [0n, 0n]),
        encodeConfigInstall(
          [this.key, this.key, this.otherKey],
          [this.token1.target, this.token2.target, this.token1.target],
          [this.limit, this.limit, this.limit],
          [this.renewPeriod, this.renewPeriod, this.renewPeriod],
        ),
      );
      await expect(this.mock.tokensCount(this.mockAccount.address)).to.eventually.equal(2n);
    });

    it('resets after uninstall', async function () {
      await this.installBoth();
      await this.mockAccountFromEntrypoint.uninstallModule(MODULE_TYPE_VALIDATOR, this.mock.target, '0x');
      await expect(this.mock.installed(this.mockAccount.address)).to.eventually.be.false;
      await expect(this.mock.tokensCount(this.mockAccount.address)).to.eventually.equal(0n);
    });
  });

  describe('onInstall', function () {
    describe('first call (validator install)', function () {
      it('registers keys via the parent', async function () {
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_VALIDATOR, this.mock.target, this.keysInstallData),
        ).to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet');
        await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
      });

      it('reverts when the first install registers zero keys', async function () {
        const empty = encodeKeysInstall([], [], []);
        await expect(this.mockFromAccount.onInstall(empty)).to.be.revertedWithCustomError(
          this.mock,
          'ERC7579ERC20SpenderEmptyKeys',
        );
      });

      it('reverts when a start is in the past', async function () {
        const bad = encodeKeysInstall([this.key], [1n], [0n]);
        await expect(this.mockFromAccount.onInstall(bad))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidStart')
          .withArgs(1n);
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

      it('writes the (key, token) config and tracks the token', async function () {
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, this.configInstallData),
        )
          .to.emit(this.mock, 'ERC7579ERC20SpendingConfigSet')
          .withArgs(this.mockAccount.address, this.key, this.token1.target, this.limit, this.renewPeriod);

        await expect(this.mock.limit(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
          this.limit,
        );
        await expect(this.mock.renewPeriod(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
          this.renewPeriod,
        );
      });

      it('allows the same key on multiple tokens (keys repeat across rows)', async function () {
        await this.mockAccountFromEntrypoint.installModule(
          MODULE_TYPE_EXECUTOR,
          this.mock.target,
          encodeConfigInstall(
            [this.key, this.key],
            [this.token1.target, this.token2.target],
            [this.limit, this.limit * 2n],
            [this.renewPeriod, this.renewPeriod],
          ),
        );
        await expect(this.mock.limit(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
          this.limit,
        );
        await expect(this.mock.limit(this.mockAccount.address, this.key, this.token2.target)).to.eventually.equal(
          this.limit * 2n,
        );
      });

      it('reverts on mismatched array lengths', async function () {
        const bad = encodeConfigInstall(
          [this.key],
          [this.token1.target, this.token2.target],
          [this.limit],
          [this.renewPeriod],
        );
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderMismatchedInitDataLengths');
      });

      it('reverts when keys array is empty', async function () {
        const bad = encodeConfigInstall([], [], [], []);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderEmptyKeys');
      });

      it('reverts when a key is not registered', async function () {
        const bad = encodeConfigInstall([this.otherKey], [this.token1.target], [this.limit], [this.renewPeriod]);
        await expect(this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579SessionKeysNonexistentKey')
          .withArgs(this.otherKey);
      });

      it('reverts on zero limit', async function () {
        const bad = encodeConfigInstall([this.key], [this.token1.target], [0n], [this.renewPeriod]);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidLimit');
      });

      it('reverts on zero renewPeriod', async function () {
        const bad = encodeConfigInstall([this.key], [this.token1.target], [this.limit], [0n]);
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidRenewPeriod');
      });

      it('reverts when token is not a contract', async function () {
        const bad = encodeConfigInstall([this.key], [this.other.address], [this.limit], [this.renewPeriod]);
        await expect(this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, bad))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidToken')
          .withArgs(this.other.address);
      });

      it('reverts on a too-short config bundle', async function () {
        const short = '0x' + '00'.repeat(0xff); // 255 bytes
        await expect(
          this.mockAccountFromEntrypoint.installModule(MODULE_TYPE_EXECUTOR, this.mock.target, short),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidInitData');
      });
    });

    describe('third call (reconfiguration ban)', function () {
      it('reverts with AlreadyInstalled when onInstall is invoked after the executor install', async function () {
        await this.installBoth();
        await expect(
          this.mockFromAccount.onInstall(
            encodeConfigInstall([this.key], [this.token2.target], [this.limit], [this.renewPeriod]),
          ),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderAlreadyInstalled');
      });
    });
  });

  describe('addKeysWithConfig', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('adds a new key with one (token, limit, renewPeriod) config', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig(
          [this.otherKey],
          [0n],
          [0n],
          [this.token2.target],
          [this.limit],
          [this.renewPeriod],
        ),
      )
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeySet')
        .and.to.emit(this.mock, 'ERC7579ERC20SpendingConfigSet')
        .withArgs(this.mockAccount.address, this.otherKey, this.token2.target, this.limit, this.renewPeriod);

      await expect(this.mock.isKey(this.mockAccount.address, this.otherKey)).to.eventually.be.true;
      await expect(this.mock.limit(this.mockAccount.address, this.otherKey, this.token2.target)).to.eventually.equal(
        this.limit,
      );
    });

    it('reverts on past start', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig(
          [this.otherKey],
          [1n],
          [0n],
          [this.token1.target],
          [this.limit],
          [this.renewPeriod],
        ),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderInvalidStart')
        .withArgs(1n);
    });

    it('reverts on mismatched lengths', async function () {
      await expect(
        this.mockFromAccount.addKeysWithConfig(
          [this.otherKey],
          [0n],
          [0n],
          [this.token1.target, this.token2.target],
          [this.limit],
          [this.renewPeriod],
        ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderMismatchedInitDataLengths');
    });
  });

  describe('removeKeys', function () {
    beforeEach(async function () {
      // Install with `key` for both tokens
      await this.installBoth(
        this.keysInstallData,
        encodeConfigInstall(
          [this.key, this.key],
          [this.token1.target, this.token2.target],
          [this.limit, this.limit],
          [this.renewPeriod, this.renewPeriod],
        ),
      );
    });

    it('clears validity but leaves spending configs intact', async function () {
      await expect(this.mockFromAccount.removeKeys([this.key]))
        .to.emit(this.mock, 'ERC7579SessionKeysERC7913KeyUnset')
        .withArgs(this.mockAccount.address, this.key);

      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.false;
      // Configs are deliberately NOT cleared on remove (documented in NatSpec).
      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
        this.limit,
      );
      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token2.target)).to.eventually.equal(
        this.limit,
      );
    });

    it('re-registering with addKeys (no addKeysWithConfig) inherits previous configs', async function () {
      await this.mockFromAccount.removeKeys([this.key]);

      // Re-register via parent's addKeys; no config writes.
      await this.mockFromAccount.addKeys([this.key], [0n], [0n]);

      await expect(this.mock.isKey(this.mockAccount.address, this.key)).to.eventually.be.true;
      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
        this.limit,
      );
      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token2.target)).to.eventually.equal(
        this.limit,
      );
    });

    it('re-registering with addKeysWithConfig overwrites the previous config for that (key, token)', async function () {
      await this.mockFromAccount.removeKeys([this.key]);

      const newLimit = ethers.parseEther('25');
      await this.mockFromAccount.addKeysWithConfig(
        [this.key],
        [0n],
        [0n],
        [this.token1.target],
        [newLimit],
        [this.renewPeriod],
      );

      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token1.target)).to.eventually.equal(
        newLimit,
      );
      // The other token's previously-set config is still there.
      await expect(this.mock.limit(this.mockAccount.address, this.key, this.token2.target)).to.eventually.equal(
        this.limit,
      );
    });
  });

  describe('transferFrom (EOA self-call)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('transfers tokens when called by the EOA holder', async function () {
      const amount = ethers.parseEther('3');
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.token1.target, this.recipient1.address, amount),
      ).to.changeTokenBalances(this.token1, [this.mockAccount, this.recipient1], [-amount, amount]);
      await expect(this.mock.spent(this.mockAccount.address, this.key, this.token1.target, 0)).to.eventually.equal(
        amount,
      );
    });

    it('reverts when caller does not match the key', async function () {
      await expect(
        this.mock
          .connect(this.other)
          .transferFrom(this.mockAccount.address, this.key, this.token1.target, this.recipient1.address, 1n),
      )
        .to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderUnauthorized')
        .withArgs(this.other.address, this.key);
    });

    it('reverts when amount exceeds available', async function () {
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(
            this.mockAccount.address,
            this.key,
            this.token1.target,
            this.recipient1.address,
            this.limit + 1n,
          ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20InsufficientAvailable');
    });

    it('reverts on a (key, token) without configured policy', async function () {
      // key has a config for token1 but NOT for token2
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.token2.target, this.recipient1.address, 1n),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpendingConfigNotSet');
    });

    it('renews the limit on the next period', async function () {
      await this.mock
        .connect(this.sessionKey)
        .transferFrom(this.mockAccount.address, this.key, this.token1.target, this.recipient1.address, this.limit);
      await time.increaseBy.timestamp(this.renewPeriod);
      await expect(
        this.mock
          .connect(this.sessionKey)
          .transferFrom(this.mockAccount.address, this.key, this.token1.target, this.recipient1.address, this.limit),
      ).to.changeTokenBalances(this.token1, [this.mockAccount, this.recipient1], [-this.limit, this.limit]);
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
          .transferFrom(this.mockAccount.address, this.key, this.token1.target, this.recipient1.address, 1n),
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
        this.mock
          .connect(this.sessionKey)
          .batchTransferFrom(this.mockAccount.address, this.key, this.token1.target, tos, amounts),
      ).to.changeTokenBalances(
        this.token1,
        [this.mockAccount, this.recipient1, this.recipient2],
        [-total, amounts[0], amounts[1]],
      );
    });

    it('reverts on mismatched batch lengths', async function () {
      await expect(
        this.mock
          .connect(this.sessionKey)
          .batchTransferFrom(
            this.mockAccount.address,
            this.key,
            this.token1.target,
            [this.recipient1.address, this.recipient2.address],
            [1n],
          ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20SpenderMismatchedBatchLengths');
    });

    it('reverts when total exceeds available', async function () {
      await expect(
        this.mock
          .connect(this.sessionKey)
          .batchTransferFrom(
            this.mockAccount.address,
            this.key,
            this.token1.target,
            [this.recipient1.address, this.recipient2.address],
            [this.limit, 1n],
          ),
      ).to.be.revertedWithCustomError(this.mock, 'ERC7579ERC20InsufficientAvailable');
    });
  });

  describe('UserOp flow (validator + executor)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('processes a transferFrom UserOp end-to-end', async function () {
      const amount = ethers.parseEther('3');
      const userOp = await this.buildSpendUserOp({ amount });

      const before = await this.token1.balanceOf(this.recipient1.address);
      await predeploy.entrypoint.v09.handleOps([userOp.packed], this.other.address);
      const after = await this.token1.balanceOf(this.recipient1.address);
      expect(after - before).to.equal(amount);
      await expect(this.mock.spent(this.mockAccount.address, this.key, this.token1.target, 0)).to.eventually.equal(
        amount,
      );
    });

    it('processes a batchTransferFrom UserOp end-to-end', async function () {
      const tos = [this.recipient1.address, this.recipient2.address];
      const amounts = [ethers.parseEther('2'), ethers.parseEther('3')];
      const total = amounts.reduce((a, b) => a + b, 0n);
      const userOp = await this.buildSpendUserOp({ batch: true, tos, amounts });

      const beforeBalances = await Promise.all(tos.map(a => this.token1.balanceOf(a)));
      await predeploy.entrypoint.v09.handleOps([userOp.packed], this.other.address);
      const afterBalances = await Promise.all(tos.map(a => this.token1.balanceOf(a)));
      for (let i = 0; i < tos.length; i++) {
        expect(afterBalances[i] - beforeBalances[i]).to.equal(amounts[i]);
      }
      await expect(this.mock.spent(this.mockAccount.address, this.key, this.token1.target, 0)).to.eventually.equal(
        total,
      );
    });
  });

  describe('_validateUserOp (callData gate)', function () {
    beforeEach(async function () {
      await this.installBoth();
    });

    it('packs success with validity range for a valid UserOp', async function () {
      const userOp = await this.buildSpendUserOp({ amount: 1n });
      const [from, until] = await this.mock.validity(this.mockAccount.address, this.key);
      const expected = ethers.toBigInt(packValidationData(from - 1n, until, true, ValidationRange.Timestamp));
      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(expected);
    });

    it('returns SIG_VALIDATION_FAILURE when inner selector is not transferFrom/batchTransferFrom', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('addKeysWithConfig', [
        [this.otherKey],
        [0n],
        [0n],
        [this.token1.target],
        [this.limit],
        [this.renewPeriod],
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const nonce = await predeploy.entrypoint.v09.getNonce(this.mockAccount.address, BigInt(this.mock.target) << 32n);
      const userOp = await this.mockAccount.createUserOp({ callData, nonce });
      const keySig = await this.sessionKey.signTypedData(this.entrypointDomain, { PackedUserOperation }, userOp.packed);
      userOp.signature = encodeSessionKeySig(this.key, keySig);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when target is not the module', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.key,
        this.token1.target,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.other.address, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const nonce = await predeploy.entrypoint.v09.getNonce(this.mockAccount.address, BigInt(this.mock.target) << 32n);
      const userOp = await this.mockAccount.createUserOp({ callData, nonce });
      const keySig = await this.sessionKey.signTypedData(this.entrypointDomain, { PackedUserOperation }, userOp.packed);
      userOp.signature = encodeSessionKeySig(this.key, keySig);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE when callData key differs from signature key', async function () {
      await this.mockFromAccount.addKeysWithConfig(
        [this.otherKey],
        [0n],
        [0n],
        [this.token1.target],
        [this.limit],
        [this.renewPeriod],
      );

      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.otherKey,
        this.token1.target,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [SINGLE_MODE, execCalldata]);
      const nonce = await predeploy.entrypoint.v09.getNonce(this.mockAccount.address, BigInt(this.mock.target) << 32n);
      const userOp = await this.mockAccount.createUserOp({ callData, nonce });
      const keySig = await this.sessionKey.signTypedData(this.entrypointDomain, { PackedUserOperation }, userOp.packed);
      userOp.signature = encodeSessionKeySig(this.key, keySig); // signed by `key`, inner uses `otherKey`

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });

    it('returns SIG_VALIDATION_FAILURE for CALLTYPE_BATCH outer mode', async function () {
      const innerCall = this.mock.interface.encodeFunctionData('transferFrom', [
        this.mockAccount.address,
        this.key,
        this.token1.target,
        this.recipient1.address,
        1n,
      ]);
      const execCalldata = encodeSingle(this.mock.target, 0, innerCall);
      const callData = this.mockAccount.interface.encodeFunctionData('execute', [BATCH_MODE, execCalldata]);
      const nonce = await predeploy.entrypoint.v09.getNonce(this.mockAccount.address, BigInt(this.mock.target) << 32n);
      const userOp = await this.mockAccount.createUserOp({ callData, nonce });
      const keySig = await this.sessionKey.signTypedData(this.entrypointDomain, { PackedUserOperation }, userOp.packed);
      userOp.signature = encodeSessionKeySig(this.key, keySig);

      await expect(this.mockFromAccount.$_validateUserOp(userOp.packed, userOp.hash()))
        .to.emit(this.mockFromAccount, 'return$_validateUserOp')
        .withArgs(SIG_VALIDATION_FAILURE);
    });
  });
});
