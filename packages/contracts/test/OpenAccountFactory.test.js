const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const {
  MODULE_TYPE_VALIDATOR,
  MODULE_TYPE_EXECUTOR,
  encodeMode,
  encodeSingle,
  encodeBatch,
  CALL_TYPE_CALL,
  CALL_TYPE_BATCH,
} = require('../../../lib/@openzeppelin-contracts/test/helpers/erc7579');

async function fixture() {
  const [deployer, signer, otherSigner] = await ethers.getSigners();

  const factory = await ethers.deployContract('OpenAccountFactory');
  const validator = await ethers.deployContract('$ERC7579ValidatorMock');
  const executor = await ethers.deployContract('$ERC7579ExecutorMock');
  const target = await ethers.deployContract('CallReceiverMock');
  const implementation = await factory.implementation();

  const getProxyCodeHash = () =>
    ethers.keccak256(
      ethers.concat([
        '0x60395f8160225f3973',
        implementation,
        '0x60095155f3365f5f375f5f365f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d5f5f3e5f3d91603757fd5bf3',
      ]),
    );

  return { deployer, signer, otherSigner, factory, validator, executor, target, getProxyCodeHash };
}

describe('OpenAccountFactory', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  describe('predictAddress', function () {
    it('predicts an address with single module', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];
      const proxyCodeHash = this.getProxyCodeHash();

      await expect(
        this.factory.predictAddress(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash),
      ).to.eventually.be.eq(
        ethers.getCreate2Address(
          this.factory.target,
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32'],
              [moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash],
            ),
          ),
          proxyCodeHash,
        ),
      );
    });

    it('predicts an address with multiple modules', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR];
      const modules = [this.validator.target, this.executor.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address]), '0x'];

      const proxyCodeHash = this.getProxyCodeHash();
      await expect(
        this.factory.predictAddress(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash),
      ).to.eventually.be.eq(
        ethers.getCreate2Address(
          this.factory.target,
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32'],
              [moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash],
            ),
          ),
          proxyCodeHash,
        ),
      );
    });

    it('predicts an address with single configuration', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];
      const configMode = encodeMode({ callType: CALL_TYPE_CALL });

      const configCalldata = encodeSingle(
        this.target,
        0,
        this.target.interface.encodeFunctionData('mockFunctionWithArgs', [42n, 100n]),
      );
      const proxyCodeHash = this.getProxyCodeHash();
      await expect(
        this.factory.predictAddress(moduleTypeIds, modules, initDatas, configMode, configCalldata, ethers.ZeroHash),
      ).to.eventually.be.eq(
        ethers.getCreate2Address(
          this.factory.target,
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32'],
              [moduleTypeIds, modules, initDatas, configMode, configCalldata, ethers.ZeroHash],
            ),
          ),
          proxyCodeHash,
        ),
      );
    });

    it('predicts an address with batch configuration', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];
      const configMode = encodeMode({ callType: CALL_TYPE_BATCH });
      const configCalldata = encodeBatch(
        [this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [10n, 20n])],
        [this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [30n, 40n])],
      );
      const proxyCodeHash = this.getProxyCodeHash();
      await expect(
        this.factory.predictAddress(moduleTypeIds, modules, initDatas, configMode, configCalldata, ethers.ZeroHash),
      ).to.eventually.be.eq(
        ethers.getCreate2Address(
          this.factory.target,
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ['uint256[]', 'address[]', 'bytes[]', 'bytes32', 'bytes', 'bytes32'],
              [moduleTypeIds, modules, initDatas, configMode, configCalldata, ethers.ZeroHash],
            ),
          ),
          proxyCodeHash,
        ),
      );
    });

    it('predicts different addresses for different signers', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];

      const moduleSigner = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        [ethers.solidityPacked(['address'], [this.signer.address])],
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      const moduleOtherSigner = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        [ethers.solidityPacked(['address'], [this.otherSigner.address])],
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      expect(moduleSigner).to.not.equal(moduleOtherSigner);
    });

    it('predicts different addresses for different modules', async function () {
      const moduleTypeIds1 = [MODULE_TYPE_VALIDATOR];
      const modules1 = [this.validator.target];
      const initDatas1 = [ethers.solidityPacked(['address'], [this.signer.address])];

      const moduleTypeIds2 = [MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR];
      const modules2 = [this.validator.target, this.executor.target];
      const initDatas2 = [ethers.solidityPacked(['address'], [this.signer.address]), '0x'];

      const moduleValidator = await this.factory.predictAddress(
        moduleTypeIds1,
        modules1,
        initDatas1,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      const moduleValidatorExecutor = await this.factory.predictAddress(
        moduleTypeIds2,
        modules2,
        initDatas2,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      expect(moduleValidator).to.not.equal(moduleValidatorExecutor);
    });
  });

  describe('createAndInitialize', function () {
    it('creates and initializes with single module', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];

      const predicted = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      const deployed = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      expect(deployed).to.equal(predicted);

      await this.factory.createAndInitialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash);

      const account = await ethers.getContractAt('OpenAccount', deployed);
      await expect(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
    });

    it('creates and initializes with multiple modules', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR];
      const modules = [this.validator.target, this.executor.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address]), '0x'];

      const predicted = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      const deployed = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      expect(deployed).to.equal(predicted);

      await this.factory.createAndInitialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash);

      const account = await ethers.getContractAt('OpenAccount', deployed);
      await expect(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
      await expect(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, this.executor.target, '0x')).to.eventually.be.true;
    });

    it('is idempotent', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];

      const deployed1 = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      await this.factory.createAndInitialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash);

      const deployed2 = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      await this.factory.createAndInitialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash);

      expect(deployed1).to.equal(deployed2);
    });

    it('creates different accounts for different signers', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];

      const initDatas1 = [ethers.solidityPacked(['address'], [this.signer.address])];
      const deployed1 = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas1,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      await this.factory.createAndInitialize(
        moduleTypeIds,
        modules,
        initDatas1,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      const initDatas2 = [ethers.solidityPacked(['address'], [this.otherSigner.address])];
      const deployed2 = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas2,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      await this.factory.createAndInitialize(
        moduleTypeIds,
        modules,
        initDatas2,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );

      expect(deployed1).to.not.equal(deployed2);

      const account1 = await ethers.getContractAt('OpenAccount', deployed1);
      const account2 = await ethers.getContractAt('OpenAccount', deployed2);
      await expect(account1.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be
        .true;
      await expect(account1.isModuleInstalled(MODULE_TYPE_EXECUTOR, this.executor.target, '0x')).to.eventually.be.false;
      await expect(account2.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be
        .true;
      await expect(account2.isModuleInstalled(MODULE_TYPE_EXECUTOR, this.executor.target, '0x')).to.eventually.be.false;
    });

    it('deploys account that can be initialized only once', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];

      const deployed = await this.factory.createAndInitialize.staticCall(
        moduleTypeIds,
        modules,
        initDatas,
        ethers.ZeroHash,
        '0x',
        ethers.ZeroHash,
      );
      await this.factory.createAndInitialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x', ethers.ZeroHash);

      const account = await ethers.getContractAt('OpenAccount', deployed);

      await expect(
        account.initialize(moduleTypeIds, modules, initDatas, ethers.ZeroHash, '0x'),
      ).to.be.revertedWithCustomError(account, 'InvalidInitialization');
    });

    it('creates account with single call configuration', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];

      const configMode = encodeMode({ callType: CALL_TYPE_CALL });
      const configCalldata = encodeSingle(
        this.target,
        0,
        this.target.interface.encodeFunctionData('mockFunctionWithArgs', [42n, 100n]),
      );

      const predicted = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        initDatas,
        configMode,
        configCalldata,
        ethers.ZeroHash,
      );

      await expect(
        this.factory.createAndInitialize(
          moduleTypeIds,
          modules,
          initDatas,
          configMode,
          configCalldata,
          ethers.ZeroHash,
        ),
      )
        .to.emit(this.target, 'MockFunctionCalledWithArgs')
        .withArgs(42n, 100n);

      const account = await ethers.getContractAt('OpenAccount', predicted);
      await expect(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
    });

    it('creates account with batch call configuration', async function () {
      const moduleTypeIds = [MODULE_TYPE_VALIDATOR];
      const modules = [this.validator.target];
      const initDatas = [ethers.solidityPacked(['address'], [this.signer.address])];

      const configMode = encodeMode({ callType: CALL_TYPE_BATCH });
      const configCalldata = encodeBatch(
        [this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [10n, 20n])],
        [this.target, 0, this.target.interface.encodeFunctionData('mockFunctionWithArgs', [30n, 40n])],
      );

      const predicted = await this.factory.predictAddress(
        moduleTypeIds,
        modules,
        initDatas,
        configMode,
        configCalldata,
        ethers.ZeroHash,
      );

      await expect(
        this.factory.createAndInitialize(
          moduleTypeIds,
          modules,
          initDatas,
          configMode,
          configCalldata,
          ethers.ZeroHash,
        ),
      )
        .to.emit(this.target, 'MockFunctionCalledWithArgs')
        .withArgs(10n, 20n)
        .to.emit(this.target, 'MockFunctionCalledWithArgs')
        .withArgs(30n, 40n);

      const account = await ethers.getContractAt('OpenAccount', predicted);
      await expect(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, this.validator.target, '0x')).to.eventually.be.true;
    });
  });
});
