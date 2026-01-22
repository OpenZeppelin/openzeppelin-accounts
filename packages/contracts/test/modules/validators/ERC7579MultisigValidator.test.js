const { ethers, predeploy } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { ERC4337Helper } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const {
  MODULE_TYPE_VALIDATOR,
  CALL_TYPE_CALL,
  EXEC_TYPE_DEFAULT,
  encodeMode,
  encodeSingle,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const {
  NonNativeSigner,
  MultiERC7913SigningKey,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/signers');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');

const { shouldBehaveLikeERC7579Module, shouldBehaveLikeERC7579Validator } = require('../ERC7579Module.behavior');
const { shouldBehaveLikeERC7579Multisig } = require('../ERC7579Multisig.behavior');

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();
const signerECDSA3 = ethers.Wallet.createRandom();

async function fixture() {
  const [other] = await ethers.getSigners();

  // Deploy ERC-7579 multisig module
  const mock = await ethers.deployContract('$ERC7579MultisigValidator');
  const target = await ethers.deployContract('CallReceiverMock');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();
  const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

  // Prepare signers
  const signers = [signerECDSA1.address, signerECDSA2.address];
  const threshold = 1;
  const signer = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, signerECDSA2]));
  const signUserOp = userOp =>
    signer
      .signTypedData(entrypointDomain, { PackedUserOperation }, userOp.packed)
      .then(signature => Object.assign(userOp, { signature }));

  // Prepare module installation data
  const installData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint256'], [signers, threshold]);

  // ERC-7579 account
  const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
  const mockFromAccount = await impersonate(mockAccount.address).then(asAccount => mock.connect(asAccount));
  const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
    mockAccount.connect(asEntrypoint),
  );

  const moduleType = MODULE_TYPE_VALIDATOR;

  await mockAccount.deploy();

  const args = [42, '0x1234'];
  const data = target.interface.encodeFunctionData('mockFunctionWithArgs', args);
  const calldata = encodeSingle(target, 0, data);
  const mode = encodeMode({ callType: CALL_TYPE_CALL, execType: EXEC_TYPE_DEFAULT });

  return {
    moduleType,
    mock,
    mockAccount,
    mockFromAccount,
    mockAccountFromEntrypoint,
    target,
    installData,
    args,
    data,
    calldata,
    mode,
    signers,
    nonSigner: signerECDSA3.address,
    threshold,
    signer,
    signUserOp,
    other,
  };
}

describe('ERC7579Multisig', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();
  shouldBehaveLikeERC7579Multisig();
  shouldBehaveLikeERC7579Validator();

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('validates multiple signatures meeting threshold', async function () {
      // Set threshold to 2
      await this.mockFromAccount.setThreshold(2);

      // Create hash and sign it
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await this.signer.signMessage(testMessage);
      // Should succeed with valid signatures meeting threshold
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, multiSignature)).to
        .eventually.be.true;
    });

    it('rejects signatures not meeting threshold', async function () {
      // First set threshold to 2
      await this.mockFromAccount.setThreshold(2);

      // Create MultiERC7913SigningKey with one authorized signer
      const signer = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1]));

      // Create hash and sign it
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await signer.signMessage(testMessage);

      // Should fail because threshold is 2 but only 1 signature provided
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, multiSignature)).to
        .eventually.be.false;
    });

    it('validates valid signatures meeting threshold', async function () {
      // Create MultiERC7913SigningKey with one authorized signer
      const signer = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1]));

      // Create hash and sign it
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await signer.signMessage(testMessage);

      // Should succeed with valid signature meeting threshold
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, multiSignature)).to
        .eventually.be.true;
    });

    it('rejects signatures from unauthorized signers', async function () {
      // Create MultiERC7913SigningKey with unauthorized signer
      const signer = new NonNativeSigner(new MultiERC7913SigningKey([ethers.Wallet.createRandom()]));

      // Create hash and sign it
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await signer.signMessage(testMessage);

      // Should fail because signer is not authorized
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, multiSignature)).to
        .eventually.be.false;
    });

    it('rejects invalid signatures from authorized signers', async function () {
      // Create hash and sign it with a different message
      const testMessage = 'test';
      const differentMessage = 'different test';
      const messageHash = ethers.hashMessage(testMessage);
      const multiSignature = await this.signer.signMessage(differentMessage);

      // Should fail because signature is for a different hash
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, multiSignature)).to
        .eventually.be.false;
    });
  });
});
