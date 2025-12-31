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

const { shouldBehaveLikeERC7579Module } = require('../ERC7579Module.behavior');
const { shouldBehaveLikeERC7579MultisigWeighted } = require('../ERC7579Multisig.behavior');

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();
const signerECDSA3 = ethers.Wallet.createRandom();
const signerECDSA4 = ethers.Wallet.createRandom();

async function fixture() {
  // Deploy ERC-7579 multisig weighted module
  const mock = await ethers.deployContract('$ERC7579MultisigWeightedValidator');
  const target = await ethers.deployContract('CallReceiverMock');

  // ERC-4337 env
  const helper = new ERC4337Helper();
  await helper.wait();

  // Prepare signers with weights
  const signers = [signerECDSA1.address, signerECDSA2.address, signerECDSA3.address];
  const weights = [1, 2, 3]; // Different weights for each signer
  const threshold = 3; // Set to 3 to match the default weights during initialization (3 signers × 1 weight = 3)

  // Create multi-signer instance
  const multiSigner = new NonNativeSigner(
    new MultiERC7913SigningKey([signerECDSA1, signerECDSA2, signerECDSA3], weights),
  );

  // Prepare module installation data
  const installData = ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes[]', 'uint256', 'uint256[]'],
    [signers, threshold, weights],
  );

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
    nonSigner: signerECDSA4.address,
    weights,
    threshold,
    multiSigner,
  };
}

describe('ERC7579MultisigWeighted', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  shouldBehaveLikeERC7579Module();
  shouldBehaveLikeERC7579MultisigWeighted();

  describe('signature validation with weights', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('validates signatures meeting threshold through combined weights', async function () {
      // Threshold is 3, signerECDSA1(weight=1) + signerECDSA2(weight=2) = 3, which equals threshold
      // Or just signerECDSA3(weight=3) alone is enough
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);

      // Try with exactly the threshold weight (1+2=3 = threshold 3)
      const exactSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, signerECDSA2]));
      const exactSignature = await exactSigner.signMessage(testMessage);

      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, exactSignature)).to
        .eventually.be.true;

      // Also works with all signers (1+2+3=6 > threshold 3)
      const sufficientSignature = await this.multiSigner.signMessage(testMessage);

      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, sufficientSignature)).to
        .eventually.be.true;

      // Also try with just signerECDSA3 (weight 3) = 3, exactly meeting threshold
      const minimumSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA3]));
      const minimumSignature = await minimumSigner.signMessage(testMessage);

      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, minimumSignature)).to
        .eventually.be.true;
    });

    it('rejects signatures that collectively miss threshold', async function () {
      // Increase threshold to 4 (more than the default total of 3)
      await this.mockFromAccount.setThreshold(4);

      // Single signer with weight 1 is insufficient
      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);
      const insufficientSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1]));
      const insufficientSignature = await insufficientSigner.signMessage(testMessage);

      // Should fail because total weight (1) < threshold (4)
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, insufficientSignature)).to
        .eventually.be.false;
    });

    it('considers weight changes when validating signatures', async function () {
      // Increase threshold to 4
      await this.mockFromAccount.setThreshold(4);

      const testMessage = 'test';
      const messageHash = ethers.hashMessage(testMessage);

      // Create signer with just signerECDSA1 + signerECDSA2 (weight 1+2=3 < threshold 4)
      const insufficientSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, signerECDSA2]));
      const insufficientSignature = await insufficientSigner.signMessage(testMessage);

      // First verify this combination is insufficient
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, insufficientSignature)).to
        .eventually.be.false;

      // Now increase the weight of signerECDSA2 to make it sufficient
      await this.mockFromAccount.setSignerWeights([this.signers[1]], [3]); // Now weight is 1+3=4 >= threshold 4

      // Same signature should now pass
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, insufficientSignature)).to
        .eventually.be.true;
    });

    it('rejects invalid signatures regardless of weight', async function () {
      // Even with a high weight, invalid signatures should be rejected
      await this.mockFromAccount.setSignerWeights([this.signers[0]], [10]); // Very high weight

      const testMessage = 'test';
      const differentMessage = 'different test';
      const messageHash = ethers.hashMessage(testMessage);

      // Sign the wrong message
      const invalidSigner = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1]));
      const invalidSignature = await invalidSigner.signMessage(differentMessage);

      // Should fail because signature is invalid for the hash
      await expect(this.mock.$_rawERC7579Validation(this.mockAccount.address, messageHash, invalidSignature)).to
        .eventually.be.false;
    });
  });
});
