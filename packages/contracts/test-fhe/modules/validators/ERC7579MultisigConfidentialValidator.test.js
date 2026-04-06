const { ethers, fhevm, predeploy } = require('hardhat');
const { expect } = require('chai');
const { FhevmType } = require('@fhevm/hardhat-plugin');

const { impersonate } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/account');
const { ERC4337Helper } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc4337');
const { MODULE_TYPE_VALIDATOR } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/erc7579');
const {
  NonNativeSigner,
  MultiERC7913SigningKey,
  P256SigningKey,
} = require('../../../../../lib/@openzeppelin-contracts/test/helpers/signers');
const { getDomain, PackedUserOperation } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');

const {
  shouldBehaveLikeERC7579Module,
  shouldBehaveLikeERC7579Validator,
} = require('../../../test/modules/ERC7579Module.behavior');
const { allowHandle } = require('../../helpers/fhe');
const { MAX_UINT32 } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/constants');
const {
  toId,
  shouldBehaveLikeERC7579MultisigConfidential,
  shouldBehaveLikeOperationDiscloser,
} = require('../ERC7579MultisigConfidential.behavior');

const TEST_MESSAGE = 'OpenZeppelin';
const TEST_MESSAGE_HASH = ethers.hashMessage(TEST_MESSAGE);

const WRONG_MESSAGE = 'Nope';
const WRONG_MESSAGE_HASH = ethers.hashMessage(WRONG_MESSAGE);

// Prepare signers in advance
const signerECDSA1 = ethers.Wallet.createRandom();
const signerECDSA2 = ethers.Wallet.createRandom();

// Prepare P256 signers for ERC-7913 tests
const aliceP256 = new NonNativeSigner(P256SigningKey.random());
const bobP256 = new NonNativeSigner(P256SigningKey.random());

describe('ERC7579MultisigConfidentialValidator', function () {
  beforeEach(async function () {
    const [other] = await ethers.getSigners();
    // Deploy ERC-7579 multisig confidential validator
    const mock = await ethers.deployContract('$ERC7579MultisigConfidentialValidatorMock');

    // ERC-4337 env
    const helper = new ERC4337Helper();
    await helper.wait();
    const entrypointDomain = await getDomain(predeploy.entrypoint.v09);

    // ERC-7579 account
    const mockAccount = await helper.newAccount('$OpenAccount', ['OpenAccount', '1']);
    const accountAsSigner = await impersonate(mockAccount.address);
    const mockFromAccount = mock.connect(accountAsSigner);
    const mockAccountFromEntrypoint = await impersonate(predeploy.entrypoint.v09.target).then(asEntrypoint =>
      mockAccount.connect(asEntrypoint),
    );

    await mockAccount.deploy();

    // Deploy ERC-7913 verifier
    const verifier = await ethers.deployContract('ERC7913P256Verifier');

    // Prepare mixed signers: one EOA and one ERC-7913 (P256)
    aliceP256.bytes = ethers.concat([
      verifier.target,
      aliceP256.signingKey.publicKey.qx,
      aliceP256.signingKey.publicKey.qy,
    ]);
    bobP256.bytes = ethers.concat([verifier.target, bobP256.signingKey.publicKey.qx, bobP256.signingKey.publicKey.qy]);

    // Prepare signer bytes for encryption and multi-signer
    const threshold = 1;
    const signer = new NonNativeSigner(new MultiERC7913SigningKey([signerECDSA1, aliceP256]));
    const rawSignMessage = signer.signMessage.bind(signer);
    const rawSignTypedData = signer.signTypedData.bind(signer);

    const requestDisclose = async (hash, signingSigners, signatures) => {
      const signerHandles = await mock.getSigners(mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(accountAsSigner, signerECDSA1.address, handle)));

      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(FhevmType.euint256, handle, mockAccount.address, signerECDSA1);
        signerIds.push(decryptedId);
      }

      const receipt = await mock
        .requestDiscloseOperation(
          mockAccount.address,
          hash,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => ethers.hexlify(signerHandles[signerIds.findIndex(id => id === toId(signer))])),
          signatures.map(signature => ethers.hexlify(signature)),
        )
        .then(tx => tx.wait());

      const [[, , , encryptedBool]] = receipt.logs
        .map(log => mock.interface.parseLog(log))
        .filter(log => log?.name === 'ERC7579MultisigOperationDiscloseRequested')
        .map(log => log.args.map(arg => ethers.hexlify(arg)));

      return fhevm.publicDecrypt([encryptedBool]);
    };

    const disclose = async (hash, signingSigners, signatures) =>
      requestDisclose(hash, signingSigners, signatures).then(decryptResult =>
        mock.discloseOperation(mockAccount.address, hash, decryptResult.decryptionProof),
      );

    signer.signMessage = async function (message) {
      const hash = ethers.hashMessage(message);
      const signature = await rawSignMessage(message);
      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes[]', 'bytes[]'], signature);
      await disclose(hash, signingSigners, signatures);

      return signature;
    };

    signer.signTypedData = async function (domain, types, value) {
      const hash = ethers.TypedDataEncoder.hash(domain, types, value);
      const signature = await rawSignTypedData(domain, types, value);
      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes[]', 'bytes[]'], signature);
      await disclose(hash, signingSigners, signatures);

      return signature;
    };

    const signUserOp = async userOp => {
      const hash = ethers.TypedDataEncoder.hash(entrypointDomain, { PackedUserOperation }, userOp.packed);
      const { serialized: signature } = this.signer.signingKey.sign(hash);
      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes[]', 'bytes[]'], signature);
      const decryptResult = await requestDisclose(hash, signingSigners, signatures);
      userOp.signature = ethers.concat([
        ethers.getBytes(ethers.zeroPadValue(this.mock.runner.address, 20)),
        decryptResult.decryptionProof,
      ]);
      return userOp;
    };

    // Encrypt signers and threshold using fhevm
    // EOA: cast to uint256, ERC-7913: hash with keccak256 then cast to uint256
    const input = fhevm.createEncryptedInput(mock.target, mockAccount.address);
    input.add32(threshold);
    input.add256(signerECDSA1.address); // EOA: cast to uint256
    input.add256(ethers.keccak256(aliceP256.bytes)); // ERC-7913: hash then cast
    const encrypted = await input.encrypt();
    const signerHandles = encrypted.handles.slice(1);

    Object.assign(this, {
      moduleType: MODULE_TYPE_VALIDATOR,
      mock,
      mockAccount,
      accountAsSigner,
      mockFromAccount,
      mockAccountFromEntrypoint,
      installData: ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes', 'bytes32[]', 'bytes32'],
        [encrypted.inputProof, signerHandles.map(handle => ethers.hexlify(handle)), encrypted.handles.at(0)],
      ),
      signerHandles,
      threshold,
      signer,
      verifier,
      signers: [signerECDSA1, aliceP256],
      nonSigners: [signerECDSA2, bobP256],
      signUserOp,
      other,
    });
  });

  shouldBehaveLikeERC7579Module();
  shouldBehaveLikeERC7579MultisigConfidential();
  shouldBehaveLikeOperationDiscloser();
  shouldBehaveLikeERC7579Validator();

  describe('signature validation', function () {
    beforeEach(async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
    });

    it('validates multiple signatures meeting threshold', async function () {
      const signerHandles = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT32);
      await Promise.all(signerHandles.map(handle => allowHandle(this.accountAsSigner, signerECDSA1.address, handle)));

      // Get signer IDs for matching
      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(
          FhevmType.euint256,
          handle,
          this.mockAccount.address,
          signerECDSA1,
        );
        signerIds.push(decryptedId);
      }

      const multiSignature = await this.signer.signMessage(TEST_MESSAGE);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          TEST_MESSAGE_HASH,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => ethers.hexlify(signerHandles[signerIds.findIndex(id => id === toId(signer))])),
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

      // Get signer IDs for matching
      const signerIds = [];
      for (const handle of signerHandles) {
        const decryptedId = await fhevm.userDecryptEuint(
          FhevmType.euint256,
          handle,
          this.mockAccount.address,
          signerECDSA1,
        );
        signerIds.push(decryptedId);
      }

      const multiSignature = await this.signer.signMessage(TEST_MESSAGE);

      const [signingSigners, signatures] = ethers.AbiCoder.defaultAbiCoder().decode(
        ['bytes[]', 'bytes[]'],
        multiSignature,
      );

      const receipt = await this.mock
        .$_validateMultisig(
          this.mockAccount.address,
          WRONG_MESSAGE_HASH,
          signingSigners.map(signer => ethers.hexlify(signer)),
          signingSigners.map(signer => ethers.hexlify(signerHandles[signerIds.findIndex(id => id === toId(signer))])),
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
