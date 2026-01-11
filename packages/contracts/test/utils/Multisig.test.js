const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

async function fixture() {
  // Deploy exposed Multisig library mock
  const mock = await ethers.deployContract('$Multisig');

  return { mock };
}

describe('Multisig', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  describe('tryDecodeMultisignatureCalldata', function () {
    it('decodes valid multisignature with single signer and signature', async function () {
      const signers = [ethers.hexlify(ethers.randomBytes(20))];
      const signatures = [ethers.hexlify(ethers.randomBytes(65))];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$tryDecodeMultisignatureCalldata(encoded);
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('decodes valid multisignature with multiple signers and signatures', async function () {
      const signers = [
        ethers.hexlify(ethers.randomBytes(20)),
        ethers.hexlify(ethers.randomBytes(20)),
        ethers.hexlify(ethers.randomBytes(20)),
      ];
      const signatures = [
        ethers.hexlify(ethers.randomBytes(65)),
        ethers.hexlify(ethers.randomBytes(65)),
        ethers.hexlify(ethers.randomBytes(65)),
      ];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$tryDecodeMultisignatureCalldata(encoded);
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('decodes valid multisignature with empty arrays', async function () {
      const signers = [];
      const signatures = [];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$tryDecodeMultisignatureCalldata(encoded);
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('decodes multisignature with different array lengths', async function () {
      const signers = [ethers.hexlify(ethers.randomBytes(20)), ethers.hexlify(ethers.randomBytes(20))];
      const signatures = [ethers.hexlify(ethers.randomBytes(65))];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$tryDecodeMultisignatureCalldata(encoded);
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('decodes multisignature with variable-sized signatures', async function () {
      const signers = [ethers.hexlify(ethers.randomBytes(20)), ethers.hexlify(ethers.randomBytes(20))];
      const signatures = [
        ethers.hexlify(ethers.randomBytes(65)), // Standard ECDSA signature
        ethers.hexlify(ethers.randomBytes(100)), // Larger signature
      ];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$tryDecodeMultisignatureCalldata(encoded);
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('returns false for data shorter than 128 bytes', async function () {
      const shortData = ethers.hexlify(ethers.randomBytes(0x8f));

      const result = await this.mock.$tryDecodeMultisignatureCalldata(shortData);
      expect(result.success).to.be.false;
      expect(result.signingSigners).to.deep.equal([]);
      expect(result.signatures).to.deep.equal([]);
    });

    it('returns false for empty data', async function () {
      const result = await this.mock.$tryDecodeMultisignatureCalldata('0x');
      expect(result.success).to.be.false;
      expect(result.signingSigners).to.deep.equal([]);
      expect(result.signatures).to.deep.equal([]);
    });

    for (const [description, invalidData] of [
      [
        'first offset too small',
        ethers.concat([
          ethers.zeroPadValue('0x20', 32), // offset1 = 32 (too small, should be >= 64)
          ethers.zeroPadValue('0x40', 32), // offset2 = 64
          ethers.zeroPadValue('0x00', 32), // length of first array
          ethers.zeroPadValue('0x00', 32), // length of second array
        ]),
      ],
      [
        'second offset too small',
        ethers.concat([
          ethers.zeroPadValue('0x40', 32), // offset1 = 64
          ethers.zeroPadValue('0x20', 32), // offset2 = 32 (too small, should be >= 64)
          ethers.zeroPadValue('0x00', 32), // length of first array
          ethers.zeroPadValue('0x00', 32), // length of second array
        ]),
      ],
      [
        'first offset out of bounds',
        ethers.concat([
          ethers.zeroPadValue('0x1000', 32), // offset1 way beyond actual data
          ethers.zeroPadValue('0x40', 32), // offset2
          ethers.zeroPadValue('0x00', 32), // some data
        ]),
      ],
      [
        'second offset out of bounds',
        ethers.concat([
          ethers.zeroPadValue('0x40', 32), // offset1
          ethers.zeroPadValue('0x1000', 32), // offset2 way beyond actual data
          ethers.zeroPadValue('0x00', 32), // some data
        ]),
      ],
      [
        'truncated data at first array length',
        ethers.concat([
          ethers.zeroPadValue('0x40', 32), // offset1
          ethers.zeroPadValue('0x60', 32), // offset2
          ethers.zeroPadValue('0x01', 32), // length of first array
          // Missing second array length and data
        ]),
      ],
    ]) {
      it(`returns false for invalid data (${description})`, async function () {
        const result = await this.mock.$tryDecodeMultisignatureCalldata(invalidData);
        expect(result.success).to.be.false;
        expect(result.signingSigners.length).to.equal(0);
        expect(result.signatures.length).to.equal(0);
      });
    }
  });

  describe('decodeMultisignatureCalldata', function () {
    it('decodes valid multisignature successfully', async function () {
      const signers = [ethers.hexlify(ethers.randomBytes(20)), ethers.hexlify(ethers.randomBytes(20))];
      const signatures = [ethers.hexlify(ethers.randomBytes(65)), ethers.hexlify(ethers.randomBytes(65))];
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes[]'], [signers, signatures]);

      const result = await this.mock.$decodeMultisignatureCalldata(encoded);
      expect(result.signingSigners).to.deep.equal(signers);
      expect(result.signatures).to.deep.equal(signatures);
    });

    it('reverts for empty data', async function () {
      await expect(this.mock.$decodeMultisignatureCalldata('0x')).to.be.revertedWithCustomError(
        this.mock,
        'MultisigInvalidFormat',
      );
    });
  });
});
