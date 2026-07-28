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

    const word = v => ethers.zeroPadValue(ethers.toBeHex(v), 0x20);
    const encode = (...items) => ethers.concat(items.map(word));
    const MAX_UINT64 = 2n ** 64n - 1n;

    it('supports minimal encoding', async function () {
      // Two offsets = 0 → both lengths read from position 0 = 0 → decode succeeds with empty arrays.
      // Two offsets = 0x20 / 0 → decodes successfully but head-bounds trip on the swapped length; here we
      // just assert the outer decoder handles the 64-byte minimum shape without reverting.
      let result = await this.mock.$tryDecodeMultisignatureCalldata(encode(0, 0));
      expect(result.success).to.be.true;
      expect(result.signingSigners).to.deep.equal([]);
      expect(result.signatures).to.deep.equal([]);

      result = await this.mock.$tryDecodeMultisignatureCalldata(encode(0x20, 0));
      expect(result.success).to.be.false;
    });

    for (const [description, invalidData] of [
      ['first offset too small', encode(0x20, 0x40, 0, 0)],
      ['second offset too small', encode(0x40, 0x20, 0, 0)],
      ['first offset out of bounds', encode(0x1000, 0x40, 0)],
      ['second offset out of bounds', encode(0x40, 0x1000, 0)],
      [
        'truncated data at first array length',
        encode(0x40, 0x60, 1), // length = 1 but missing element offset word
      ],
      // Attacker-crafted values that must not overflow checked arithmetic.
      ['offset near type(uint256).max (would overflow signersOffset + 0x20)', encode(ethers.MaxUint256, ethers.MaxUint256, 0, 0)],
      ['array length above type(uint64).max (would overflow length * 0x20)', encode(0x40, 0x60, MAX_UINT64 + 1n, MAX_UINT64 + 1n)],
      ['array length exceeds remaining buffer (correct head bound uses signersDataOffset)', encode(0x40, 0x60, 10, 0)],
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
