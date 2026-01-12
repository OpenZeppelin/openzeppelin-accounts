const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { encodeERC7964Header } = require('../../helpers/eip7964');
const { getDomain } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { SetValue, EIP712ChainDomain, ChainOperation } = require('../../helpers/eip712-types');

const types = {
  SetValue,
  EIP712ChainDomain,
  ChainOperation,
};

async function fixture() {
  const [signer, other] = await ethers.getSigners();

  // Deploy multiple CrossChainAppMock instances (simulating different chains)
  const apps = await Promise.all(
    Array.from({ length: 3 }, () => ethers.deployContract('CrossChainAppMock', ['CrossChainAppMock', '1.0.0'])),
  );

  return { signer, other, apps };
}

describe('CrossChainSignatureChecker', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  for (const fn of ['setValue', 'setValueCalldata']) {
    describe(fn, function () {
      it('should set value with valid cross-chain signature', async function () {
        const fields = '0x03';
        const value = 42n;

        const chainId = await ethers.provider.getNetwork().then(n => n.chainId);
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = this.apps.map(app => ({
          domain: {
            chainId: chainId,
            verifyingContract: app.target,
          },
          value,
        }));

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });

        for (let i = 0; i < this.apps.length; i++) {
          const header = encodeERC7964Header(fields, i, this.apps[i].target);
          const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32[]', 'bytes'],
            [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
          );

          await expect(this.apps[i][fn](this.signer.address, value, erc7964Signature))
            .to.emit(this.apps[i], 'ValueSet')
            .withArgs(this.signer.address, value);
          await expect(this.apps[i].value(this.signer.address)).to.eventually.equal(value);
        }
      });

      it('should revert with incorrect struct index', async function () {
        const fields = '0x03';
        const value = 42n;

        const chainId = await ethers.provider.getNetwork().then(n => n.chainId);
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = this.apps.map(app => ({
          domain: {
            chainId: chainId,
            verifyingContract: app.target,
          },
          value,
        }));

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });
        const header = encodeERC7964Header(fields, 1, this.apps[0].target); // Use wrong struct index (should be 0, but use 1)
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
        );

        await expect(this.apps[0][fn](this.signer.address, value, erc7964Signature)).to.be.revertedWith(
          'Invalid signature',
        );
      });

      it('should revert with invalid signature', async function () {
        const fields = '0x03';
        const value = 42n;

        const chainId = await ethers.provider.getNetwork().then(n => n.chainId);
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = this.apps.map(app => ({
          domain: {
            chainId: chainId,
            verifyingContract: app.target,
          },
          value,
        }));

        // Use other signer to generate invalid signature
        const invalidSignature = await this.other.signTypedData(crossChainDomain, types, {
          operations,
        });
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [
            encodeERC7964Header(fields, 0, this.apps[0].target),
            operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)),
            invalidSignature,
          ],
        );

        await expect(this.apps[0][fn](this.signer.address, value, erc7964Signature)).to.be.revertedWith(
          'Invalid signature',
        );
      });

      it('should revert with wrong value', async function () {
        const fields = '0x03';
        const value = 42n;
        const wrongValue = 100n;

        const chainId = await ethers.provider.getNetwork().then(n => n.chainId);
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = this.apps.map(app => ({
          domain: {
            chainId: chainId,
            verifyingContract: app.target,
          },
          value,
        }));

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });
        const header = encodeERC7964Header(fields, 0, this.apps[0].target);
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
        );

        await expect(this.apps[0][fn](this.signer.address, wrongValue, erc7964Signature)).to.be.revertedWith(
          'Invalid signature',
        );
      });

      it('should revert with invalid magic prefix', async function () {
        const fields = '0x03';
        const value = 42n;
        const chainId = await ethers.provider.getNetwork().then(n => n.chainId);
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = this.apps.map(app => ({
          domain: {
            chainId: chainId,
            verifyingContract: app.target,
          },
          value,
        }));

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });
        const header = ethers.concat([
          ethers.hexlify(ethers.randomBytes(9)), // Use wrong magic prefix
          ethers.getBytes(fields),
          ethers.zeroPadValue(ethers.toBeHex(0), 2),
          ethers.getBytes(this.apps[0].target),
        ]);
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
        );

        await expect(this.apps[0][fn](this.signer.address, value, erc7964Signature)).to.be.revertedWith(
          'Invalid signature',
        );
      });
    });
  }
});
