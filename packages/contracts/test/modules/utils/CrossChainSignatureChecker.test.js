const { ethers, config } = require('hardhat');
const { expect } = require('chai');
const { spawn } = require('child_process');
const { encodeERC7964Header } = require('../../helpers/eip7964');
const { getDomain } = require('../../../../../lib/@openzeppelin-contracts/test/helpers/eip712');
const { SetValue, EIP712ChainDomain, ChainOperation } = require('../../helpers/eip712-types');

const types = {
  SetValue,
  EIP712ChainDomain,
  ChainOperation,
};

describe('CrossChainSignatureChecker', function () {
  before('start anvil nodes', async function () {
    [this.signer, this.other] = await ethers.getSigners();
    const instances = [
      { port: 8546, chainId: 31337 },
      { port: 8547, chainId: 31338 },
      { port: 8548, chainId: 31339 },
      { port: 8549, chainId: 31340 },
      { port: 8550, chainId: 31341 },
    ];

    // start processes and create providers
    this.processes = await Promise.all(
      instances.map(({ port, chainId }) => spawn('anvil', ['--port', port, '--chain-id', chainId], { timeout: 30000 })),
    );
    await Promise.all(this.processes.map(process => new Promise(resolve => process.stdout.once('data', resolve))));
    this.providers = await Promise.all(
      instances.map(({ port, chainId }) =>
        ethers.Wallet.fromPhrase(
          config.networks.hardhat.accounts.mnemonic,
          new ethers.JsonRpcProvider(`http://localhost:${port}`, chainId),
        ),
      ),
    );

    this.apps = await Promise.all(
      this.providers.map(provider =>
        ethers.deployContract('CrossChainAppMock', ['CrossChainAppMock', '1.0.0'], provider),
      ),
    );
  });

  after('stop anvil nodes', async function () {
    await Promise.all(this.processes.map(process => process.kill()));
  });

  for (const fn of ['setValue']) {
    describe(fn, function () {
      it('should set value with valid cross-chain signature', async function () {
        const fields = '0x03';
        const value = 42n;

        const operations = await Promise.all(
          this.providers.map(async ({ provider }, i) => ({
            domain: {
              chainId: await provider.getNetwork().then(n => n.chainId),
              verifyingContract: this.apps[i].target,
            },
            value,
          })),
        );

        for (let i = 0; i < this.providers.length; i++) {
          const header = encodeERC7964Header(fields, i, this.apps[i].target);
          const domain = await getDomain(this.apps[i]);
          const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));
          const signature = await this.signer.signTypedData(crossChainDomain, types, {
            operations,
          });
          const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32[]', 'bytes'],
            [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
          );
          await expect(
            this.apps[i][fn](this.signer.address, value, erc7964Signature, {
              nonce: await this.providers[i].provider.getTransactionCount(this.apps[i].runner.address),
            }),
          )
            .to.emit(this.apps[i], 'ValueSet')
            .withArgs(this.signer.address, value);
          await expect(this.apps[i].value(this.signer.address)).to.eventually.equal(value);
        }
      });

      it('should revert with incorrect struct index', async function () {
        const fields = '0x03';
        const value = 42n;

        const domain = await getDomain(this.apps[0]);
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = await Promise.all(
          this.providers.map(async ({ provider }, i) => ({
            domain: {
              chainId: await provider.getNetwork().then(n => n.chainId),
              verifyingContract: this.apps[i].target,
            },
            value,
          })),
        );

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });
        const header = encodeERC7964Header(fields, 1, this.apps[0].target); // Use wrong struct index (should be 0, but use 1)
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
        );

        await expect(
          this.apps[0][fn](this.signer.address, value, erc7964Signature, {
            nonce: await this.providers[0].provider.getTransactionCount(this.apps[0].runner.address),
          }),
        ).to.be.revertedWith('Invalid signature');
      });

      it('should revert with invalid signature', async function () {
        const fields = '0x03';
        const value = 42n;

        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = await Promise.all(
          this.providers.map(async ({ provider }, i) => ({
            domain: {
              chainId: await provider.getNetwork().then(n => n.chainId),
              verifyingContract: this.apps[i].target,
            },
            value,
          })),
        );

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

        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = await Promise.all(
          this.providers.map(async ({ provider }, i) => ({
            domain: {
              chainId: await provider.getNetwork().then(n => n.chainId),
              verifyingContract: this.apps[i].target,
            },
            value,
          })),
        );

        const signature = await this.signer.signTypedData(crossChainDomain, types, {
          operations,
        });
        const header = encodeERC7964Header(fields, 0, this.apps[0].target);
        const erc7964Signature = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes32', 'bytes32[]', 'bytes'],
          [header, operations.map(op => ethers.TypedDataEncoder.hashStruct('ChainOperation', types, op)), signature],
        );

        await expect(
          this.apps[0][fn](this.signer.address, wrongValue, erc7964Signature, {
            nonce: await this.providers[0].provider.getTransactionCount(this.apps[0].runner.address),
          }),
        ).to.be.revertedWith('Invalid signature');
      });

      it('should revert with invalid magic prefix', async function () {
        const fields = '0x03';
        const value = 42n;
        const domain = await getDomain(this.apps[0]); // All apps share the same name and version
        const crossChainDomain = Object.fromEntries(Object.entries(domain).filter((_, i) => fields & (1 << i)));

        const operations = await Promise.all(
          this.providers.map(async ({ provider }, i) => ({
            domain: {
              chainId: await provider.getNetwork().then(n => n.chainId),
              verifyingContract: this.apps[i].target,
            },
            value,
          })),
        );

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
