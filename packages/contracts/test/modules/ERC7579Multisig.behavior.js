const { ethers } = require('hardhat');
const { expect } = require('chai');
const { MAX_UINT64 } = require('../../../../lib/@openzeppelin-contracts/test/helpers/constants');

function shouldBehaveLikeERC7579Multisig() {
  describe('behaves like ERC7579Multisig', function () {
    it('sets initial signers and threshold on installation', async function () {
      const tx = await this.mockAccountFromEntrypoint.installModule(
        this.moduleType,
        this.mock.target,
        this.installData,
      );

      for (const signer of this.signers) {
        await expect(tx)
          .to.emit(this.mock, 'ERC7913SignerAdded')
          .withArgs(this.mockAccount.address, signer.toLowerCase());
      }

      await expect(tx).to.emit(this.mock, 'ERC7913ThresholdSet').withArgs(this.mockAccount.address, this.threshold);

      // Verify signers and threshold
      await expect(this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal(
        this.signers,
      );
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(this.threshold);

      // onInstall is allowed again but is a noop
      await this.mockFromAccount.onInstall(
        ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'uint256'], [[this.nonSigner], 2]),
      );

      // Should still have the original signers and threshold
      await expect(this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal(
        this.signers,
      );
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(this.threshold);
    });

    it('cleans up signers and threshold on uninstallation', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Verify signers and threshold are cleared
      await expect(this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal([]);
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(0);
    });

    describe('signer management', function () {
      beforeEach(async function () {
        await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      });

      it('reverts adding an invalid signer', async function () {
        await expect(this.mockFromAccount.addSigners(['0x1234']))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigInvalidSigner')
          .withArgs('0x1234');
      });

      it('can add signers', async function () {
        const newSigners = [this.nonSigner];

        // Get signers before adding
        const signersBefore = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Add new signers
        const tx = await this.mockFromAccount.addSigners(newSigners);
        for (const signer of newSigners) {
          await expect(tx)
            .to.emit(this.mock, 'ERC7913SignerAdded')
            .withArgs(this.mockAccount.address, signer.toLowerCase());
        }

        // Get signers after adding
        const signersAfter = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Check that new signers were added
        expect(signersAfter.length).to.equal(signersBefore.length + 1);
        expect(signersAfter.map(ethers.getAddress)).to.include(ethers.getAddress(this.nonSigner));

        // Verify isSigner function
        await expect(this.mock.isSigner(this.mockAccount.address, this.nonSigner)).to.eventually.be.true;

        // Reverts if the signer already exists
        await expect(this.mockFromAccount.addSigners(newSigners))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigAlreadyExists')
          .withArgs(this.nonSigner.toLowerCase());
      });

      it('can remove signers', async function () {
        const removedSigners = [this.signers[0]].map(address => address.toLowerCase());

        // Get signers before removing
        const signersBefore = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Remove signers
        const tx = await this.mockFromAccount.removeSigners(removedSigners);
        for (const signer of removedSigners) {
          await expect(tx)
            .to.emit(this.mock, 'ERC7913SignerRemoved')
            .withArgs(this.mockAccount.address, signer.toLowerCase());
        }

        // Get signers after removing
        const signersAfter = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Check that signers were removed
        expect(signersAfter.length).to.equal(signersBefore.length - 1);
        expect(signersAfter).to.not.include(this.signers[0]);

        // Verify isSigner function
        await expect(this.mock.isSigner(this.mockAccount.address, this.signers[0])).to.eventually.be.false;

        // Reverts if the signer doesn't exist
        await expect(this.mockFromAccount.removeSigners(removedSigners))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner')
          .withArgs(this.signers[0].toLowerCase());

        // Reverts if threshold becomes unreachable after removal
        await this.mockFromAccount.setThreshold(1);
        await expect(this.mockFromAccount.removeSigners([this.signers[1]]))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnreachableThreshold')
          .withArgs(0, 1);
      });

      it('can set threshold', async function () {
        // Set threshold to 2
        await expect(this.mockFromAccount.setThreshold(2))
          .to.emit(this.mock, 'ERC7913ThresholdSet')
          .withArgs(this.mockAccount.address, 2);

        // Verify threshold
        await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(2);

        // Reverts if threshold is unreachable
        await expect(this.mockFromAccount.setThreshold(3))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnreachableThreshold')
          .withArgs(2, 3);
      });
    });
  });
}

function shouldBehaveLikeERC7579MultisigWeighted() {
  describe('behaves like ERC7579MultisigWeighted', function () {
    it('sets initial signers, weights, and threshold on installation', async function () {
      const tx = await this.mockAccountFromEntrypoint.installModule(
        this.moduleType,
        this.mock.target,
        this.installData,
      );

      for (const signer of this.signers) {
        await expect(tx)
          .to.emit(this.mock, 'ERC7913SignerAdded')
          .withArgs(this.mockAccount.address, signer.toLowerCase());
      }
      await expect(tx).to.emit(this.mock, 'ERC7913ThresholdSet').withArgs(this.mockAccount.address, this.threshold);

      // Verify signers and weights were set correctly
      for (let i = 0; i < this.signers.length; i++) {
        await expect(this.mock.signerWeight(this.mockAccount.address, this.signers[i])).to.eventually.equal(
          this.weights[i],
        );
      }

      // Verify threshold was set correctly
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(this.threshold);

      // onInstall is allowed again but is a noop
      const newSigners = [this.nonSigner];
      const newWeights = [5];
      const newThreshold = 10;

      await this.mockFromAccount.onInstall(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes[]', 'uint256', 'uint256[]'],
          [newSigners, newThreshold, newWeights],
        ),
      );

      // Should still have the original signers, weights, and threshold
      await expect(this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal(
        this.signers,
      );

      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(this.threshold);
    });

    it('cleans up signers, weights, and threshold on uninstallation', async function () {
      await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      await this.mockAccountFromEntrypoint.uninstallModule(this.moduleType, this.mock.target, '0x');

      // Verify signers and threshold are cleared
      await expect(this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64)).to.eventually.deep.equal([]);
      await expect(this.mock.threshold(this.mockAccount.address)).to.eventually.equal(0);

      // Verify weights are cleared (by checking a previously existing signer)
      await expect(this.mock.signerWeight(this.mockAccount.address, this.signers[0])).to.eventually.equal(0);
    });

    describe('signer and weight management', function () {
      beforeEach(async function () {
        await this.mockAccountFromEntrypoint.installModule(this.moduleType, this.mock.target, this.installData);
      });

      it('can add signers with default weight', async function () {
        const newSigners = [this.nonSigner];

        // Get signers before adding
        const signersBefore = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Add new signer
        const tx = await this.mockFromAccount.addSigners(newSigners);
        for (const signer of newSigners) {
          await expect(tx)
            .to.emit(this.mock, 'ERC7913SignerAdded')
            .withArgs(this.mockAccount.address, signer.toLowerCase());
        }

        // Get signers after adding
        const signersAfter = await this.mock.getSigners(this.mockAccount.address, 0, MAX_UINT64);

        // Check that new signer was added
        expect(signersAfter.length).to.equal(signersBefore.length + 1);
        expect(signersAfter.map(ethers.getAddress)).to.include(ethers.getAddress(this.nonSigner));

        // Check that default weight is 1
        await expect(this.mock.signerWeight(this.mockAccount.address, this.nonSigner)).to.eventually.equal(1);

        // Check that total weight was updated
        const totalWeight = await this.mock.totalWeight(this.mockAccount.address);
        expect(totalWeight).to.equal(1 + 2 + 3 + 1); // Sum of all weights including new signer
      });

      it('can set signer weights', async function () {
        // Set new weights for existing signers
        const updateSigners = [this.signers[0], this.signers[1]];
        const newWeights = [5, 5];

        await expect(this.mockFromAccount.setSignerWeights(updateSigners, newWeights))
          .to.emit(this.mock, 'ERC7579MultisigWeightChanged')
          .withArgs(this.mockAccount.address, updateSigners[0].toLowerCase(), newWeights[0])
          .to.emit(this.mock, 'ERC7579MultisigWeightChanged')
          .withArgs(this.mockAccount.address, updateSigners[1].toLowerCase(), newWeights[1]);

        // Verify new weights
        await expect(this.mock.signerWeight(this.mockAccount.address, updateSigners[0])).to.eventually.equal(
          newWeights[0],
        );
        await expect(this.mock.signerWeight(this.mockAccount.address, updateSigners[1])).to.eventually.equal(
          newWeights[1],
        );

        // Third signer weight should remain unchanged
        await expect(this.mock.signerWeight(this.mockAccount.address, this.signers[2])).to.eventually.equal(
          this.weights[2],
        );

        // Check total weight
        await expect(this.mock.totalWeight(this.mockAccount.address)).to.eventually.equal(5 + 5 + 3); // Sum of all weights after update
      });

      it('cannot set weight to non-existent signer', async function () {
        const randomSigner = ethers.Wallet.createRandom().address;

        // Reverts when setting weight for non-existent signer
        await expect(this.mockFromAccount.setSignerWeights([randomSigner], [1]))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner')
          .withArgs(randomSigner.toLowerCase());
      });

      it('cannot set weight to 0', async function () {
        // Reverts when setting weight to 0
        await expect(this.mockFromAccount.setSignerWeights([this.signers[0]], [0]))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigInvalidWeight')
          .withArgs(this.signers[0].toLowerCase(), 0);
      });

      it('requires signers and weights arrays to have same length', async function () {
        // Reverts when arrays have different lengths
        await expect(
          this.mockFromAccount.setSignerWeights([this.signers[0], this.signers[1]], [1]),
        ).to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigMismatchedLength');
      });

      it('can remove signers and updates total weight', async function () {
        const removedSigner = this.signers[0].toLowerCase(); // weight = 1
        const weightBefore = await this.mock.totalWeight(this.mockAccount.address);

        // Remove signer
        await expect(this.mockFromAccount.removeSigners([removedSigner]))
          .to.emit(this.mock, 'ERC7913SignerRemoved')
          .withArgs(this.mockAccount.address, removedSigner);

        // Check weight was updated
        const weightAfter = await this.mock.totalWeight(this.mockAccount.address);
        expect(weightAfter).to.equal(weightBefore - 1n); // Should be decreased by removed signer's weight

        // Cannot remove non-existent signer
        await expect(this.mockFromAccount.removeSigners([removedSigner]))
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigNonexistentSigner')
          .withArgs(removedSigner);
      });

      it('validates threshold is reachable when updating weights', async function () {
        // Increase threshold to match total weight
        const totalWeight = await this.mock.totalWeight(this.mockAccount.address);

        // Ensure totalWeight is what we expect (should be 6)
        expect(totalWeight).to.equal(6); // 1+2+3 after weights are properly set

        // Set threshold to total weight
        await this.mockFromAccount.setThreshold(totalWeight);

        // Now try to lower a weight, making total weight less than threshold
        await expect(this.mockFromAccount.setSignerWeights([this.signers[2]], [1])) // Change weight from 3 to 1
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnreachableThreshold')
          .withArgs(totalWeight - 2n, totalWeight); // Total weight would be 2 less than threshold
      });

      it('prevents removing signers if threshold becomes unreachable', async function () {
        // First check initial total weight
        const initialTotalWeight = await this.mock.totalWeight(this.mockAccount.address);
        expect(initialTotalWeight).to.equal(6); // 1+2+3

        // Set threshold to current total weight
        await this.mockFromAccount.setThreshold(initialTotalWeight);

        // Cannot remove a signer with weight > 0 as threshold would become unreachable
        await expect(this.mockFromAccount.removeSigners([this.signers[0]])) // Weight 1
          .to.be.revertedWithCustomError(this.mock, 'ERC7579MultisigUnreachableThreshold')
          .withArgs(initialTotalWeight - 1n, initialTotalWeight);
      });
    });
  });
}

module.exports = {
  shouldBehaveLikeERC7579Multisig,
  shouldBehaveLikeERC7579MultisigWeighted,
};
