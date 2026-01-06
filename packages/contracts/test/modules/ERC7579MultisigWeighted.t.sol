// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Multisig} from "../../src/modules/ERC7579Multisig.sol";
import {ERC7579MultisigWeighted} from "../../src/modules/ERC7579MultisigWeighted.sol";
import {CallReceiverMock} from "../../src/mocks/CallReceiverMock.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../src/OpenAccount.sol";
import {OpenAccountFactory} from "../../src/OpenAccountFactory.sol";

contract ERC7579MultisigWeightedMock is ERC7579MultisigWeighted {
    function isModuleType(uint256) public pure override returns (bool) {
        return true; // All types are valid for this mock
    }
}

contract ERC7579MultisigWeightedTest is Test {
    CallReceiverMock private _target;
    ERC7579MultisigWeightedMock private _multisig;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy weighted multisig
        _multisig = new ERC7579MultisigWeightedMock();

        // Deploy factory
        _factory = new OpenAccountFactory();
    }

    function testWeightedMultisigInstallation(uint64 numSigners) public {
        numSigners = uint64(bound(numSigners, 1, 10)); // Reasonable bounds

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        assertEq(_multisig.getSignerCount(address(_account)), numSigners);
        assertEq(_multisig.threshold(address(_account)), totalWeight);
        assertEq(_multisig.totalWeight(address(_account)), totalWeight);

        for (uint256 i = 0; i < numSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), signers[i]));
            assertEq(_multisig.signerWeight(address(_account), signers[i]), weights[i]);
        }
    }

    function testSetSignerWeights(uint64 numSigners, uint256 updateCount) public {
        numSigners = uint64(bound(numSigners, 1, 5));
        updateCount = uint64(bound(updateCount, 1, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory signersToUpdate) = _buildSigners(updateCount);
        (uint64[] memory newWeights, uint64 updatedNewTotalWeight) = _buildWeights(updateCount);
        uint64 updatedOldTotalWeight;
        for (uint256 i = 0; i < updateCount; i++) {
            updatedOldTotalWeight += _multisig.signerWeight(address(_account), signersToUpdate[i]);
        }
        uint64 expectedTotalWeight = totalWeight - updatedOldTotalWeight + updatedNewTotalWeight;

        vm.prank(address(_account));
        _multisig.setSignerWeights(signersToUpdate, newWeights);

        for (uint256 i = 0; i < updateCount; i++) {
            assertEq(_multisig.signerWeight(address(_account), signersToUpdate[i]), newWeights[i]);
        }

        assertEq(_multisig.totalWeight(address(_account)), expectedTotalWeight);
    }

    function testAddSigners(uint64 initialSigners, uint64 newSigners) public {
        initialSigners = uint64(bound(initialSigners, 1, 5));
        newSigners = uint64(bound(newSigners, 1, 5));

        (, bytes[] memory signers) = _buildSigners(initialSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(initialSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        uint64 initialTotalWeight = _multisig.totalWeight(address(_account));

        (, bytes[] memory additionalSigners) = _buildSigners(newSigners, initialSigners);

        vm.prank(address(_account));
        _multisig.addSigners(additionalSigners);

        assertEq(_multisig.getSignerCount(address(_account)), initialSigners + newSigners);
        assertEq(_multisig.totalWeight(address(_account)), initialTotalWeight + newSigners);

        for (uint256 i = 0; i < newSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), additionalSigners[i]));
            assertEq(_multisig.signerWeight(address(_account), additionalSigners[i]), 1);
        }
    }

    function testRemoveSigners(uint256 totalSigners, uint256 removeCount) public {
        totalSigners = bound(totalSigners, 2, 8);
        removeCount = bound(removeCount, 1, totalSigners - 1);

        (, bytes[] memory signers) = _buildSigners(totalSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(totalSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        uint64 removedWeight = 0;
        (, bytes[] memory signersToRemove) = _buildSigners(removeCount);
        for (uint256 i = 0; i < removeCount; i++) {
            removedWeight += _multisig.signerWeight(address(_account), signersToRemove[i]);
        }

        vm.prank(address(_account));
        _multisig.setThreshold(totalWeight - removedWeight);

        vm.prank(address(_account));
        _multisig.removeSigners(signersToRemove);

        assertEq(_multisig.getSignerCount(address(_account)), totalSigners - removeCount);
        assertEq(_multisig.totalWeight(address(_account)), totalWeight - removedWeight);

        for (uint256 i = 0; i < removeCount; i++) {
            assertFalse(_multisig.isSigner(address(_account), signersToRemove[i]));
            assertEq(_multisig.signerWeight(address(_account), signersToRemove[i]), 0);
        }
    }

    function testSetThreshold(uint256 numSigners, uint64 newThreshold) public {
        numSigners = bound(numSigners, 1, 10);
        newThreshold = uint64(bound(newThreshold, 1, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        assertEq(_multisig.threshold(address(_account)), totalWeight);

        vm.prank(address(_account));
        _multisig.setThreshold(newThreshold);

        assertEq(_multisig.threshold(address(_account)), newThreshold);
    }

    function testRevertUnreachableThreshold(uint256 numSigners, uint64 newThreshold) public {
        numSigners = bound(numSigners, 1, 10);

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);
        vm.assume(newThreshold > totalWeight);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Multisig.ERC7579MultisigUnreachableThreshold.selector,
                totalWeight,
                newThreshold
            )
        );
        _multisig.setThreshold(newThreshold);
    }

    function testRevertZeroThreshold() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        vm.expectRevert(ERC7579Multisig.ERC7579MultisigZeroThreshold.selector);
        _multisig.setThreshold(0);
    }

    function testRevertInvalidSigner(bytes memory invalidSigner) public {
        vm.assume(invalidSigner.length < 20);

        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        signers[0] = invalidSigner;

        vm.expectRevert(abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigInvalidSigner.selector, invalidSigner));
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
    }

    function testRevertAlreadyExistsSigner() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigAlreadyExists.selector, signers[0]));
        _multisig.addSigners(signers);
    }

    function testRevertNonexistentSigner() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory nonexistentSigners) = _buildSigners(1, 999);

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigNonexistentSigner.selector, nonexistentSigners[0])
        );
        _multisig.removeSigners(nonexistentSigners);
    }

    function testRevertInvalidWeight() public {
        // Setup one signer
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        weights[0] = 0;

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579MultisigWeighted.ERC7579MultisigInvalidWeight.selector, signers[0], uint64(0))
        );
        _multisig.setSignerWeights(signers, weights);
    }

    function testRevertMismatchedLength(uint256 signersLength, uint256 weightsLength) public {
        signersLength = bound(signersLength, 1, 5);
        weightsLength = bound(weightsLength, 1, 5);
        vm.assume(signersLength != weightsLength);

        (, bytes[] memory signers) = _buildSigners(1);
        uint64[] memory weights;
        uint64 totalWeight;
        (weights, totalWeight) = _buildWeights(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, totalWeight, weights);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory signersToUpdate) = _buildSigners(signersLength);
        weights = new uint64[](weightsLength);
        for (uint256 i = 0; i < weightsLength; i++) {
            weights[i] = 1;
        }

        vm.prank(address(_account));
        vm.expectRevert(ERC7579MultisigWeighted.ERC7579MultisigMismatchedLength.selector);
        _multisig.setSignerWeights(signersToUpdate, weights);
    }

    function _buildSigners(uint256 numSigners) private pure returns (uint256[] memory, bytes[] memory) {
        return _buildSigners(numSigners, 0);
    }

    function _buildSigners(
        uint256 numSigners,
        uint256 start
    ) private pure returns (uint256[] memory keys, bytes[] memory signers) {
        keys = new uint256[](numSigners);
        signers = new bytes[](numSigners);
        for (uint256 i = 0; i < numSigners; i++) {
            keys[i] = i + start + 1;
            signers[i] = abi.encodePacked(vm.addr(keys[i]));
        }
        return (keys, signers);
    }

    function _buildWeights(uint256 numSigners) private pure returns (uint64[] memory weights, uint64 totalWeight) {
        weights = new uint64[](numSigners);
        for (uint256 i = 0; i < numSigners; i++) {
            weights[i] = uint64(bound(uint256(keccak256(abi.encode(i))), 1, 10));
            totalWeight += weights[i];
        }
        return (weights, totalWeight);
    }

    function _buildInstallationModules(
        bytes[] memory signers,
        uint64 threshold,
        uint64[] memory weights
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_multisig);
        initDatas[0] = abi.encode(signers, threshold, weights);
        return (moduleTypeIds, modules, initDatas);
    }
}
