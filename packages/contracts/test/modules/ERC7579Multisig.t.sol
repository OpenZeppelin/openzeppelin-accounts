// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC7579Multisig} from "../../src/modules/ERC7579Multisig.sol";
import {CallReceiverMock} from "../../src/mocks/CallReceiverMock.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../src/OpenAccount.sol";
import {OpenAccountFactory} from "../../src/OpenAccountFactory.sol";

contract ERC7579MultisigMock is ERC7579Multisig {
    function isModuleType(uint256) public pure override returns (bool) {
        return true; // All types are valid for this mock
    }

    /// @dev Exposes internal `_validateMultisig` for testing
    function validateMultisig(
        address account,
        bytes32 hash,
        bytes[] calldata signingSigners,
        bytes[] calldata signatures
    ) external view returns (bool) {
        return _validateMultisig(account, hash, signingSigners, signatures);
    }
}

contract ERC7579MultisigTest is Test {
    CallReceiverMock private _target;
    ERC7579MultisigMock private _multisig;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy multisig
        _multisig = new ERC7579MultisigMock();

        // Deploy factory
        _factory = new OpenAccountFactory();
    }

    function testMultisigInstallation(uint256 numSigners, uint64 threshold) public {
        numSigners = bound(numSigners, 1, 10); // Reasonable bounds
        threshold = uint64(bound(threshold, 1, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, threshold);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        assertEq(_multisig.getSignerCount(address(_account)), numSigners);
        assertEq(_multisig.threshold(address(_account)), threshold);

        for (uint256 i = 0; i < numSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), signers[i]));
        }
    }

    function testGetSignersSlice(uint256 numSigners, uint64 start, uint64 end) public {
        numSigners = bound(numSigners, 1, 10);
        start = uint64(bound(start, 0, numSigners));
        end = uint64(bound(end, start, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        bytes[] memory slice = _multisig.getSigners(address(_account), start, end);

        assertEq(slice.length, end - start);

        for (uint256 i = 0; i < slice.length; i++) {
            assertEq(slice[i], signers[start + i]);
        }
    }

    function testAddSigners(uint256 initialSigners, uint256 newSigners) public {
        initialSigners = bound(initialSigners, 1, 5);
        newSigners = bound(newSigners, 1, 5);

        (, bytes[] memory signers) = _buildSigners(initialSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory additionalSigners) = _buildSigners(newSigners, initialSigners);

        vm.prank(address(_account));
        _multisig.addSigners(additionalSigners);

        assertEq(_multisig.getSignerCount(address(_account)), initialSigners + newSigners);

        for (uint256 i = 0; i < newSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), additionalSigners[i]));
        }
    }

    function testRemoveSigners(uint256 totalSigners, uint256 removeCount, uint64 threshold) public {
        totalSigners = bound(totalSigners, 2, 10);
        removeCount = bound(removeCount, 1, totalSigners - 1);
        uint256 remainingSigners = totalSigners - removeCount;
        threshold = uint64(bound(threshold, 1, remainingSigners));

        (, bytes[] memory signers) = _buildSigners(totalSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, threshold);
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory signersToRemove) = _buildSigners(removeCount);

        vm.prank(address(_account));
        _multisig.removeSigners(signersToRemove);

        assertEq(_multisig.getSignerCount(address(_account)), remainingSigners);

        for (uint256 i = 0; i < removeCount; i++) {
            assertFalse(_multisig.isSigner(address(_account), signersToRemove[i]));
        }

        for (uint256 i = removeCount; i < totalSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), signers[i]));
        }
    }

    function testSetThreshold(uint256 numSigners, uint64 newThreshold) public {
        numSigners = bound(numSigners, 1, 10);
        newThreshold = uint64(bound(newThreshold, 1, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        _multisig.setThreshold(newThreshold);

        assertEq(_multisig.threshold(address(_account)), newThreshold);
    }

    function testRevertUnreachableThreshold(uint64 numSigners, uint64 threshold) public {
        numSigners = uint64(bound(numSigners, 1, 10));
        vm.assume(threshold > numSigners);

        (, bytes[] memory signers) = _buildSigners(numSigners);

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigUnreachableThreshold.selector, numSigners, threshold)
        );
        _multisig.setThreshold(threshold);
    }

    function testRevertZeroThreshold() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
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
        signers[0] = invalidSigner;

        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));

        vm.expectRevert(abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigInvalidSigner.selector, invalidSigner));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );
    }

    function testRevertAlreadyExistsSigner() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
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
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(signers, uint64(1));
        _account = OpenAccount(
            payable(
                _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
            )
        );

        (, bytes[] memory nonExistentSigners) = _buildSigners(1, 999);

        vm.prank(address(_account));
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigNonexistentSigner.selector, nonExistentSigners[0])
        );
        _multisig.removeSigners(nonExistentSigners);
    }

    function _buildSigners(uint256 numSigners) private pure returns (uint256[] memory keys, bytes[] memory signers) {
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

    function _buildInstallationModules(
        bytes[] memory signers,
        uint64 threshold
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_VALIDATOR;
        modules[0] = address(_multisig);
        initDatas[0] = abi.encode(signers, threshold);
    }
}
