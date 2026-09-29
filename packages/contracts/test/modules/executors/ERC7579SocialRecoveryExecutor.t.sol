// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579SocialRecoveryExecutor} from "../../../src/modules/executors/ERC7579SocialRecoveryExecutor.sol";
import {CallReceiverMock} from "../../../src/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {OpenAccount} from "../../../src/OpenAccount.sol";
import {OpenAccountFactory} from "../../../src/OpenAccountFactory.sol";
import {ERC7579DelayedExecutor} from "../../../src/modules/executors/ERC7579DelayedExecutor.sol";
import {ERC7579Multisig} from "../../../src/modules/ERC7579Multisig.sol";

contract ERC7579SocialRecoveryExecutorTest is Test {
    using ERC7579Utils for *;
    using MessageHashUtils for *;

    CallReceiverMock private _target;
    ERC7579SocialRecoveryExecutor private _executor;
    ERC7579SocialRecoveryExecutor private _otherExecutor;
    OpenAccount private _account;
    OpenAccountFactory private _factory;

    bytes32 private constant SCHEDULE_RECOVER_TYPEHASH =
        keccak256("ScheduleRecover(address executor,bytes32 salt,bytes32 mode,bytes recoveryCalldata)");
    bytes32 private constant CANCEL_RECOVER_TYPEHASH =
        keccak256("CancelRecover(address executor,bytes32 salt,bytes32 mode,bytes recoveryCalldata)");

    function setUp() public {
        _target = new CallReceiverMock();
        _executor = new ERC7579SocialRecoveryExecutor();
        _factory = new OpenAccountFactory();
    }

    function testInstallation(uint32 delay, uint32 expiration, uint64 threshold, uint256 guardiansAmount) public {
        (, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(bound(guardiansAmount, 1, 10));
        uint64 totalWeight = _calculateTotalWeight(weights);
        threshold = uint64(bound(threshold, 1, totalWeight));

        _account = _createAndInstall(delay, expiration, threshold, guardians, weights);

        assertTrue(_executor.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(_executor.isModuleType(999)); // Random invalid type

        (uint32 actualDelay, uint32 pendingDelay, uint48 effectTime) = _executor.getDelay(address(_account));
        assertEq(actualDelay, delay);
        assertEq(pendingDelay, 0);
        assertEq(effectTime, 0);

        assertEq(_executor.getExpiration(address(_account)), expiration);

        assertEq(_executor.getGuardianCount(address(_account)), guardians.length);
        assertEq(_executor.threshold(address(_account)), threshold);

        for (uint256 i = 0; i < guardians.length; i++) {
            assertTrue(_executor.isGuardian(address(_account), guardians[i]));
            assertEq(_executor.signerWeight(address(_account), guardians[i]), weights[i]);
        }
    }

    function testUninstallation(uint32 delay, uint32 expiration, uint64 threshold, uint256 guardiansAmount) public {
        (, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(bound(guardiansAmount, 1, 10));
        threshold = uint64(bound(threshold, 1, _calculateTotalWeight(weights)));
        _account = _createAndInstall(delay, expiration, threshold, guardians, weights);

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorDelayUpdated(
            address(_account),
            0,
            uint48(block.timestamp) + uint48(delay)
        );

        vm.expectEmit(true, true, true, true);
        emit ERC7579DelayedExecutor.ERC7579ExecutorExpirationUpdated(address(_account), 0);

        vm.prank(address(_account));
        _executor.onUninstall("");

        assertEq(_executor.getExpiration(address(_account)), 0);
        assertEq(_executor.getGuardianCount(address(_account)), 0);
        assertEq(_executor.threshold(address(_account)), 0);
    }

    function testAddGuardians(
        uint32 delay,
        uint32 expiration,
        uint64 threshold,
        uint256 guardiansAmount,
        uint256 newGuardiansAmount
    ) public {
        guardiansAmount = bound(guardiansAmount, 1, 10);
        newGuardiansAmount = bound(newGuardiansAmount, 1, 10);
        (, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(guardiansAmount);
        threshold = uint64(bound(threshold, 1, _calculateTotalWeight(weights)));
        _account = _createAndInstall(delay, expiration, threshold, guardians, weights);

        (, bytes[] memory newGuardians, ) = _buildGuardians(newGuardiansAmount, guardiansAmount);

        uint256 countBefore = _executor.getGuardianCount(address(_account));

        for (uint256 i = 0; i < newGuardiansAmount; i++) {
            vm.expectEmit(true, true, true, true);
            emit ERC7579Multisig.ERC7913SignerAdded(address(_account), newGuardians[i]);
        }

        vm.startPrank(address(_account));
        _executor.addGuardians(newGuardians);

        assertEq(_executor.getGuardianCount(address(_account)), countBefore + newGuardiansAmount);
        for (uint256 i = 0; i < newGuardiansAmount; i++) {
            assertTrue(_executor.isGuardian(address(_account), newGuardians[i]));
        }

        // Reverts if the guardian already exists
        vm.expectRevert(abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigAlreadyExists.selector, newGuardians[0]));
        _executor.addGuardians(newGuardians);
        vm.stopPrank();
    }

    function testRemoveGuardians(
        uint32 delay,
        uint32 expiration,
        uint64 threshold,
        uint256 guardiansAmount,
        uint256 guardiansToRemoveAmount
    ) public {
        guardiansAmount = bound(guardiansAmount, 2, 10);
        guardiansToRemoveAmount = bound(guardiansToRemoveAmount, 1, guardiansAmount - 1);
        (, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(guardiansAmount);
        uint64 totalWeight = _calculateTotalWeight(weights);
        threshold = uint64(bound(threshold, 1, totalWeight));
        _account = _createAndInstall(delay, expiration, threshold, guardians, weights);

        (, bytes[] memory guardiansToRemove, uint64[] memory weightsToRemove) = _buildGuardians(
            guardiansToRemoveAmount
        );

        // Adjust threshold to account for removal
        uint64 weightRemoved = _calculateTotalWeight(weightsToRemove);
        vm.startPrank(address(_account));
        if (_executor.threshold(address(_account)) > totalWeight - weightRemoved) {
            _executor.setThreshold(totalWeight - weightRemoved);
        }

        uint256 countBefore = _executor.getGuardianCount(address(_account));

        for (uint256 i = 0; i < guardiansToRemoveAmount; i++) {
            vm.expectEmit(true, true, true, true);
            emit ERC7579Multisig.ERC7913SignerRemoved(address(_account), guardiansToRemove[i]);
        }

        _executor.removeGuardians(guardiansToRemove);

        assertEq(_executor.getGuardianCount(address(_account)), countBefore - guardiansToRemoveAmount);
        for (uint256 i = 0; i < guardiansToRemoveAmount; i++) {
            assertFalse(_executor.isGuardian(address(_account), guardiansToRemove[i]));
        }

        // Reverts if the guardian doesn't exist
        _executor.setThreshold(1); // To avoid unreachable threshold error
        vm.expectRevert(
            abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigNonexistentSigner.selector, guardiansToRemove[0])
        );
        _executor.removeGuardians(guardiansToRemove);

        // Reverts if threshold becomes unreachable after removal
        uint64 remainingWeight = totalWeight - weightRemoved;
        _executor.setThreshold(remainingWeight); // Max-out the threshold
        (, guardiansToRemove, weightsToRemove) = _buildGuardians(1, guardiansToRemoveAmount);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Multisig.ERC7579MultisigUnreachableThreshold.selector,
                uint64(remainingWeight - _calculateTotalWeight(weightsToRemove)),
                uint64(remainingWeight)
            )
        );
        _executor.removeGuardians(guardiansToRemove);
        vm.stopPrank();
    }

    function testRecovery(uint32 delay, uint32 expiration, uint64 threshold, uint256 guardiansAmount) public {
        guardiansAmount = bound(guardiansAmount, 1, 10);
        (uint256[] memory guardianKeys, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(
            guardiansAmount
        );
        threshold = uint64(bound(threshold, 1, _calculateTotalWeight(weights)));
        _account = _createAndInstall(delay, expiration, threshold, guardians, weights);

        (bytes memory calldata_, bytes32 mode) = _prepareDataAndMode(1, 2);

        bytes memory multisignature = _createMultisignature(
            SCHEDULE_RECOVER_TYPEHASH,
            bytes32(0),
            mode,
            calldata_,
            guardians,
            guardianKeys
        );
        bytes memory cancelMultisignature = _createMultisignature(
            CANCEL_RECOVER_TYPEHASH,
            bytes32(0),
            mode,
            calldata_,
            guardians,
            guardianKeys
        );

        vm.expectEmit(true, true, true, true);
        bytes32 operationId = _executor.hashOperation(address(_account), bytes32(0), mode, calldata_);
        uint48 executableAt = uint48(block.timestamp + delay);
        uint48 expiresAt = uint48(executableAt + expiration);
        emit ERC7579DelayedExecutor.ERC7579ExecutorOperationScheduled(
            address(_account),
            operationId,
            bytes32(0),
            mode,
            calldata_,
            executableAt
        );
        _executor.startRecovery(address(_account), bytes32(0), mode, calldata_, multisignature);

        bool ready = delay == 0;
        bool expiresImmediately = expiration == 0;

        ERC7579DelayedExecutor.OperationState state = _executor.state(operationId);
        assertEq(
            uint8(state),
            !ready
                ? uint8(ERC7579DelayedExecutor.OperationState.Scheduled)
                : (!expiresImmediately || !ready)
                    ? uint8(ERC7579DelayedExecutor.OperationState.Ready)
                    : uint8(ERC7579DelayedExecutor.OperationState.Expired)
        );

        // Try to schedule again
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                operationId,
                state,
                1 << uint8(ERC7579DelayedExecutor.OperationState.Unknown)
            )
        );
        _executor.startRecovery(address(_account), bytes32(0), mode, calldata_, multisignature);

        if (!ready) {
            // Try to execute before delay passes
            vm.expectRevert(
                abi.encodeWithSelector(
                    ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                    operationId,
                    state,
                    1 << uint8(ERC7579DelayedExecutor.OperationState.Ready)
                )
            );
            _executor.executeRecovery(address(_account), bytes32(0), mode, calldata_);
        }

        uint256 snapshot = vm.snapshotState();

        vm.warp(executableAt);

        // Try to execute after delay passes
        if (!expiresImmediately) {
            vm.expectCall(address(_target), abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (1, 2)));
            _executor.executeRecovery(address(_account), bytes32(0), mode, calldata_); // Anyone can execute the recovery
            assertEq(uint8(_executor.state(operationId)), uint8(ERC7579DelayedExecutor.OperationState.Executed));
            // Try to execute again
            vm.expectRevert(
                abi.encodeWithSelector(
                    ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                    operationId,
                    _executor.state(operationId),
                    1 << uint8(ERC7579DelayedExecutor.OperationState.Ready)
                )
            );
            _executor.executeRecovery(address(_account), bytes32(0), mode, calldata_);
        } else {
            vm.expectRevert(
                abi.encodeWithSelector(
                    ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                    operationId,
                    ERC7579DelayedExecutor.OperationState.Expired,
                    1 << uint8(ERC7579DelayedExecutor.OperationState.Ready)
                )
            );
            _executor.executeRecovery(address(_account), bytes32(0), mode, calldata_);
        }

        vm.revertTo(snapshot);

        vm.warp(expiresAt);

        // Try to execute after expiration
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                operationId,
                ERC7579DelayedExecutor.OperationState.Expired,
                1 << uint8(ERC7579DelayedExecutor.OperationState.Ready)
            )
        );
        _executor.executeRecovery(address(_account), bytes32(0), mode, calldata_);

        if (!expiresImmediately) {
            vm.revertTo(snapshot);

            // Cancel by the account
            vm.expectEmit(true, true, true, true);
            emit ERC7579DelayedExecutor.ERC7579ExecutorOperationCanceled(address(_account), operationId);
            vm.prank(address(_account));
            _executor.cancelRecovery(address(_account), bytes32(0), mode, calldata_);
            assertEq(uint8(_executor.state(operationId)), uint8(ERC7579DelayedExecutor.OperationState.Canceled));

            vm.revertTo(snapshot);

            // Cancel by the guardians
            vm.expectEmit(true, true, true, true);
            emit ERC7579DelayedExecutor.ERC7579ExecutorOperationCanceled(address(_account), operationId);
            _executor.cancelRecovery(address(_account), bytes32(0), mode, calldata_, cancelMultisignature);
            assertEq(uint8(_executor.state(operationId)), uint8(ERC7579DelayedExecutor.OperationState.Canceled));

            // Try to cancel again
            vm.expectRevert(
                abi.encodeWithSelector(
                    ERC7579DelayedExecutor.ERC7579ExecutorUnexpectedOperationState.selector,
                    operationId,
                    ERC7579DelayedExecutor.OperationState.Canceled,
                    (1 << uint8(ERC7579DelayedExecutor.OperationState.Ready)) |
                        (1 << uint8(ERC7579DelayedExecutor.OperationState.Scheduled))
                )
            );
            vm.prank(address(_account));
            _executor.cancelRecovery(address(_account), bytes32(0), mode, calldata_);
        }

        vm.deleteStateSnapshot(snapshot);
    }

    function testScheduleMultisignatureDoesNotReplayAcrossExecutors() public {
        (uint256[] memory keys, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(3);
        _installSecondExecutor(guardians, weights);
        (bytes memory calldata_, bytes32 mode) = _prepareDataAndMode(1, 2);

        bytes memory multisignature = _sign(
            _recoveryDigest(address(_executor), SCHEDULE_RECOVER_TYPEHASH, bytes32(0), mode, calldata_),
            guardians,
            keys
        );

        // Valid on the executor it was signed for.
        _executor.startRecovery(address(_account), bytes32(0), mode, calldata_, multisignature);

        // Rejected by the other deployment, which is not the `executor` bound into the digest.
        vm.expectRevert(ERC7579SocialRecoveryExecutor.ERC7579SocialRecoveryExecutorInvalidSchedule.selector);
        _otherExecutor.startRecovery(address(_account), bytes32(0), mode, calldata_, multisignature);
    }

    function testCancelMultisignatureDoesNotReplayAcrossExecutors() public {
        (uint256[] memory keys, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(3);
        _installSecondExecutor(guardians, weights);
        (bytes memory calldata_, bytes32 mode) = _prepareDataAndMode(1, 2);

        _otherExecutor.startRecovery(
            address(_account),
            bytes32(0),
            mode,
            calldata_,
            _sign(
                _recoveryDigest(address(_otherExecutor), SCHEDULE_RECOVER_TYPEHASH, bytes32(0), mode, calldata_),
                guardians,
                keys
            )
        );

        // Built before `expectRevert` so the `eip712Domain` call it makes is not the expected revert.
        bytes memory cancelMultisignature = _sign(
            _recoveryDigest(address(_executor), CANCEL_RECOVER_TYPEHASH, bytes32(0), mode, calldata_),
            guardians,
            keys
        );

        // A cancellation signed for `_executor` does not authorize a cancellation on `_otherExecutor`.
        vm.expectRevert(ERC7579SocialRecoveryExecutor.ERC7579SocialRecoveryExecutorInvalidCancel.selector);
        _otherExecutor.cancelRecovery(address(_account), bytes32(0), mode, calldata_, cancelMultisignature);
    }

    function testUninstalledModuleRejectsGuardianCancel() public {
        (uint256[] memory keys, bytes[] memory guardians, uint64[] memory weights) = _buildGuardians(3);
        _account = _createAndInstall(1 days, 30 days, _calculateTotalWeight(weights), guardians, weights);
        (bytes memory calldata_, bytes32 mode) = _prepareDataAndMode(1, 2);

        bytes memory multisignature = _createMultisignature(
            SCHEDULE_RECOVER_TYPEHASH,
            bytes32(0),
            mode,
            calldata_,
            guardians,
            keys
        );
        _executor.startRecovery(address(_account), bytes32(0), mode, calldata_, multisignature);

        // Uninstalling clears the guardians and resets the threshold, but retains the operation.
        vm.prank(address(_account));
        _executor.onUninstall("");
        assertEq(_executor.threshold(address(_account)), 0);
        assertEq(
            uint8(_executor.state(address(_account), bytes32(0), mode, calldata_)),
            uint8(ERC7579DelayedExecutor.OperationState.Scheduled)
        );

        // Two empty arrays would otherwise clear a threshold of zero. Both encodings are rejected.
        vm.expectRevert(ERC7579SocialRecoveryExecutor.ERC7579SocialRecoveryExecutorInvalidCancel.selector);
        vm.prank(address(0xBAD));
        _executor.cancelRecovery(address(_account), bytes32(0), mode, calldata_, new bytes(0x40));

        vm.expectRevert(ERC7579SocialRecoveryExecutor.ERC7579SocialRecoveryExecutorInvalidCancel.selector);
        vm.prank(address(0xBAD));
        _executor.cancelRecovery(
            address(_account),
            bytes32(0),
            mode,
            calldata_,
            abi.encode(new bytes[](0), new bytes[](0))
        );

        assertEq(
            uint8(_executor.state(address(_account), bytes32(0), mode, calldata_)),
            uint8(ERC7579DelayedExecutor.OperationState.Scheduled)
        );

        // The account keeps its own cancellation path while uninstalled.
        vm.prank(address(_account));
        _executor.cancelRecovery(address(_account), bytes32(0), mode, calldata_);
        assertEq(
            uint8(_executor.state(address(_account), bytes32(0), mode, calldata_)),
            uint8(ERC7579DelayedExecutor.OperationState.Canceled)
        );
    }

    /// @dev Installs `_executor` and a second deployment of the same module on a fresh account.
    function _installSecondExecutor(bytes[] memory guardians, uint64[] memory weights) private {
        uint64 threshold = _calculateTotalWeight(weights);
        _account = _createAndInstall(1 days, 30 days, threshold, guardians, weights);
        _otherExecutor = new ERC7579SocialRecoveryExecutor();
        (, , bytes[] memory initDatas) = _buildInstallationModules(guardians, threshold, weights, 1 days, 30 days);
        vm.prank(address(_account));
        _account.installModule(MODULE_TYPE_EXECUTOR, address(_otherExecutor), initDatas[0]);
    }

    // Helper functions

    function _createAndInstall(
        uint32 delay,
        uint32 expiration,
        uint64 threshold,
        bytes[] memory guardians,
        uint64[] memory weights
    ) private returns (OpenAccount) {
        (
            uint256[] memory moduleTypeIds,
            address[] memory modules,
            bytes[] memory initDatas
        ) = _buildInstallationModules(guardians, threshold, weights, delay, expiration);
        return
            OpenAccount(
                payable(
                    _factory.createAndInitialize(moduleTypeIds, modules, initDatas, Mode.wrap(0), bytes(""), bytes32(0))
                )
            );
    }

    function _buildGuardians(
        uint256 count
    ) private pure returns (uint256[] memory keys, bytes[] memory signers, uint64[] memory weights) {
        return _buildGuardians(count, 0);
    }

    function _buildGuardians(
        uint256 count,
        uint256 start
    ) private pure returns (uint256[] memory keys, bytes[] memory signers, uint64[] memory weights) {
        keys = new uint256[](count);
        signers = new bytes[](count);
        weights = new uint64[](count);
        for (uint256 i = 0; i < count; i++) {
            keys[i] = i + start + 1;
            signers[i] = abi.encodePacked(vm.addr(keys[i]));
            weights[i] = uint64(keys[i]);
        }
        return (keys, signers, weights);
    }

    function _calculateTotalWeight(uint64[] memory weights) private pure returns (uint64 total) {
        for (uint256 i = 0; i < weights.length; i++) {
            total += weights[i];
        }
        return total;
    }

    function _prepareDataAndMode(uint256 arg1, uint256 arg2) private view returns (bytes memory data, bytes32 mode) {
        data = abi.encodePacked(
            address(_target),
            uint256(0),
            abi.encodeCall(CallReceiverMock.mockFunctionWithArgs, (arg1, arg2))
        );
        mode = Mode.unwrap(
            ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
                ERC7579Utils.EXECTYPE_DEFAULT,
                ModeSelector.wrap(0x00000000),
                ModePayload.wrap(0x00000000)
            )
        );
        return (data, mode);
    }

    function _buildInstallationModules(
        bytes[] memory guardians,
        uint64 threshold,
        uint64[] memory weights,
        uint32 delay,
        uint32 expiration
    ) private view returns (uint256[] memory moduleTypeIds, address[] memory modules, bytes[] memory initDatas) {
        moduleTypeIds = new uint256[](1);
        modules = new address[](1);
        initDatas = new bytes[](1);
        moduleTypeIds[0] = MODULE_TYPE_EXECUTOR;
        modules[0] = address(_executor);
        bytes memory executorArgs = abi.encodePacked(delay, expiration);
        bytes memory multisigArgs = abi.encode(guardians, threshold, weights);
        initDatas[0] = bytes.concat(
            bytes2(uint16(executorArgs.length)),
            executorArgs,
            bytes2(uint16(multisigArgs.length)),
            multisigArgs
        );
    }

    function _createMultisignature(
        bytes32 typehash,
        bytes32 salt,
        bytes32 mode,
        bytes memory recoveryCalldata,
        bytes[] memory guardians,
        uint256[] memory guardianKeys
    ) private view returns (bytes memory) {
        return
            _sign(_recoveryDigest(address(_executor), typehash, salt, mode, recoveryCalldata), guardians, guardianKeys);
    }

    /// @dev Signs `hash` with each of `guardianKeys` and encodes the result as a multisignature.
    function _sign(
        bytes32 hash,
        bytes[] memory guardians,
        uint256[] memory guardianKeys
    ) private pure returns (bytes memory) {
        bytes[] memory signatures = new bytes[](guardianKeys.length);
        for (uint256 i = 0; i < guardianKeys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeys[i], hash);
            signatures[i] = abi.encodePacked(r, s, v);
        }
        return abi.encode(guardians, signatures);
    }

    /// @dev EIP-712 digest over the account's domain, with `executor` bound into the struct.
    function _recoveryDigest(
        address executor,
        bytes32 typehash,
        bytes32 salt,
        bytes32 mode,
        bytes memory recoveryCalldata
    ) private view returns (bytes32) {
        bytes1 fields;
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;
        bytes32 domainSalt;
        (fields, name, version, chainId, verifyingContract, domainSalt, ) = IERC5267(_account).eip712Domain();
        return
            fields.toDomainSeparator(name, version, chainId, verifyingContract, domainSalt).toTypedDataHash(
                keccak256(abi.encode(typehash, executor, salt, mode, keccak256(recoveryCalldata)))
            );
    }
}
