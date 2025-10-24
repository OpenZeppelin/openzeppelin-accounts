// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC7579MultisigWeighted} from "../../src/modules/ERC7579MultisigWeighted.sol";
import {ERC7579Multisig} from "../../src/modules/ERC7579Multisig.sol";
import {CallReceiverMock} from "@openzeppelin/contracts/mocks/CallReceiverMock.sol";
import {
    ERC7579Utils,
    Mode,
    ModeSelector,
    ModePayload
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {ERC4337Utils, IEntryPointExtra} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {AccountERC7579} from "@openzeppelin/contracts/account/extensions/draft-AccountERC7579.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {OpenAccount} from "../../src/OpenAccount.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("TestAccount", "1") {}
}

contract ERC7579MultisigWeightedMock is ERC7579MultisigWeighted {
    function onInstall(bytes calldata initData) public override {
        super.onInstall(initData);
    }

    function onUninstall(bytes calldata data) public override {
        super.onUninstall(data);
    }

    // Expose internal function for testing
    function exposed_rawERC7579Validation(
        address account,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool) {
        return _rawERC7579Validation(account, hash, signature);
    }

    // Expose internal functions for testing
    function exposed_decodeMultisigWeightedInitData(
        bytes calldata initData
    ) external pure returns (bytes[] calldata signers, uint64 threshold, uint64[] calldata weights) {
        return _decodeMultisigWeightedInitData(initData);
    }

    function exposed_setSignerWeights(address account, bytes[] memory signers, uint64[] memory weights) external {
        _setSignerWeights(account, signers, weights);
    }

    function exposed_addSigners(address account, bytes[] memory newSigners) external {
        _addSigners(account, newSigners);
    }

    function exposed_removeSigners(address account, bytes[] memory oldSigners) external {
        _removeSigners(account, oldSigners);
    }

    function exposed_validateReachableThreshold(address account) external view {
        _validateReachableThreshold(account);
    }

    function exposed_validateThreshold(
        address account,
        bytes[] calldata validatingSigners
    ) external view returns (bool) {
        return _validateThreshold(account, validatingSigners);
    }
}

contract ERC7579MultisigWeightedTest is Test {
    using ERC7579Utils for *;
    using ERC4337Utils for PackedUserOperation;
    using Strings for *;
    using SignatureChecker for bytes32;

    uint256 private constant MAX_ETH = type(uint128).max;

    CallReceiverMock private _target;
    ERC7579MultisigWeightedMock private _multisig;
    OpenAccount private _account;

    function setUp() public {
        // Deploy target contract
        _target = new CallReceiverMock();

        // Deploy weighted multisig
        _multisig = new ERC7579MultisigWeightedMock();

        // Deploy account
        _account = new OpenAccountMock();

        vm.deal(address(_account), MAX_ETH);

        // Setup entrypoint
        address entrypoint = address(ERC4337Utils.ENTRYPOINT_V08);
        vm.deal(entrypoint, MAX_ETH);
        vm.etch(
            entrypoint,
            vm.readFileBinary(
                string.concat(
                    "packages/contracts/node_modules/hardhat-predeploy/bin/",
                    Strings.toChecksumHexString(entrypoint),
                    ".bytecode"
                )
            )
        );
    }

    function testWeightedMultisigInstallation(uint64 numSigners) public {
        numSigners = uint64(bound(numSigners, 1, 10)); // Reasonable bounds

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);

        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

        assertEq(_multisig.getSignerCount(address(_account)), numSigners);
        assertEq(_multisig.threshold(address(_account)), totalWeight);
        assertEq(_multisig.totalWeight(address(_account)), totalWeight);

        for (uint256 i = 0; i < numSigners; i++) {
            assertTrue(_multisig.isSigner(address(_account), signers[i]));
            assertEq(_multisig.signerWeight(address(_account), signers[i]), weights[i]);
        }
    }

    function testValidateUserOp(uint256 numSigners) public {
        numSigners = bound(numSigners, 1, 10);
        (uint256[] memory keys, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);

        bytes memory initData = abi.encode(signers, totalWeight, weights);
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), initData);

        PackedUserOperation memory userOp = _prepareUserOperation();
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08)).getUserOpHash(userOp);

        bytes[] memory signatures = new bytes[](signers.length);

        for (uint256 i = 0; i < signers.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], userOpHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        bytes memory multisigSignature = abi.encode(signers, signatures);
        userOp.signature = multisigSignature;

        vm.prank(address(_account));
        uint256 result = _multisig.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    function testValidateUserOpInsufficientWeight(uint256 numSigners) public {
        numSigners = bound(numSigners, 1, 10);
        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);

        bytes memory initData = abi.encode(signers, totalWeight, weights);
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), initData);

        PackedUserOperation memory userOp = _prepareUserOperation();
        bytes32 userOpHash = IEntryPointExtra(address(ERC4337Utils.ENTRYPOINT_V08)).getUserOpHash(userOp);

        (uint256[] memory signingKeys, bytes[] memory signingSigners) = _buildSigners(numSigners - 1, 1);
        bytes[] memory signatures = new bytes[](signingSigners.length);

        for (uint256 i = 0; i < signingSigners.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKeys[i], userOpHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        bytes memory multisigSignature = abi.encode(signingSigners, signatures);
        userOp.signature = multisigSignature;

        vm.prank(address(_account));
        uint256 result = _multisig.validateUserOp(userOp, userOpHash);

        assertEq(result, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    function testSetSignerWeights(uint64 numSigners, uint256 updateCount) public {
        numSigners = uint64(bound(numSigners, 1, 5));
        updateCount = uint64(bound(updateCount, 1, numSigners));

        (, bytes[] memory signers) = _buildSigners(numSigners);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(numSigners);
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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

        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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

        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));
    }

    function testRevertAlreadyExistsSigner() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

        vm.prank(address(_account));
        vm.expectRevert(abi.encodeWithSelector(ERC7579Multisig.ERC7579MultisigAlreadyExists.selector, signers[0]));
        _multisig.addSigners(signers);
    }

    function testRevertNonexistentSigner() public {
        (, bytes[] memory signers) = _buildSigners(1);
        (uint64[] memory weights, uint64 totalWeight) = _buildWeights(1);
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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
        _account.initialize(MODULE_TYPE_VALIDATOR, address(_multisig), abi.encode(signers, totalWeight, weights));

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

    function _prepareUserOperation() private view returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(_account),
                nonce: uint256(uint160(bytes20(address(_multisig)))) << 96,
                initCode: bytes(""),
                callData: abi.encodeCall(
                    AccountERC7579.execute,
                    (
                        Mode.unwrap(
                            ERC7579Utils.CALLTYPE_SINGLE.encodeMode(
                                ERC7579Utils.EXECTYPE_DEFAULT,
                                ModeSelector.wrap(0x00000000),
                                ModePayload.wrap(0x00000000)
                            )
                        ),
                        abi.encodePacked(
                            address(_target),
                            uint256(0),
                            abi.encodeCall(CallReceiverMock.mockFunction, ())
                        )
                    )
                ),
                preVerificationGas: 100000,
                accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
                gasFees: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
                paymasterAndData: bytes(""),
                signature: bytes("")
            });
    }
}
