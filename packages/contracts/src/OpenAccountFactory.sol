// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC1967} from "@openzeppelin/contracts/interfaces/IERC1967.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {OpenAccount} from "./OpenAccount.sol";
import {ERC1967Clones} from "./utils/ERC1967Clones.sol";

/// @dev Implementation contract for the OpenAccount factory.
contract OpenAccountImplementation is OpenAccount, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() EIP712("OpenAccount", "1") {
        _disableInitializers();
    }

    /**
     * @dev See {OpenAccount-initialize}.
     * Emits an ERC-1967 Upgraded event to notify about its factory initial setup.
     */
    function initialize(
        uint256[] calldata moduleTypeIds,
        address[] calldata modules,
        bytes[] calldata initDatas,
        Mode configMode,
        bytes calldata configCalldata
    ) public override {
        super.initialize(moduleTypeIds, modules, initDatas, configMode, configCalldata);
        emit IERC1967.Upgraded(OpenAccountFactory(msg.sender).implementation());
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyEntryPointOrSelf {}
}

/**
 * @dev A factory contract to create OpenAccount instances on demand.
 *
 * Each account is created as a minimal ERC-1967 proxy clone that delegates to the implementation contract.
 * The proxy follows the ERC-1967 standard for proxy storage slots, storing the implementation address at
 * `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)`.
 *
 * See https://eips.ethereum.org/EIPS/eip-1967 for the full specification.
 */
contract OpenAccountFactory {
    using ERC1967Clones for address;

    address private immutable _implementation = address(new OpenAccountImplementation());

    /**
     * @dev Returns the OpenAccount implementation contract address.
     *
     * This is the logic contract that all created proxy clones will delegate to.
     */
    function implementation() public view returns (address) {
        return _implementation;
    }

    /**
     * @dev Predicts the address of an OpenAccount before it is created.
     *
     * The address is deterministically computed based on the initialization parameters and salt.
     * Each account is deployed as an ERC-1967 proxy clone.
     */
    function predictAddress(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata,
        bytes32 salt
    ) public view returns (address) {
        bytes32 saltData = keccak256(abi.encode(moduleTypeIds, modules, initDatas, configMode, configCalldata, salt));
        return Create2.computeAddress(saltData, implementation().ERC1967ProxyCodeHash());
    }

    /**
     * @dev Creates and initializes a new OpenAccount instance.
     *
     * Deploys a minimal ERC-1967 proxy clone using CREATE2 for deterministic addresses.
     * The proxy delegates all calls to the implementation contract and maintains its own storage.
     * If an account at the predicted address already exists, returns that address without redeploying.
     */
    function createAndInitialize(
        uint256[] memory moduleTypeIds,
        address[] memory modules,
        bytes[] memory initDatas,
        Mode configMode,
        bytes memory configCalldata,
        bytes32 salt
    ) public returns (address) {
        address predicted = predictAddress(moduleTypeIds, modules, initDatas, configMode, configCalldata, salt);
        if (predicted.code.length != 0) return predicted;
        bytes32 saltData = keccak256(abi.encode(moduleTypeIds, modules, initDatas, configMode, configCalldata, salt));
        implementation().cloneDeterministicERC1967(saltData);
        OpenAccount(payable(predicted)).initialize(moduleTypeIds, modules, initDatas, configMode, configCalldata);
        return predicted;
    }
}
