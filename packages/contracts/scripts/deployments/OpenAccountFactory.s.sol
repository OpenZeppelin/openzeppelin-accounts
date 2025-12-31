// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BaseScript} from "../Base.s.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {console} from "forge-std/console.sol";
import {LowLevelCall} from "@openzeppelin/contracts/utils/LowLevelCall.sol";
import {OpenAccountFactory} from "../../src/OpenAccountFactory.sol";
import {ERC7579ECDSAValidator} from "../../src/modules/validators/ERC7579ECDSAValidator.sol";
import {ERC7579P256Validator} from "../../src/modules/validators/ERC7579P256Validator.sol";
import {ERC7579WebAuthnValidator} from "../../src/modules/validators/ERC7579WebAuthnValidator.sol";
import {ERC7579MultisigValidator} from "../../src/modules/validators/ERC7579MultisigValidator.sol";
import {ERC7579MultisigWeightedValidator} from "../../src/modules/validators/ERC7579MultisigWeightedValidator.sol";
import {ERC7579ERC20Spender} from "../../src/modules/executors/ERC7579ERC20Spender.sol";
import {ERC7579NativeSpender} from "../../src/modules/executors/ERC7579NativeSpender.sol";

contract OpenAccountFactoryScript is BaseScript {
    using Strings for *;

    // See https://github.com/Arachnid/deterministic-deployment-proxy
    // According to this research: https://ethereum-magicians.org/t/eip-7997-deterministic-factory-predeploy/24998/15
    // the Arachnid deployment proxy is the widest proxy available and its adoption suggests that a
    // more effect approach to support deterministic addresses is to enshrine it as a predeployed contract
    // through proposals like [RIP-7740](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7740.md).
    address public constant DEPLOYMENT_PROXY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() public broadcast {
        string memory deployments = vm.readFile("packages/contracts/deployments.json");
        // Factory
        _deployOpenAccountFactory(deployments);

        // Modules
        _deployERC7579ECDSAValidator(deployments);
        _deployERC7579P256Validator(deployments);
        _deployERC7579WebAuthnValidator(deployments);
        _deployERC7579MultisigValidator(deployments);
        _deployERC7579MultisigWeightedValidator(deployments);
        _deployERC7579ERC20Spender(deployments);
        _deployERC7579NativeSpender(deployments);
    }

    function _deployOpenAccountFactory(string memory deployments) internal {
        address deployedAddress = _deploy(deployments, "OpenAccountFactory", type(OpenAccountFactory).creationCode);
        vm.writeJson(
            vm.serializeAddress("address", "OpenAccountFactory", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
        vm.writeJson(
            vm.serializeAddress(
                "address",
                "OpenAccountImplementation",
                OpenAccountFactory(deployedAddress).implementation()
            ),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579ECDSAValidator(string memory deployments) internal {
        address deployedAddress = _deploy(
            deployments,
            "ERC7579ECDSAValidator",
            type(ERC7579ECDSAValidator).creationCode
        );
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579ECDSAValidator", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579P256Validator(string memory deployments) internal {
        address deployedAddress = _deploy(deployments, "ERC7579P256Validator", type(ERC7579P256Validator).creationCode);
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579P256Validator", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579WebAuthnValidator(string memory deployments) internal {
        address deployedAddress = _deploy(
            deployments,
            "ERC7579WebAuthnValidator",
            type(ERC7579WebAuthnValidator).creationCode
        );
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579WebAuthnValidator", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579MultisigValidator(string memory deployments) internal {
        address deployedAddress = _deploy(
            deployments,
            "ERC7579MultisigValidator",
            type(ERC7579MultisigValidator).creationCode
        );
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579MultisigValidator", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579MultisigWeightedValidator(string memory deployments) internal {
        address deployedAddress = _deploy(
            deployments,
            "ERC7579MultisigWeightedValidator",
            type(ERC7579MultisigWeightedValidator).creationCode
        );
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579MultisigWeightedValidator", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579ERC20Spender(string memory deployments) internal {
        address deployedAddress = _deploy(deployments, "ERC7579ERC20Spender", type(ERC7579ERC20Spender).creationCode);
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579ERC20Spender", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deployERC7579NativeSpender(string memory deployments) internal {
        address deployedAddress = _deploy(deployments, "ERC7579NativeSpender", type(ERC7579NativeSpender).creationCode);
        vm.writeJson(
            vm.serializeAddress("address", "ERC7579NativeSpender", deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }

    function _deploy(
        string memory deployments,
        string memory key,
        bytes memory creationCode
    ) internal returns (address) {
        bytes memory parsedValue = vm.parseJson(deployments, string.concat("$.", block.chainid.toString(), ".", key));
        address deployedAddress = address(uint160(uint256(bytes32(parsedValue))));
        bytes32 salt = bytes32(0);
        address predictedAddress = Create2.computeAddress(salt, keccak256(creationCode), DEPLOYMENT_PROXY);
        if (deployedAddress == address(0) || deployedAddress.code.length == 0 || predictedAddress != deployedAddress) {
            (bool success) = LowLevelCall.callNoReturn(DEPLOYMENT_PROXY, abi.encodePacked(salt, creationCode));
            require(success, "Failed to call deployment proxy");
            deployedAddress = predictedAddress;
        }
        return deployedAddress;
    }
}
