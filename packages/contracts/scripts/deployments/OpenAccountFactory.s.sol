// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BaseScript} from "../Base.s.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {console} from "forge-std/console.sol";
import {LowLevelCall} from "@openzeppelin/contracts/utils/LowLevelCall.sol";
import {OpenAccountFactory} from "../../src/OpenAccountFactory.sol";

contract OpenAccountFactoryScript is BaseScript {
    using Strings for *;

    // See https://github.com/Arachnid/deterministic-deployment-proxy
    // According to this research: https://ethereum-magicians.org/t/eip-7997-deterministic-factory-predeploy/24998/15
    // the Arachnid deployment proxy is the widest proxy available and its adoption suggests that a
    // more effect approach to support deterministic addresses is to enshrine it as a predeployed contract
    // through proposals like [RIP-7740](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7740.md).
    address public constant DEPLOYMENT_PROXY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    string internal constant CONTRACT_KEY = "OpenAccountFactory";

    function run() public broadcast {
        string memory deployments = vm.readFile("packages/contracts/deployments.json");
        bytes memory parsedValue = vm.parseJson(
            deployments,
            string.concat("$.", block.chainid.toString(), ".", CONTRACT_KEY)
        );
        address deployedAddress = address(uint160(uint256(bytes32(parsedValue))));
        if (deployedAddress == address(0) || deployedAddress.code.length == 0) {
            (bool success, bytes32 encodedAddress, ) = LowLevelCall.callReturn64Bytes(
                DEPLOYMENT_PROXY,
                abi.encodePacked(
                    bytes32(0), // Salt
                    type(OpenAccountFactory).creationCode
                )
            );
            require(success, "Failed to call deployment proxy");
            deployedAddress = address(bytes20(encodedAddress));
        }
        vm.writeJson(
            vm.serializeAddress("address", CONTRACT_KEY, deployedAddress),
            "packages/contracts/deployments.json",
            string.concat("$.", block.chainid.toString())
        );
    }
}
