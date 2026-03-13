// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {MultisigCoordinator} from "../../utils/MultisigCoordinator.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

contract MultisigCoordinatorMock is MultisigCoordinator, ZamaEthereumConfig {}
