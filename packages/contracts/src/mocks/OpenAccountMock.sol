// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OpenAccount} from "../../src/OpenAccount.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MODULE_TYPE_VALIDATOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

contract OpenAccountMock is OpenAccount {
    constructor(address validator, bytes memory initData) EIP712("OpenAccount", "1") {
        initialize(MODULE_TYPE_VALIDATOR, validator, initData);
    }
}
