// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OpenAccount} from "../../src/OpenAccount.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract OpenAccountMock is OpenAccount {
    constructor() EIP712("MyAccount", "1") {}
}
