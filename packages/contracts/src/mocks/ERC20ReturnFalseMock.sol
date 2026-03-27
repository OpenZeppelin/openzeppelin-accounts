// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {ERC20Mock} from "./ERC20Mock.sol";

contract ERC20ReturnFalseMock is ERC20Mock {
    function transfer(address, uint256) public pure override returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) public pure override returns (bool) {
        return false;
    }

    function approve(address, uint256) public pure override returns (bool) {
        return false;
    }
}
