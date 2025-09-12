// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract ReceiverMock {
    event MockFunctionCalledWithArgs(uint256 a, uint256 b);
    event MockFunctionCalledMsg(address caller, uint256 value);

    function mockFunctionWithArgs(
        uint256 a,
        uint256 b
    ) public payable returns (string memory) {
        emit MockFunctionCalledWithArgs(a, b);
        return "0x1234";
    }

    function mockFunctionMsg() public payable {
        emit MockFunctionCalledMsg(msg.sender, msg.value);
    }
}
