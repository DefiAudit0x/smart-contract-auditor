// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract SelfdestructFixed {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address payable recipient, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(recipient != address(0), "zero recipient");
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "transfer failed");
    }

    receive() external payable {}
}
