// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract MsgSenderAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address nextOwner) external {
        require(msg.sender == owner, "not owner");
        owner = nextOwner;
    }
}
