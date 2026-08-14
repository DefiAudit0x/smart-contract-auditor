// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract TimestampClaimGate {
    uint256 public deadline;
    mapping(address => bool) public claimed;

    constructor(uint256 window) {
        deadline = block.timestamp + window;
    }

    function claim() external {
        require(block.timestamp <= deadline, "expired");
        claimed[msg.sender] = true;
    }
}
