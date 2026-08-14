// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract TimestampGate {
    uint256 public unlockTime;
    bool public claimed;

    constructor(uint256 delay) {
        unlockTime = block.number + delay;
    }

    function claim() external {
        require(block.timestamp >= unlockTime, "locked");
        claimed = true;
    }
}
