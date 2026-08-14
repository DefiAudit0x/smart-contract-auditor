// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract BlockNumberGate {
    uint256 public unlockBlock;
    bool public claimed;

    constructor(uint256 delayBlocks) {
        unlockBlock = block.number + delayBlocks;
    }

    function claim() external {
        require(block.number >= unlockBlock, "locked");
        claimed = true;
    }
}
