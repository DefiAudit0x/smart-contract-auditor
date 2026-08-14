// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract TimestampGate {
    uint256 public unlockTime;
    bool public claimed;

    constructor(uint256 delay) {
        unlockTime = block.timestamp + delay;
    }

    function claim() external {
        require(block.timestamp >= unlockTime, "locked");
        claimed = true;
    }
}

interface Vm {
    function warp(uint256) external;
}

contract TimestampPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoC_TimestampGateCanBeWarped() external {
        TimestampGate gate = new TimestampGate(100);
        vm.warp(block.timestamp + 100);
        gate.claim();
        require(gate.claimed(), "timestamp gate did not open");
    }
}
