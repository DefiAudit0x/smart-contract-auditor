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

interface Vm {
    function warp(uint256) external;
}

contract TimestampClaimGatePoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoC_ClaimGateUsesTimestamp() external {
        TimestampClaimGate gate = new TimestampClaimGate(100);
        vm.warp(block.timestamp + 99);
        gate.claim();
        require(gate.claimed(address(this)), "claim did not open before deadline");
    }
}
