// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract NomadValidatedRoot {
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bool) public processed;

    function setConfirmed(bytes32 root, uint256 validAt) external {
        require(validAt > block.timestamp, "invalid time");
        confirmAt[root] = validAt;
    }

    function process(bytes32 messageHash, bytes32 root) external {
        uint256 validAt = confirmAt[root];
        require(validAt != 0 && block.timestamp >= validAt, "unconfirmed root");
        require(!processed[messageHash], "processed");
        processed[messageHash] = true;
    }
}
