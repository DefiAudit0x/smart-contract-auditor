// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Minimal owned reproduction of the Nomad zero-root acceptance mechanism.
/// @dev This is an explanatory fixture, not the historical Nomad implementation.
contract NomadReplicaVulnerable {
    bytes32 public constant LEGACY_STATUS_PROVEN = bytes32(uint256(1));
    bytes32 public constant LEGACY_STATUS_PROCESSED = bytes32(uint256(2));

    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bytes32) public messages;

    function initialize(bytes32 committedRoot) external {
        confirmAt[committedRoot] = 1;
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        if (root == LEGACY_STATUS_PROVEN) return true;
        if (root == LEGACY_STATUS_PROCESSED) return false;
        uint256 time = confirmAt[root];
        if (time == 0) return false;
        return block.timestamp >= time;
    }

    function process(bytes32 messageHash) external returns (bool) {
        require(acceptableRoot(messages[messageHash]), "!proven");
        messages[messageHash] = LEGACY_STATUS_PROCESSED;
        return true;
    }
}
