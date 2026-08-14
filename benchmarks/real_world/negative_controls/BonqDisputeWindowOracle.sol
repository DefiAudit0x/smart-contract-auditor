// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract BonqDisputeWindowOracle {
    struct Report {
        uint256 value;
        uint256 reportedAt;
    }

    Report public latest;
    uint256 public constant DISPUTE_WINDOW = 1 hours;

    function publish(uint256 value) external {
        latest = Report(value, block.timestamp);
    }

    function safePrice() external view returns (uint256) {
        require(latest.reportedAt != 0, "missing report");
        require(block.timestamp >= latest.reportedAt + DISPUTE_WINDOW, "dispute window");
        return latest.value;
    }
}
