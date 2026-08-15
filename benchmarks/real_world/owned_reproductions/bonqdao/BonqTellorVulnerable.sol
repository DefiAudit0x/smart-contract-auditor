// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Minimal owned oracle fixture for the BonqDAO adjudication.
/// @dev This models the relevant latest-report behavior, not the historical contract.
contract BonqTellorVulnerableOracle {
    struct Report {
        uint256 value;
        uint256 reportedAt;
    }

    Report public latest;

    function submitValue(uint256 value) external {
        latest = Report({value: value, reportedAt: block.timestamp});
    }

    function getCurrentValue() external view returns (bytes memory) {
        return abi.encode(latest.value);
    }

    function getDataBefore(uint256 timestamp)
        external
        view
        returns (bool found, bytes memory value, uint256 reportedAt)
    {
        if (latest.reportedAt == 0 || latest.reportedAt >= timestamp) {
            return (false, bytes(""), 0);
        }
        return (true, abi.encode(latest.value), latest.reportedAt);
    }
}

interface IBonqTellorVulnerable {
    function getCurrentValue() external view returns (bytes memory);
}

/// @notice Vulnerable Bonq-style consumer: it reads the newest report immediately.
contract BonqTellorVulnerablePriceFeed {
    IBonqTellorVulnerable public immutable oracle;

    constructor(address oracle_) {
        oracle = IBonqTellorVulnerable(oracle_);
    }

    function price() external view returns (uint256) {
        return abi.decode(oracle.getCurrentValue(), (uint256));
    }
}
