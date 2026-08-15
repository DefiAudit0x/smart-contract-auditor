// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Minimal owned oracle fixture with an explicit dispute window.
/// @dev This models the safe consumer boundary, not a replacement oracle protocol.
contract BonqTellorFixedOracle {
    struct Report {
        uint256 value;
        uint256 reportedAt;
    }

    Report public latest;
    uint256 public constant DISPUTE_WINDOW = 20 minutes;

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

interface IBonqTellorFixed {
    function getDataBefore(uint256 timestamp)
        external
        view
        returns (bool found, bytes memory value, uint256 reportedAt);
}

/// @notice Fixed Bonq-style consumer: it reads only a report older than the window.
contract BonqTellorFixedPriceFeed {
    uint256 public constant DISPUTE_WINDOW = 20 minutes;
    IBonqTellorFixed public immutable oracle;

    constructor(address oracle_) {
        oracle = IBonqTellorFixed(oracle_);
    }

    function price() external view returns (uint256) {
        (bool found, bytes memory value, ) = oracle.getDataBefore(
            block.timestamp - DISPUTE_WINDOW
        );
        require(found, "dispute window");
        return abi.decode(value, (uint256));
    }
}
