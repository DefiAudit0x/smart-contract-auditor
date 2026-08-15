// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

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

contract BonqTellorVulnerablePriceFeed {
    IBonqTellorVulnerable public immutable oracle;

    constructor(address oracle_) {
        oracle = IBonqTellorVulnerable(oracle_);
    }

    function price() external view returns (uint256) {
        return abi.decode(oracle.getCurrentValue(), (uint256));
    }
}

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

contract BonqTellorFixedPriceFeed {
    IBonqTellorFixed public immutable oracle;

    constructor(address oracle_) {
        oracle = IBonqTellorFixed(oracle_);
    }

    function price() external view returns (uint256) {
        (bool found, bytes memory value, ) = oracle.getDataBefore(
            block.timestamp - 20 minutes
        );
        require(found, "dispute window");
        return abi.decode(value, (uint256));
    }
}

interface Vm {
    function warp(uint256 newTimestamp) external;
}

contract BonqDisputeWindowPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant INITIAL_TIME = 1_000_000;
    uint256 private constant MANIPULATED_PRICE = 5_000_000_000;

    function testVulnerableConsumesFreshReport() public {
        vm.warp(INITIAL_TIME);
        BonqTellorVulnerableOracle oracle = new BonqTellorVulnerableOracle();
        BonqTellorVulnerablePriceFeed feed = new BonqTellorVulnerablePriceFeed(address(oracle));

        oracle.submitValue(MANIPULATED_PRICE);
        require(feed.price() == MANIPULATED_PRICE, "vulnerable feed did not consume fresh report");
    }

    function testFixedRejectsFreshReportAndAcceptsMatureReport() public {
        vm.warp(INITIAL_TIME);
        BonqTellorFixedOracle oracle = new BonqTellorFixedOracle();
        BonqTellorFixedPriceFeed feed = new BonqTellorFixedPriceFeed(address(oracle));

        oracle.submitValue(MANIPULATED_PRICE);
        (bool freshAccepted, ) = address(feed).call(
            abi.encodeWithSelector(BonqTellorFixedPriceFeed.price.selector)
        );
        require(!freshAccepted, "fixed feed accepted a report inside dispute window");

        vm.warp(INITIAL_TIME + 20 minutes + 1);
        require(feed.price() == MANIPULATED_PRICE, "fixed feed rejected a mature report");
    }
}
