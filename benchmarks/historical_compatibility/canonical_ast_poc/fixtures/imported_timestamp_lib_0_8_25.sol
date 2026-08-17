pragma solidity ^0.8.25;

library TimestampLib {
    function readTimestamp() internal view returns (uint256) {
        return block.timestamp;
    }
}
