pragma solidity ^0.8.25;

library TimestampLib {
    function readTimestamp() internal view returns (uint256) {
        // Stage 2 imported-source timestamp fixture.
        return block.timestamp;
    }
}
