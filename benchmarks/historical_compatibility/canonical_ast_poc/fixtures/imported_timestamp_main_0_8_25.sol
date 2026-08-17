pragma solidity ^0.8.25;

import "Lib.sol";

contract TimestampMain {
    function read() external view returns (uint256) {
        // Entry source intentionally contains no timestamp primitive.
        return TimestampLib.readTimestamp();
    }
}
