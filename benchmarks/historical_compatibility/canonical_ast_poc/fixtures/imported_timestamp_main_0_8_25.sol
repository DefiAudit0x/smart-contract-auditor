pragma solidity ^0.8.25;

import "imported_timestamp_lib_0_8_25.sol";

contract TimestampMain {
    function read() external view returns (uint256) {
        return TimestampLib.readTimestamp();
    }
}
