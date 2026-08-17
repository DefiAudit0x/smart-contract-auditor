pragma solidity ^0.8.25;

import "Lib.sol";

contract TimestampMain {
    function read() external view returns (uint256) {
        return TimestampLib.readTimestamp();
    }
}
