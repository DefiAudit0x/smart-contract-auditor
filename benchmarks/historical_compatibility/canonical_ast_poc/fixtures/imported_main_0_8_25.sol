pragma solidity ^0.8.25;

import "Lib.sol";

contract ImportedSourceEntry {
    function safeEntry() external pure returns (uint256) {
        return 1;
    }
}
