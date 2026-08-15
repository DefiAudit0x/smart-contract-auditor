pragma solidity ^0.8.25;

contract CanonicalNegative {
    string constant TEXT = "suicide(now, callcode, selfdestruct, block.timestamp, delegatecall)";

    function identifiers() public {
        uint256 timestamp = 1;
        bool delegatecall = true;
        uint256 now = 1;
        timestamp;
        delegatecall;
        now;
    }

    function callShapes(address target) public {
        target.call("");
    }

    function nested() public {
        uint256 x = 1;
        uint256 y = x + 1;
        y;
    }

    // suicide(now, callcode, delegatecall) must remain a comment only.
}
