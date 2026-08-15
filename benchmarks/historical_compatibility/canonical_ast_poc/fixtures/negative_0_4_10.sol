pragma solidity ^0.4.10;

contract CanonicalNegative {
    string constant TEXT = "suicide(now, callcode, selfdestruct, block.timestamp, delegatecall)";

    function identifiers() public {
        uint timestamp = 1;
        bool delegatecall = true;
        uint now = 1;
        timestamp;
        delegatecall;
        now;
    }

    function callShapes(address target) public {
        target.call();
    }

    function nested() public {
        uint x = 1;
        uint y = x + 1;
        y;
    }

    // suicide(now, callcode, delegatecall) must remain a comment only.
}
