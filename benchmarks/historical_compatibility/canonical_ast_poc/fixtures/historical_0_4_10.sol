pragma solidity ^0.4.10;

contract CanonicalCompatibility {
    function destroy() public {
        suicide(msg.sender);
    }

    function readTime() public {
        uint256 observed = now;
        observed;
    }

    function delegated(address target, bytes data) public {
        target.callcode(data);
    }
}
