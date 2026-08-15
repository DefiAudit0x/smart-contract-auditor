pragma solidity ^0.8.25;

contract CanonicalCompatibility {
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    function readTime() public {
        uint256 observed = block.timestamp;
        observed;
    }

    function delegated(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
}
