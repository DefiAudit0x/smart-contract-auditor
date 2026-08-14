// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract MutableDelegatecallProxy {
    struct Slot {
        uint256 value;
        address owner;
    }

    mapping(address => Slot) public slots;
    address public implementation;

    function upgrade(address target) external {
        implementation = target;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}
