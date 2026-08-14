// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract CollisionProxy {
    struct Account {
        address owner;
        uint256 balance;
    }

    mapping(address => Account) public accounts;
    address public implementation;

    function setImplementation(address target) external {
        implementation = target;
    }

    fallback() external payable {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}
