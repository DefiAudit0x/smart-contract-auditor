// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract CollisionProxyFixed {
    struct Account {
        address owner;
        uint256 balance;
    }

    mapping(address => Account) public accounts;
    address public immutable implementation;

    constructor(address target) {
        require(target != address(0), "zero target");
        implementation = target;
    }

    function credit(address account, uint256 amount) external {
        require(account != address(0), "zero account");
        accounts[account].balance += amount;
    }
}
