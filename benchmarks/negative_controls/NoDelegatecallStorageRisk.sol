// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract NoDelegatecallStorageRisk {
    struct Account {
        uint256 balance;
        bool enabled;
    }

    mapping(address => Account) public accounts;

    function update(uint256 amount) external {
        accounts[msg.sender] = Account(amount, true);
    }
}
