// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract BoundedDistributor {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        require(recipient != address(0), "zero recipient");
        recipients.push(recipient);
    }

    function distributeOne(uint256 index, uint256 amount) external {
        require(index < recipients.length, "invalid index");
        recipients[index].transfer(amount);
    }
}
