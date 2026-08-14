// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract UnboundedDistributor {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        recipients.push(recipient);
    }

    function distribute(uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amount);
        }
    }
}
