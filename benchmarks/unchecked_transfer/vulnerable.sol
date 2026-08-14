// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract UncheckedPayout {
    function pay(address payable recipient, uint256 amount) external {
        recipient.send(amount);
    }
}
