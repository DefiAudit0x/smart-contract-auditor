// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract CheckedPayout {
    function pay(address payable recipient, uint256 amount) external {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "payment failed");
    }
}
