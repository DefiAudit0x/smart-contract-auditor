// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract BoundedDistribution {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        recipients.push(recipient);
    }

    function distributeOne(uint256 index, uint256 amount) external {
        require(index < recipients.length, "invalid index");
        recipients[index].call{value: amount}("");
    }

    receive() external payable {}
}
