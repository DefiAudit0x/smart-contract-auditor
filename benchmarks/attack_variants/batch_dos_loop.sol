// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract BatchDosLoop {
    address payable[] public recipients;

    function addRecipient(address payable recipient) external {
        recipients.push(recipient);
    }

    function distributeAll(uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(amount);
        }
    }

    receive() external payable {}
}
