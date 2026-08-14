// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract CheckedValueCall {
    function pay(address payable recipient, uint256 amount) external {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "payment failed");
    }

    receive() external payable {}
}
