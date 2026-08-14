// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract SafeReentrancyPattern {
    bool private entered;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "send failed");
    }

    receive() external payable {}
}
