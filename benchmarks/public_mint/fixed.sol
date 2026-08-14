// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract PublicMintFixed {
    address private immutable owner;
    mapping(address => uint256) private balanceOf;

    constructor() {
        owner = msg.sender;
    }

    function mint(address recipient, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(recipient != address(0), "zero recipient");
        balanceOf[recipient] += amount;
    }
}
