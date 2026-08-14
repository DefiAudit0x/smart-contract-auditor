// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract OwnerMint {
    address public owner;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balanceOf[to] += amount;
    }
}
