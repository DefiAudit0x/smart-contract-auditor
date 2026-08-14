// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract SafeDelegatecallLayout {
    struct Position {
        uint256 amount;
        address owner;
    }

    mapping(address => Position) public positions;

    function setPosition(uint256 amount) external {
        positions[msg.sender] = Position(amount, msg.sender);
    }
}
