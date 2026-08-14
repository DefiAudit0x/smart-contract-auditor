// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract TxOriginFixed {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function privilegedAction() external view returns (bool) {
        require(msg.sender == owner, "not owner");
        return true;
    }
}
