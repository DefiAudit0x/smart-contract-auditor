// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract DoughCheckedCalldata {
    address public immutable approvedTarget;
    bytes4 public immutable approvedSelector;

    constructor(address target, bytes4 selector) {
        approvedTarget = target;
        approvedSelector = selector;
    }

    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        require(target == approvedTarget && target != address(0), "target");
        require(data.length >= 4 && bytes4(data[:4]) == approvedSelector, "selector");
        (bool success, bytes memory result) = target.call{value: msg.value}(data);
        require(success, "call failed");
        return result;
    }
}
