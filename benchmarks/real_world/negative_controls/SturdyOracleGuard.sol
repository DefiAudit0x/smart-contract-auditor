// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SturdyOracleGuard {
    mapping(address => bool) public collateral;
    mapping(address => uint256) public healthFactor;

    function setHealthFactor(address account, uint256 value) external {
        healthFactor[account] = value;
    }

    function setUserUseReserveAsCollateral(address asset, bool enabled) external {
        require(healthFactor[msg.sender] >= 1e18, "unsafe oracle state");
        collateral[asset] = enabled;
    }
}
