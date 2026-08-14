// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract KyberRoundedMath {
    function roundUp(uint256 numerator, uint256 denominator) public pure returns (uint256) {
        require(denominator != 0, "zero denominator");
        return numerator == 0 ? 0 : ((numerator - 1) / denominator) + 1;
    }

    function boundedAmount(uint256 amount, uint256 limit) external pure returns (uint256) {
        uint256 rounded = roundUp(amount, 1e9);
        require(rounded <= limit, "limit");
        return rounded;
    }
}
