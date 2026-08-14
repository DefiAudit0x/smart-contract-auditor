// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract CrossFunctionVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "withdraw failed");
        balances[msg.sender] = 0;
    }

    function claimBonus() external {
        require(balances[msg.sender] > 0, "not eligible");
        (bool success, ) = payable(msg.sender).call{value: 1}("");
        require(success, "bonus failed");
    }

    receive() external payable {}
}
