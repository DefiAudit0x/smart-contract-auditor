// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract CallbackFlashLoan {
    uint256 public reserve;

    function seed() external payable {
        reserve += msg.value;
    }

    function flashLoan(uint256 amount) external {
        require(amount <= reserve, "insufficient");
        reserve -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "callback failed");
        reserve += amount;
    }

    function withdraw() external {
        uint256 amount = reserve;
        reserve = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "withdraw failed");
    }

    receive() external payable {}
}
