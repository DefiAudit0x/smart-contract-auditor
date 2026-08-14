// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IFlashBorrower {
    function receiveLoan(uint256 amount) external;
}

contract FlashLoanVaultFixed {
    uint256 public reserve;
    bool private entered;

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    function seed(uint256 amount) external {
        reserve += amount;
    }

    function flashLoan(uint256 amount) external nonReentrant {
        require(amount <= reserve, "insufficient reserve");
        reserve -= amount;
        IFlashBorrower(msg.sender).receiveLoan(amount);
        reserve += amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount <= reserve, "insufficient reserve");
        reserve -= amount;
    }
}
