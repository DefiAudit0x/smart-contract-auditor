// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IGuardedBorrower {
    function receiveLoan(uint256 amount) external;
}

contract GuardedFlashLoan {
    uint256 public reserve;
    bool private entered;

    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    function flashLoan(uint256 amount) external nonReentrant {
        require(amount <= reserve, "insufficient");
        reserve -= amount;
        IGuardedBorrower(msg.sender).receiveLoan(amount);
        reserve += amount;
    }
}
